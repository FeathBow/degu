//! Create-only provisioning for fixed system-managed and self-managed activation anchors.
//!
//! The system entry point remains root-only and accepts a numeric UID. The
//! self-managed entry point derives both its UID and account base internally and
//! rejects root. Layout, ownership, and path selection are never caller supplied;
//! existing objects are authenticated and never repaired or replaced.

use crate::local_backend::{
    CertificationError, CertifiedLocalBackend, certify_held_fd_backend, require_held_fd_acl_absent,
};
use crate::seal_store::{StoreError, open_authenticated_parent};
use crate::seal_wal::{ExclusiveFileLock, RecoveryLockError, StrongObjectIdentity};
use crate::staging_recovery::strong_identity_fd;
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const LEAF_MODE: u32 = 0o700;
const PUBLIC_MODE: u32 = 0o755;
const PRIVATE_LOCK_MODE: u32 = 0o700;
pub(crate) const PROVISIONING_LOCK_NAME: &str = ".anchor-provisioning-lock";
const PRIVATE_TEMP_PREFIX: &str = ".degu-anchor-initializing-";
#[cfg(test)]
const TEST_CLEANUP_BLOCKER_NAME: &str = ".test-cleanup-blocker";
const PRIVATE_CREATE_MODE: Mode = Mode::RWXU;
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

mod account;
mod publish;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use account::AccountBaseError;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use account::{OS_PREFIX_COMPONENTS as BASE_COMPONENTS, PRODUCT_COMPONENTS, SELF_STATE_COMPONENTS};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use account::{current_self_anchor_path, system_anchor_root};
use publish::{
    chain_entry, directory_identity, fixed_path, io_error, merge_rollback_residue, open_directory,
    open_or_publish_directory, preflight_runtime_parent, report_all_scaffold_failure,
    report_created_scaffold_failure, revalidate_account_base, rollback_created, sync_directory,
    validate_binding, validate_directory,
};

/// Result of provisioning an activation anchor for one UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationAnchorProvisioningOutcome {
    pub path: PathBuf,
    pub uid: u32,
    pub backend: CertifiedLocalBackend,
    pub status: ActivationAnchorProvisioningStatus,
}

impl ActivationAnchorProvisioningOutcome {
    pub fn mutated(&self) -> bool {
        self.status == ActivationAnchorProvisioningStatus::Created
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationAnchorProvisioningStatus {
    Created,
    AlreadyProvisioned,
}

#[derive(Debug, thiserror::Error)]
pub enum ActivationAnchorProvisioningError {
    #[error("activation-anchor provisioning requires effective UID 0")]
    NotRoot,
    #[error("self-managed activation-anchor provisioning refuses effective UID 0")]
    RootCannotSelfProvision,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("self-managed activation-anchor account base is unavailable: {0}")]
    AccountBase(#[from] AccountBaseError),
    #[error("UID {uid} cannot be an activation-anchor target")]
    InvalidUid { uid: u32 },
    #[error("activation-anchor provisioning is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("unsafe existing activation-anchor namespace entry at {path}: {reason}")]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error("activation-anchor backend is unsupported at {path}: {reason:?}")]
    UnsupportedBackend {
        path: PathBuf,
        reason: CertificationError,
    },
    #[error("activation-anchor inspection is uncertain at {path}: {reason:?}")]
    Uncertain {
        path: PathBuf,
        reason: CertificationError,
    },
    #[error("activation-anchor provisioning I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("activation-anchor provisioning is busy at {path}")]
    Busy { path: PathBuf },
    #[error(
        "activation-anchor path cannot be consumed by the runtime contract at {path}: {source}"
    )]
    RuntimeIncompatible {
        path: PathBuf,
        #[source]
        source: StoreError,
    },
    #[error(
        "activation-anchor provisioning failed: {failure}; rollback is uncertain or left residue at {residue:?}"
    )]
    RollbackResidue {
        failure: String,
        residue: Vec<PathBuf>,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn refuse_existing_self_candidate(uid: u32) -> Result<(), ActivationAnchorProvisioningError> {
    let Some(path) = account::self_anchor_path_for_uid(uid)? else {
        return Ok(());
    };
    refuse_existing_self_candidate_path(path)
}

fn refuse_existing_self_candidate_path(
    path: PathBuf,
) -> Result<(), ActivationAnchorProvisioningError> {
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Err(ActivationAnchorProvisioningError::Unsafe {
            path,
            reason: "a self-managed activation candidate already exists; system initialization would compete",
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ActivationAnchorProvisioningError::Io { path, source }),
    }
}

/// Provision the fixed platform path for `uid`.
///
/// The call is create-only and requires real effective UID zero. `initial` is
/// the administrator's assertion that this numeric UID has never activated a
/// store; it is not repair or recovery authority.
pub fn provision_activation_anchor(
    uid: u32,
    initial: bool,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    if !rustix::process::geteuid().is_root() {
        return Err(ActivationAnchorProvisioningError::NotRoot);
    }
    validate_provision_arguments(Path::new("/"), uid, initial)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    refuse_existing_self_candidate(uid)?;
    provision(
        Path::new("/"),
        uid,
        initial,
        Credentials {
            controller_uid: 0,
            enforce_root: true,
        },
        BackendProbe::Real,
    )
}

/// Provision the self-managed activation anchor for the current effective UID.
///
/// The target is derived exclusively from the account database and the fixed
/// self-managed layout. Callers cannot select a UID or path. Root is rejected:
/// administrators must use [`provision_activation_anchor`] instead.
pub fn provision_current_euid_self_activation_anchor()
-> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            return Err(ActivationAnchorProvisioningError::RootCannotSelfProvision);
        }
        provision_current_euid_self_with_lookup(euid, account::self_anchor_base)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ActivationAnchorProvisioningError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provision_current_euid_self_with_lookup<F>(
    euid: u32,
    mut account_home_lookup: F,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError>
where
    F: FnMut() -> Result<PathBuf, AccountBaseError>,
{
    let account_home = account_home_lookup()?;
    provision_flavor(
        ProvisioningFlavor::SelfManaged(&account_home),
        euid,
        Credentials {
            controller_uid: euid,
            enforce_root: false,
        },
        BackendProbe::Real,
        Some(&mut account_home_lookup),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum ProvisioningFlavor<'a> {
    System(&'a Path),
    SelfManaged(&'a Path),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'a> ProvisioningFlavor<'a> {
    fn base(self) -> &'a Path {
        match self {
            Self::System(path) | Self::SelfManaged(path) => path,
        }
    }

    fn existing_prefix(self) -> &'static [&'static str] {
        match self {
            Self::System(_) => BASE_COMPONENTS,
            Self::SelfManaged(_) => &[],
        }
    }

    fn scaffold_prefix(self) -> &'static [&'static str] {
        match self {
            Self::System(_) => &[],
            Self::SelfManaged(_) => SELF_STATE_COMPONENTS,
        }
    }

    fn uses_trusted_account_base(self) -> bool {
        matches!(self, Self::SelfManaged(_))
    }
}

#[derive(Clone, Copy)]
struct Credentials {
    controller_uid: u32,
    enforce_root: bool,
}

#[derive(Clone, Copy)]
enum BackendProbe {
    Real,
    #[cfg(test)]
    Fixed(CertifiedLocalBackend),
    #[cfg(test)]
    FailAt(&'static str),
    #[cfg(test)]
    LoseNoreplaceRaceAndBlockCleanupAt(&'static str),
}

struct ValidatedDirectory {
    fd: OwnedFd,
    identity: StrongObjectIdentity,
    backend: CertifiedLocalBackend,
}

struct ChainEntry {
    parent: OwnedFd,
    name: OsString,
    child: OwnedFd,
    path: PathBuf,
    identity: StrongObjectIdentity,
    kind: DirectoryKind,
}

struct CreatedEntry {
    parent: OwnedFd,
    name: OsString,
    path: PathBuf,
    identity: StrongObjectIdentity,
}

#[derive(Clone, Copy)]
enum DirectoryKind {
    System,
    Public,
    Leaf(u32),
    PrivateLock,
}

fn validate_provision_arguments(
    filesystem_root: &Path,
    uid: u32,
    initial: bool,
) -> Result<(), ActivationAnchorProvisioningError> {
    if uid == 0 || uid == u32::MAX {
        return Err(ActivationAnchorProvisioningError::InvalidUid { uid });
    }
    if !initial {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: fixed_path(ProvisioningFlavor::System(filesystem_root), uid),
            reason: "the administrator must assert --initial; provisioning is not repair or recovery",
        });
    }
    Ok(())
}

fn provision(
    filesystem_root: &Path,
    uid: u32,
    initial: bool,
    credentials: Credentials,
    backend_probe: BackendProbe,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    if credentials.enforce_root && !rustix::process::geteuid().is_root() {
        return Err(ActivationAnchorProvisioningError::NotRoot);
    }
    validate_provision_arguments(filesystem_root, uid, initial)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (filesystem_root, credentials, backend_probe);
        Err(ActivationAnchorProvisioningError::UnsupportedPlatform)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    provision_flavor(
        ProvisioningFlavor::System(filesystem_root),
        uid,
        credentials,
        backend_probe,
        None,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provision_flavor(
    flavor: ProvisioningFlavor<'_>,
    uid: u32,
    credentials: Credentials,
    backend_probe: BackendProbe,
    mut account_home_lookup: Option<&mut dyn FnMut() -> Result<PathBuf, AccountBaseError>>,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    let filesystem_root = flavor.base();
    let mut path = filesystem_root.to_path_buf();
    let mut current = if flavor.uses_trusted_account_base() {
        degu_walk::resolve_trusted_directory(filesystem_root, "self-managed account base")
            .map_err(|source| io_error(filesystem_root, source))?
    } else {
        rustix::fs::open(filesystem_root, OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(filesystem_root, error.into()))?
    };
    // The trusted resolver permits trusted symlinks. Before creating self-managed
    // state, also require the lexical runtime path to be no-follow, ACL-free, and
    // on a certified local backend. The system base retains its existing checks.
    let trusted_base_identity = if flavor.uses_trusted_account_base() {
        let identity = directory_identity(&current, filesystem_root)?;
        // Reject a lexical passwd-home path that runtime could never consume
        // before creating even the shared self-managed scaffold.
        preflight_runtime_parent(&filesystem_root.join(SELF_STATE_COMPONENTS[0]), &current)?;
        Some(identity)
    } else {
        None
    };
    let root = if flavor.uses_trusted_account_base() {
        None
    } else {
        Some(validate_directory(
            &current,
            &path,
            credentials.controller_uid,
            DirectoryKind::System,
            backend_probe,
        )?)
    };
    let mut chain = Vec::new();

    // The operating-system prefix is existing-only. Provisioning never invents
    // `/var/lib` or `/private/var/db` and never repairs it.
    for component in flavor.existing_prefix() {
        path.push(component);
        let child = open_directory(&current, OsStr::new(component), &path)?;
        let validated = validate_directory(
            &child,
            &path,
            credentials.controller_uid,
            DirectoryKind::System,
            backend_probe,
        )?;
        validate_binding(
            &current,
            OsStr::new(component),
            &child,
            &path,
            validated.identity,
        )?;
        chain.push(chain_entry(
            &current,
            OsStr::new(component),
            &child,
            &path,
            validated.identity,
            DirectoryKind::System,
        )?);
        current = child;
    }

    // Self-managed `.local/state` components are flavor data. Existing entries
    // are never repaired; missing entries are privately initialized, certified,
    // strongly identified, synced, and atomically published by the shared driver.
    let mut flavor_scaffold_created = Vec::new();
    for component in flavor.scaffold_prefix() {
        path.push(component);
        let (directory, created) = open_or_publish_directory(
            &current,
            OsStr::new(component),
            &path,
            credentials.controller_uid,
            DirectoryKind::System,
            backend_probe,
        )
        .map_err(|error| report_created_scaffold_failure(error, &flavor_scaffold_created))?;
        if created.is_some() {
            flavor_scaffold_created.push(path.clone());
        }
        chain.push(
            chain_entry(
                &current,
                OsStr::new(component),
                &directory.fd,
                &path,
                directory.identity,
                DirectoryKind::System,
            )
            .map_err(|error| report_created_scaffold_failure(error, &flavor_scaffold_created))?,
        );
        current = directory.fd;
    }

    // Publish the degu-owned serialization namespace first. A safe, empty
    // scaffold may remain after a later failure; it carries no per-UID
    // authority and is accepted idempotently. We never lock the shared OS base.
    let degu_name = OsStr::new(PRODUCT_COMPONENTS[0]);
    path.push(degu_name);
    let (degu, degu_created) = open_or_publish_directory(
        &current,
        degu_name,
        &path,
        credentials.controller_uid,
        DirectoryKind::Public,
        backend_probe,
    )
    .map_err(|error| report_created_scaffold_failure(error, &flavor_scaffold_created))?;
    let degu_chain = chain_entry(
        &current,
        degu_name,
        &degu.fd,
        &path,
        degu.identity,
        DirectoryKind::Public,
    )
    .map_err(|error| {
        report_all_scaffold_failure(
            error,
            flavor,
            &flavor_scaffold_created,
            degu_created.is_some(),
            false,
        )
    })?;
    chain.push(degu_chain);
    current = degu.fd;

    // Publish and lock a root-private degu object. Public product directories
    // must remain readable/searchable because runtime authentication opens
    // them with O_RDONLY|O_DIRECTORY; locking either the OS base or a public
    // directory would let unrelated unprivileged processes cause Busy.
    let lock_path = path.join(PROVISIONING_LOCK_NAME);
    let (lock_directory, lock_created) = open_or_publish_directory(
        &current,
        OsStr::new(PROVISIONING_LOCK_NAME),
        &lock_path,
        credentials.controller_uid,
        DirectoryKind::PrivateLock,
        backend_probe,
    )
    .map_err(|error| {
        report_all_scaffold_failure(
            error,
            flavor,
            &flavor_scaffold_created,
            degu_created.is_some(),
            false,
        )
    })?;
    let scaffold_created = (degu_created.is_some(), lock_created.is_some());
    let lock_fd = rustix::io::fcntl_dupfd_cloexec(&lock_directory.fd, 0)
        .map_err(|error| io_error(&lock_path, error.into()))
        .map_err(|error| {
            report_all_scaffold_failure(
                error,
                flavor,
                &flavor_scaffold_created,
                scaffold_created.0,
                scaffold_created.1,
            )
        })?;
    let _provisioning_lock = ExclusiveFileLock::try_acquire(File::from(lock_fd))
        .map_err(|error| match error {
            RecoveryLockError::Busy => ActivationAnchorProvisioningError::Busy {
                path: lock_path.clone(),
            },
            RecoveryLockError::Io(source) => ActivationAnchorProvisioningError::Io {
                path: lock_path.clone(),
                source,
            },
        })
        .map_err(|error| {
            report_all_scaffold_failure(
                error,
                flavor,
                &flavor_scaffold_created,
                scaffold_created.0,
                scaffold_created.1,
            )
        })?;
    validate_binding(
        &current,
        OsStr::new(PROVISIONING_LOCK_NAME),
        &lock_directory.fd,
        &lock_path,
        lock_directory.identity,
    )
    .and_then(|()| {
        validate_directory(
            &lock_directory.fd,
            &lock_path,
            credentials.controller_uid,
            DirectoryKind::PrivateLock,
            backend_probe,
        )
        .map(|_| ())
    })
    .map_err(|error| {
        report_all_scaffold_failure(
            error,
            flavor,
            &flavor_scaffold_created,
            scaffold_created.0,
            scaffold_created.1,
        )
    })?;

    let mut created = Vec::new();
    let attempt = (|| {
        let store_name = OsStr::new(PRODUCT_COMPONENTS[1]);
        path.push(store_name);
        let (store_parent, store_created) = open_or_publish_directory(
            &current,
            store_name,
            &path,
            credentials.controller_uid,
            DirectoryKind::Public,
            backend_probe,
        )?;
        if let Some(created_entry) = store_created {
            created.push(created_entry);
        }
        chain.push(chain_entry(
            &current,
            store_name,
            &store_parent.fd,
            &path,
            store_parent.identity,
            DirectoryKind::Public,
        )?);
        current = store_parent.fd;

        let leaf_name = uid.to_string();
        let leaf_path = path.join(&leaf_name);
        let leaf_owner = if credentials.enforce_root {
            uid
        } else {
            credentials.controller_uid
        };
        if let (Some(expected), Some(lookup)) =
            (trusted_base_identity, account_home_lookup.as_deref_mut())
        {
            revalidate_account_base(filesystem_root, expected, lookup)?;
            preflight_runtime_parent(&leaf_path, &current)?;
        }
        let (leaf, leaf_created) = open_or_publish_directory(
            &current,
            OsStr::new(&leaf_name),
            &leaf_path,
            leaf_owner,
            DirectoryKind::Leaf(leaf_owner),
            backend_probe,
        )?;
        let was_created = leaf_created.is_some();
        if let Some(created_entry) = leaf_created {
            created.push(created_entry);
        }
        chain.push(chain_entry(
            &current,
            OsStr::new(&leaf_name),
            &leaf.fd,
            &leaf_path,
            leaf.identity,
            DirectoryKind::Leaf(leaf_owner),
        )?);

        // Re-authenticate after leaf publication, before the complete held
        // chain and its durability boundaries are validated. The same account
        // and runtime checks run again at the final commit gate below.
        if let (Some(expected), Some(lookup)) =
            (trusted_base_identity, account_home_lookup.as_deref_mut())
        {
            revalidate_account_base(filesystem_root, expected, lookup)?;
            preflight_runtime_parent(&leaf_path, &current)?;
        }
        if let Some(root) = &root {
            validate_directory(
                &root.fd,
                filesystem_root,
                credentials.controller_uid,
                DirectoryKind::System,
                backend_probe,
            )?;
        }
        for entry in &chain {
            validate_binding(
                &entry.parent,
                &entry.name,
                &entry.child,
                &entry.path,
                entry.identity,
            )?;
            validate_directory(
                &entry.child,
                &entry.path,
                match entry.kind {
                    DirectoryKind::Leaf(owner) => owner,
                    DirectoryKind::System | DirectoryKind::Public | DirectoryKind::PrivateLock => {
                        credentials.controller_uid
                    }
                },
                entry.kind,
                backend_probe,
            )?;
        }
        sync_directory(&leaf.fd, &leaf_path)?;
        for entry in chain.iter().rev() {
            sync_directory(
                &entry.parent,
                entry.path.parent().unwrap_or(filesystem_root),
            )?;
        }
        // This is the commit gate: re-read account facts and re-open the exact
        // runtime ancestry after all validation and fsync work, immediately
        // before relinquishing rollback authority over the published leaf.
        if let (Some(expected), Some(lookup)) =
            (trusted_base_identity, account_home_lookup.as_deref_mut())
        {
            revalidate_account_base(filesystem_root, expected, lookup)?;
            preflight_runtime_parent(&leaf_path, &current)?;
        }
        created.clear();
        Ok(ActivationAnchorProvisioningOutcome {
            path: fixed_path(flavor, uid),
            uid,
            backend: leaf.backend,
            status: if was_created {
                ActivationAnchorProvisioningStatus::Created
            } else {
                ActivationAnchorProvisioningStatus::AlreadyProvisioned
            },
        })
    })();

    match attempt {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let mut residue = rollback_created(&mut created);
            // The degu namespace and its private cooperative lock are durable,
            // safe prerequisites. Once published they may be adopted by a
            // concurrent/retry invocation and are therefore never rolled back.
            // Report their creation honestly if this invocation later fails.
            if degu_created.is_some() {
                let mut degu_path = filesystem_root.to_path_buf();
                for component in flavor
                    .existing_prefix()
                    .iter()
                    .chain(flavor.scaffold_prefix())
                    .chain(std::iter::once(&PRODUCT_COMPONENTS[0]))
                {
                    degu_path.push(component);
                }
                residue.push(degu_path);
            }
            if lock_created.is_some() {
                let mut lock_path = filesystem_root.to_path_buf();
                for component in flavor
                    .existing_prefix()
                    .iter()
                    .chain(flavor.scaffold_prefix())
                    .chain(std::iter::once(&PRODUCT_COMPONENTS[0]))
                    .chain(std::iter::once(&PROVISIONING_LOCK_NAME))
                {
                    lock_path.push(component);
                }
                residue.push(lock_path);
            }
            residue.extend(flavor_scaffold_created);
            Err(merge_rollback_residue(error, &residue))
        }
    }
}
#[cfg(test)]
mod tests;
