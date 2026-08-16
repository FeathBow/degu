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
const PROVISIONING_LOCK_NAME: &str = ".anchor-provisioning-lock";
const PRIVATE_TEMP_PREFIX: &str = ".degu-anchor-initializing-";
#[cfg(test)]
const TEST_CLEANUP_BLOCKER_NAME: &str = ".test-cleanup-blocker";
const PRIVATE_CREATE_MODE: Mode = Mode::RWXU;
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::anchor_layout::{
    OS_PREFIX_COMPONENTS as BASE_COMPONENTS, PRODUCT_COMPONENTS, SELF_STATE_COMPONENTS,
    SelfAnchorRootError,
};

/// Result of provisioning the platform-fixed activation anchor for one UID.
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
    AccountBase(#[from] SelfAnchorRootError),
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
        provision_current_euid_self_with_lookup(euid, crate::anchor_layout::self_anchor_base)
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
    F: FnMut() -> Result<PathBuf, SelfAnchorRootError>,
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
    if uid == 0 || uid == u32::MAX {
        return Err(ActivationAnchorProvisioningError::InvalidUid { uid });
    }
    if !initial {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: fixed_path(ProvisioningFlavor::System(filesystem_root), uid),
            reason: "the administrator must assert --initial; provisioning is not repair or recovery",
        });
    }
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
    mut account_home_lookup: Option<&mut dyn FnMut() -> Result<PathBuf, SelfAnchorRootError>>,
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
    // trusted_path makes the initial self-managed walk descriptor-relative. A
    // later runtime-contract preflight additionally requires the lexical account
    // ancestry to be no-follow, ACL-free, and on a certified local backend before
    // a leaf can be published. The system base retains its existing checks.
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
fn open_or_publish_directory(
    parent: &OwnedFd,
    final_name: &OsStr,
    final_path: &Path,
    owner: u32,
    kind: DirectoryKind,
    backend_probe: BackendProbe,
) -> Result<(ValidatedDirectory, Option<CreatedEntry>), ActivationAnchorProvisioningError> {
    match open_directory(parent, final_name, final_path) {
        Ok(fd) => {
            let validated = validate_directory(&fd, final_path, owner, kind, backend_probe)?;
            validate_binding(parent, final_name, &fd, final_path, validated.identity)?;
            return Ok((validated, None));
        }
        Err(ActivationAnchorProvisioningError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let temp_name = private_temp_name()?;
    let temp_path = final_path.with_file_name(&temp_name);
    rustix::fs::mkdirat(parent, &temp_name, PRIVATE_CREATE_MODE)
        .map_err(|error| io_error(&temp_path, error.into()))?;
    let temp_fd = match open_directory(parent, &temp_name, &temp_path) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(ActivationAnchorProvisioningError::RollbackResidue {
                failure: error.to_string(),
                residue: vec![temp_path],
            });
        }
    };
    let birth_identity = strong_identity_fd(&temp_fd).map_err(|_| {
        ActivationAnchorProvisioningError::RollbackResidue {
            failure: "strong birth identity is unavailable for the private initializer".into(),
            residue: vec![temp_path.clone()],
        }
    })?;
    if let Err(error) = validate_binding(parent, &temp_name, &temp_fd, &temp_path, birth_identity) {
        return cleanup_temp_after_failure(parent, &temp_name, &temp_path, birth_identity, error);
    }

    let initialize = (|| {
        let mode = match kind {
            DirectoryKind::Public => PUBLIC_MODE,
            DirectoryKind::System | DirectoryKind::Leaf(_) | DirectoryKind::PrivateLock => {
                PRIVATE_LOCK_MODE
            }
        };
        rustix::fs::fchmod(&temp_fd, Mode::from_raw_mode(mode as _))
            .map_err(|error| io_error(&temp_path, error.into()))?;
        if matches!(kind, DirectoryKind::Leaf(_)) {
            fchown_uid(&temp_fd, owner).map_err(|error| io_error(&temp_path, error))?;
        }
        let validated = validate_directory(&temp_fd, &temp_path, owner, kind, backend_probe)?;
        validate_binding(parent, &temp_name, &temp_fd, &temp_path, birth_identity)?;
        sync_directory(&temp_fd, &temp_path)?;
        sync_directory(parent, final_path.parent().unwrap_or(Path::new("/")))?;
        Ok(validated)
    })();
    if let Err(error) = initialize {
        return cleanup_temp_after_failure(parent, &temp_name, &temp_path, birth_identity, error);
    }

    let published_rollback =
        match prepared_created_entry(parent, final_name, final_path, birth_identity) {
            Ok(entry) => entry,
            Err(error) => {
                return cleanup_temp_after_failure(
                    parent,
                    &temp_name,
                    &temp_path,
                    birth_identity,
                    error,
                );
            }
        };

    #[cfg(test)]
    if let BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(target) = backend_probe
        && final_name == OsStr::new(target)
    {
        // Deterministically model a concurrent winner, then make this
        // invocation's initializer non-empty so collision cleanup fails.
        rustix::fs::mkdirat(parent, final_name, PRIVATE_CREATE_MODE)
            .map_err(|error| io_error(final_path, error.into()))?;
        rustix::fs::mkdirat(
            &temp_fd,
            OsStr::new(TEST_CLEANUP_BLOCKER_NAME),
            PRIVATE_CREATE_MODE,
        )
        .map_err(|error| io_error(&temp_path, error.into()))?;
    }

    match rustix::fs::renameat_with(
        parent,
        &temp_name,
        parent,
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            let published = (|| {
                sync_directory(parent, final_path.parent().unwrap_or(Path::new("/")))?;
                validate_binding(parent, final_name, &temp_fd, final_path, birth_identity)?;
                validate_directory(&temp_fd, final_path, owner, kind, backend_probe)
            })();
            match published {
                Ok(validated) => Ok((validated, Some(published_rollback))),
                Err(error) => cleanup_temp_after_failure(
                    parent,
                    final_name,
                    final_path,
                    birth_identity,
                    error,
                ),
            }
        }
        Err(rustix::io::Errno::EXIST) => {
            if let Err(failure) =
                remove_identity_matched_empty(parent, &temp_name, &temp_path, birth_identity)
            {
                return Err(ActivationAnchorProvisioningError::RollbackResidue {
                    failure: failure.to_string(),
                    residue: vec![temp_path],
                });
            }
            let fd = open_directory(parent, final_name, final_path)?;
            let validated = validate_directory(&fd, final_path, owner, kind, backend_probe)?;
            validate_binding(parent, final_name, &fd, final_path, validated.identity)?;
            Ok((validated, None))
        }
        Err(error) => cleanup_temp_after_failure(
            parent,
            &temp_name,
            &temp_path,
            birth_identity,
            io_error(final_path, error.into()),
        ),
    }
}

fn cleanup_temp_after_failure<T>(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    identity: StrongObjectIdentity,
    failure: ActivationAnchorProvisioningError,
) -> Result<T, ActivationAnchorProvisioningError> {
    match remove_identity_matched_empty(parent, name, path, identity) {
        Ok(()) => Err(failure),
        Err(_) => Err(ActivationAnchorProvisioningError::RollbackResidue {
            failure: failure.to_string(),
            residue: vec![path.to_path_buf()],
        }),
    }
}

#[allow(clippy::disallowed_methods)] // rollback: held parent, no-follow, strong identity, empty dir only
fn remove_identity_matched_empty(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
    identity: StrongObjectIdentity,
) -> Result<(), ActivationAnchorProvisioningError> {
    let fd = open_directory(parent, name, path)?;
    if strong_identity_fd(&fd).ok() != Some(identity)
        || !binding_matches(parent, name, &fd).map_err(|error| io_error(path, error))?
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "refusing to remove an initializer whose identity or binding changed",
        });
    }
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR)
        .map_err(|error| io_error(path, error.into()))?;
    sync_directory(parent, path.parent().unwrap_or(Path::new("/")))
}

fn private_temp_name() -> Result<OsString, ActivationAnchorProvisioningError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|source| ActivationAnchorProvisioningError::Io {
        path: PathBuf::from("platform random source"),
        source: io::Error::other(source),
    })?;
    let mut name = String::from(PRIVATE_TEMP_PREFIX);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(name.into())
}

fn open_directory(
    parent: &OwnedFd,
    name: &OsStr,
    path: &Path,
) -> Result<OwnedFd, ActivationAnchorProvisioningError> {
    rustix::fs::openat(parent, name, OPEN_DIRECTORY, Mode::empty()).map_err(|error| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
            ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "entry is not a no-follow directory",
            }
        }
        error => io_error(path, error.into()),
    })
}

fn validate_directory(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    kind: DirectoryKind,
    backend_probe: BackendProbe,
) -> Result<ValidatedDirectory, ActivationAnchorProvisioningError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "entry is not a directory",
        });
    }
    if stat.st_uid != owner {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: match kind {
                DirectoryKind::Leaf(_) => "activation-anchor leaf has the wrong owner",
                DirectoryKind::System | DirectoryKind::Public | DirectoryKind::PrivateLock
                    if owner != 0 =>
                {
                    "self-managed activation-anchor namespace component has the wrong owner"
                }
                DirectoryKind::System | DirectoryKind::Public | DirectoryKind::PrivateLock => {
                    "activation-anchor namespace component is not root-owned"
                }
            },
        });
    }
    let mode = stat.st_mode as u32 & 0o7777;
    match kind {
        DirectoryKind::System if mode & 0o022 != 0 => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "system activation-anchor component grants group or other write",
            });
        }
        DirectoryKind::Public if mode != PUBLIC_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "public activation-anchor component mode is not exactly 0755",
            });
        }
        DirectoryKind::PrivateLock if mode != PRIVATE_LOCK_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "private provisioning lock mode is not exactly 0700",
            });
        }
        DirectoryKind::Leaf(_) if mode != LEAF_MODE => {
            return Err(ActivationAnchorProvisioningError::Unsafe {
                path: path.to_path_buf(),
                reason: "activation-anchor leaf mode is not exactly 0700",
            });
        }
        DirectoryKind::System
        | DirectoryKind::Public
        | DirectoryKind::PrivateLock
        | DirectoryKind::Leaf(_) => {}
    }
    require_held_fd_acl_absent(fd).map_err(|reason| certification_error(path, reason))?;
    let backend = match backend_probe {
        BackendProbe::Real => certify_held_fd_backend(fd),
        #[cfg(test)]
        BackendProbe::Fixed(backend) => Ok(backend),
        #[cfg(test)]
        BackendProbe::FailAt(name) if path.file_name() == Some(OsStr::new(name)) => {
            Err(CertificationError::InspectionFailed)
        }
        #[cfg(test)]
        BackendProbe::FailAt(_) => Ok(CertifiedLocalBackend::Ext4),
        #[cfg(test)]
        BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(_) => certify_held_fd_backend(fd),
    }
    .map_err(|reason| certification_error(path, reason))?;
    let identity =
        strong_identity_fd(fd).map_err(|_| ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "strong birth identity is unavailable",
        })?;
    Ok(ValidatedDirectory {
        fd: rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(|error| io_error(path, error.into()))?,
        identity,
        backend,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_account_base(
    initial_home: &Path,
    expected_identity: (u64, u64),
    account_home_lookup: &mut dyn FnMut() -> Result<PathBuf, SelfAnchorRootError>,
) -> Result<(), ActivationAnchorProvisioningError> {
    let current_home = account_home_lookup()?;
    if current_home != initial_home {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: initial_home.to_path_buf(),
            reason: "account database home changed during self-managed provisioning",
        });
    }
    let rebound = degu_walk::resolve_trusted_directory(&current_home, "self-managed account base")
        .map_err(|source| io_error(&current_home, source))?;
    if directory_identity(&rebound, &current_home)? != expected_identity {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: current_home,
            reason: "self-managed account base binding changed during provisioning",
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preflight_runtime_parent(
    leaf_path: &Path,
    held_parent: &OwnedFd,
) -> Result<(), ActivationAnchorProvisioningError> {
    let (runtime_parent, runtime_name, runtime_parent_path) = open_authenticated_parent(leaf_path)
        .map_err(
            |source| ActivationAnchorProvisioningError::RuntimeIncompatible {
                path: leaf_path.to_path_buf(),
                source,
            },
        )?;
    if runtime_name != leaf_path.file_name().unwrap_or_default()
        || runtime_parent_path != leaf_path.parent().unwrap_or(Path::new("/"))
        || directory_identity(&runtime_parent, &runtime_parent_path)?
            != directory_identity(held_parent, &runtime_parent_path)?
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: leaf_path.to_path_buf(),
            reason: "runtime ancestry does not bind the provisioning parent",
        });
    }
    Ok(())
}

fn directory_identity(
    fd: &OwnedFd,
    path: &Path,
) -> Result<(u64, u64), ActivationAnchorProvisioningError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

fn validate_binding(
    parent: &OwnedFd,
    name: &OsStr,
    fd: &OwnedFd,
    path: &Path,
    identity: StrongObjectIdentity,
) -> Result<(), ActivationAnchorProvisioningError> {
    if !binding_matches(parent, name, fd).map_err(|error| io_error(path, error))?
        || strong_identity_fd(fd).ok() != Some(identity)
    {
        return Err(ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "held directory is no longer the exact parent entry",
        });
    }
    Ok(())
}

fn binding_matches(parent: &OwnedFd, name: &OsStr, fd: &OwnedFd) -> io::Result<bool> {
    let entry =
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let held = rustix::fs::fstat(fd).map_err(io::Error::from)?;
    Ok(entry.st_dev == held.st_dev
        && entry.st_ino == held.st_ino
        && FileType::from_raw_mode(entry.st_mode) == FileType::Directory)
}

fn chain_entry(
    parent: &OwnedFd,
    name: &OsStr,
    child: &OwnedFd,
    path: &Path,
    identity: StrongObjectIdentity,
    kind: DirectoryKind,
) -> Result<ChainEntry, ActivationAnchorProvisioningError> {
    Ok(ChainEntry {
        parent: rustix::io::fcntl_dupfd_cloexec(parent, 0)
            .map_err(|error| io_error(path, error.into()))?,
        name: name.to_os_string(),
        child: rustix::io::fcntl_dupfd_cloexec(child, 0)
            .map_err(|error| io_error(path, error.into()))?,
        path: path.to_path_buf(),
        identity,
        kind,
    })
}

fn prepared_created_entry(
    parent: &OwnedFd,
    final_name: &OsStr,
    final_path: &Path,
    identity: StrongObjectIdentity,
) -> Result<CreatedEntry, ActivationAnchorProvisioningError> {
    Ok(CreatedEntry {
        parent: rustix::io::fcntl_dupfd_cloexec(parent, 0)
            .map_err(|error| io_error(final_path, error.into()))?,
        name: final_name.to_os_string(),
        path: final_path.to_path_buf(),
        identity,
    })
}

fn rollback_created(created: &mut Vec<CreatedEntry>) -> Vec<PathBuf> {
    let mut residue = Vec::new();
    while let Some(entry) = created.pop() {
        if remove_identity_matched_empty(&entry.parent, &entry.name, &entry.path, entry.identity)
            .is_err()
        {
            residue.push(entry.path);
        }
    }
    residue
}

fn fchown_uid(fd: &OwnedFd, uid: u32) -> io::Result<()> {
    debug_assert_ne!(uid, u32::MAX);
    // SAFETY: `fd` is held open and the public/core validators reject the
    // `(uid_t)-1` sentinel before this function is reachable.
    let result = unsafe { libc::fchown(fd.as_raw_fd(), uid, !0 as libc::gid_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sync_directory(fd: &OwnedFd, path: &Path) -> Result<(), ActivationAnchorProvisioningError> {
    rustix::fs::fsync(fd).map_err(|error| io_error(path, error.into()))
}

fn certification_error(
    path: &Path,
    reason: CertificationError,
) -> ActivationAnchorProvisioningError {
    match reason {
        CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem => {
            ActivationAnchorProvisioningError::UnsupportedBackend {
                path: path.to_path_buf(),
                reason,
            }
        }
        CertificationError::FilesystemMagicMismatch
        | CertificationError::NotDirectory
        | CertificationError::AclPresent => ActivationAnchorProvisioningError::Unsafe {
            path: path.to_path_buf(),
            reason: "entry type, ACL, or filesystem identity is unsafe",
        },
        reason => ActivationAnchorProvisioningError::Uncertain {
            path: path.to_path_buf(),
            reason,
        },
    }
}

fn io_error(path: &Path, source: io::Error) -> ActivationAnchorProvisioningError {
    ActivationAnchorProvisioningError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn report_created_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    created: &[PathBuf],
) -> ActivationAnchorProvisioningError {
    merge_rollback_residue(error, created)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn merge_rollback_residue(
    error: ActivationAnchorProvisioningError,
    additional: &[PathBuf],
) -> ActivationAnchorProvisioningError {
    if additional.is_empty() {
        return error;
    }
    match error {
        ActivationAnchorProvisioningError::RollbackResidue {
            failure,
            mut residue,
        } => {
            residue.extend_from_slice(additional);
            residue.sort();
            residue.dedup();
            ActivationAnchorProvisioningError::RollbackResidue { failure, residue }
        }
        error => {
            let mut residue = additional.to_vec();
            residue.sort();
            residue.dedup();
            ActivationAnchorProvisioningError::RollbackResidue {
                failure: error.to_string(),
                residue,
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn report_all_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    flavor: ProvisioningFlavor<'_>,
    flavor_created: &[PathBuf],
    degu_created: bool,
    lock_created: bool,
) -> ActivationAnchorProvisioningError {
    let error = report_scaffold_failure(error, flavor, degu_created, lock_created);
    report_created_scaffold_failure(error, flavor_created)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn report_scaffold_failure(
    error: ActivationAnchorProvisioningError,
    flavor: ProvisioningFlavor<'_>,
    degu_created: bool,
    lock_created: bool,
) -> ActivationAnchorProvisioningError {
    let mut residue = Vec::new();
    let scaffold_path = |include_lock: bool| {
        let mut path = flavor.base().to_path_buf();
        for component in flavor
            .existing_prefix()
            .iter()
            .chain(flavor.scaffold_prefix())
            .chain(std::iter::once(&PRODUCT_COMPONENTS[0]))
        {
            path.push(component);
        }
        if include_lock {
            path.push(PROVISIONING_LOCK_NAME);
        }
        path
    };
    if degu_created {
        residue.push(scaffold_path(false));
    }
    if lock_created {
        residue.push(scaffold_path(true));
    }
    merge_rollback_residue(error, &residue)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fixed_path(flavor: ProvisioningFlavor<'_>, uid: u32) -> PathBuf {
    let mut path = flavor.base().to_path_buf();
    for component in flavor
        .existing_prefix()
        .iter()
        .chain(flavor.scaffold_prefix())
        .chain(PRODUCT_COMPONENTS)
    {
        path.push(component);
    }
    path.push(uid.to_string());
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};

    fn test_credentials() -> Credentials {
        Credentials {
            controller_uid: rustix::process::geteuid().as_raw(),
            enforce_root: false,
        }
    }

    fn test_uid() -> u32 {
        42424
    }

    fn fixture() -> tempfile::TempDir {
        let root = crate::secure_test_tempdir().unwrap();
        let mut base = root.path().to_path_buf();
        for component in BASE_COMPONENTS {
            base.push(component);
            std::fs::create_dir(&base).unwrap();
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        root
    }

    fn provision_test(
        root: &Path,
        uid: u32,
    ) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
        provision(
            root,
            uid,
            true,
            test_credentials(),
            BackendProbe::Fixed(CertifiedLocalBackend::Ext4),
        )
    }

    #[test]
    fn fixed_path_contains_only_platform_and_decimal_uid() {
        let path = fixed_path(ProvisioningFlavor::System(Path::new("/")), 12345);
        #[cfg(target_os = "linux")]
        assert_eq!(path, Path::new("/var/lib/degu/store-activation/12345"));
        #[cfg(target_os = "macos")]
        assert_eq!(
            path,
            Path::new("/private/var/db/degu/store-activation/12345")
        );
    }

    #[test]
    fn create_then_validate_without_repair_and_runtime_can_open_public_parents() {
        let root = fixture();
        let created = provision_test(root.path(), test_uid()).unwrap();
        assert_eq!(created.status, ActivationAnchorProvisioningStatus::Created);
        assert_eq!(
            std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
            LEAF_MODE
        );
        for parent in [
            created.path.parent().unwrap(),
            created.path.parent().unwrap().parent().unwrap(),
        ] {
            let metadata = std::fs::symlink_metadata(parent).unwrap();
            assert_eq!(metadata.mode() & 0o7777, PUBLIC_MODE);
            assert_eq!(
                metadata.mode() & 0o005,
                0o005,
                "runtime needs read and search"
            );
        }
        let lock = created
            .path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(PROVISIONING_LOCK_NAME);
        assert_eq!(
            std::fs::symlink_metadata(lock).unwrap().mode() & 0o7777,
            PRIVATE_LOCK_MODE
        );
        let again = provision_test(root.path(), test_uid()).unwrap();
        assert_eq!(
            again.status,
            ActivationAnchorProvisioningStatus::AlreadyProvisioned
        );
        assert!(!again.mutated());
    }

    #[test]
    fn existing_wrong_mode_is_rejected_and_unchanged() {
        let root = fixture();
        let created = provision_test(root.path(), test_uid()).unwrap();
        std::fs::set_permissions(&created.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = provision_test(root.path(), test_uid()).unwrap_err();
        assert!(error.to_string().contains("mode is not exactly 0700"));
        assert_eq!(
            std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn existing_file_and_symlink_are_never_replaced() {
        for symlink in [false, true] {
            let root = fixture();
            let leaf = fixed_path(ProvisioningFlavor::System(root.path()), test_uid());
            std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
            std::fs::set_permissions(
                leaf.parent().unwrap().parent().unwrap(),
                std::fs::Permissions::from_mode(PUBLIC_MODE),
            )
            .unwrap();
            std::fs::set_permissions(
                leaf.parent().unwrap(),
                std::fs::Permissions::from_mode(PUBLIC_MODE),
            )
            .unwrap();
            if symlink {
                std::os::unix::fs::symlink(root.path(), &leaf).unwrap();
            } else {
                std::fs::write(&leaf, b"keep").unwrap();
            }
            let error = provision_test(root.path(), test_uid()).unwrap_err();
            assert!(error.to_string().contains("not a no-follow directory"));
            if symlink {
                assert!(
                    std::fs::symlink_metadata(&leaf)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
            } else {
                assert_eq!(std::fs::read(&leaf).unwrap(), b"keep");
            }
        }
    }

    #[test]
    fn failure_rolls_back_only_this_attempts_published_components() {
        let root = fixture();
        let error = provision(
            root.path(),
            test_uid(),
            true,
            test_credentials(),
            BackendProbe::FailAt("store-activation"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("inspection is uncertain"));
        let mut base = root.path().to_path_buf();
        for component in BASE_COMPONENTS {
            base.push(component);
        }
        // The empty, authenticated degu-owned serialization scaffold is a
        // committed idempotent prerequisite, not per-UID authority.
        assert!(base.join("degu").is_dir());
        assert!(!base.join("degu/store-activation").exists());
    }

    #[test]
    fn cooperative_concurrency_never_removes_a_successful_anchor() {
        let root = fixture();
        let path = root.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                provision_test(&path, test_uid())
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(results.iter().any(Result::is_ok));
        assert!(fixed_path(ProvisioningFlavor::System(root.path()), test_uid()).is_dir());
        assert!(provision_test(root.path(), test_uid()).is_ok());
    }

    #[test]
    fn missing_initial_and_reserved_uids_are_rejected_before_mutation() {
        let root = fixture();
        assert!(
            provision(
                root.path(),
                test_uid(),
                false,
                test_credentials(),
                BackendProbe::Fixed(CertifiedLocalBackend::Ext4)
            )
            .is_err()
        );
        for uid in [0, u32::MAX] {
            assert!(matches!(
                provision(
                    root.path(),
                    uid,
                    true,
                    test_credentials(),
                    BackendProbe::Fixed(CertifiedLocalBackend::Ext4)
                ),
                Err(ActivationAnchorProvisioningError::InvalidUid { uid: rejected }) if rejected == uid
            ));
        }
    }

    fn provision_self_test(
        account_home: &Path,
    ) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
        let euid = rustix::process::geteuid().as_raw();
        let home = account_home.to_path_buf();
        let mut lookup = || Ok(home.clone());
        provision_flavor(
            ProvisioningFlavor::SelfManaged(account_home),
            euid,
            Credentials {
                controller_uid: euid,
                enforce_root: false,
            },
            BackendProbe::Real,
            Some(&mut lookup),
        )
    }

    #[test]
    fn self_flavor_uses_trusted_account_base_and_real_backend_certification() {
        let home = crate::secure_test_tempdir().unwrap();
        let canonical_home = home.path().canonicalize().unwrap();
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            // The public API rejects root, but the shared driver is still covered
            // under its exact current-EUID ownership policy.
        }
        let created = provision_self_test(&canonical_home).unwrap();
        assert_eq!(created.uid, euid);
        assert_eq!(created.status, ActivationAnchorProvisioningStatus::Created);
        assert_eq!(
            created.path,
            canonical_home
                .join(".local/state/degu/store-activation")
                .join(euid.to_string())
        );
        assert_eq!(
            std::fs::symlink_metadata(canonical_home.join(".local"))
                .unwrap()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::symlink_metadata(&created.path).unwrap().uid(),
            euid
        );
        assert_eq!(
            std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
            LEAF_MODE
        );
        let again = provision_self_test(&canonical_home).unwrap();
        assert_eq!(
            again.status,
            ActivationAnchorProvisioningStatus::AlreadyProvisioned
        );
        assert_eq!(again.backend, created.backend);
    }

    #[test]
    fn self_flavor_rejects_untrusted_home_ancestry_before_creation() {
        let outer = crate::secure_test_tempdir().unwrap();
        let home = outer.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let error = provision_self_test(&home).unwrap_err();
        assert!(matches!(
            error,
            ActivationAnchorProvisioningError::Io { .. }
        ));
        assert!(!home.join(".local").exists());
    }

    #[test]
    fn self_flavor_never_repairs_an_existing_scaffold() {
        let home = crate::secure_test_tempdir().unwrap();
        let canonical_home = home.path().canonicalize().unwrap();
        let local = canonical_home.join(".local");
        std::fs::create_dir(&local).unwrap();
        std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o770)).unwrap();
        let error = provision_self_test(&canonical_home).unwrap_err();
        assert!(error.to_string().contains("grants group or other write"));
        assert_eq!(
            std::fs::symlink_metadata(&local).unwrap().mode() & 0o7777,
            0o770
        );
        assert!(!local.join("state").exists());
    }

    #[test]
    fn self_flavor_concurrency_keeps_one_valid_current_euid_anchor() {
        let home = crate::secure_test_tempdir().unwrap();
        let path = home.path().canonicalize().unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                provision_self_test(&path)
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(results.iter().any(Result::is_ok));
        let final_result = provision_self_test(&path).unwrap();
        assert_eq!(
            final_result.status,
            ActivationAnchorProvisioningStatus::AlreadyProvisioned
        );
    }

    #[test]
    fn noreplace_loser_reports_unremoved_initializer_as_residue() {
        let home = crate::secure_test_tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let euid = rustix::process::geteuid().as_raw();
        let lookup_home = home.clone();
        let mut lookup = || Ok(lookup_home.clone());
        let error = provision_flavor(
            ProvisioningFlavor::SelfManaged(&home),
            euid,
            Credentials {
                controller_uid: euid,
                enforce_root: false,
            },
            BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(SELF_STATE_COMPONENTS[0]),
            Some(&mut lookup),
        )
        .unwrap_err();

        let (failure, residue) = match error {
            ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
                (failure, residue)
            }
            other => panic!("expected machine-readable initializer residue, got {other:?}"),
        };
        assert!(!failure.is_empty());
        assert_eq!(residue.len(), 1);
        let initializer = &residue[0];
        assert_eq!(initializer.parent(), Some(home.as_path()));
        assert!(
            initializer
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(PRIVATE_TEMP_PREFIX))
        );
        assert!(initializer.join(TEST_CLEANUP_BLOCKER_NAME).is_dir());
        let remaining_initializers = std::fs::read_dir(&home)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(PRIVATE_TEMP_PREFIX))
            })
            .collect::<Vec<_>>();
        assert_eq!(remaining_initializers, residue);
        assert!(home.join(SELF_STATE_COMPONENTS[0]).is_dir());
        assert!(!home.join(".local/state").exists());
    }

    #[test]
    fn all_scaffold_wrappers_preserve_original_failure_and_every_residue_path() {
        let home = PathBuf::from("/account-home");
        let local = home.join(".local");
        let state = local.join("state");
        let degu = state.join("degu");
        let lock = degu.join(PROVISIONING_LOCK_NAME);
        let initializer = degu.join(".degu-anchor-initializing-test");
        let merged = report_all_scaffold_failure(
            ActivationAnchorProvisioningError::RollbackResidue {
                failure: "original failure".into(),
                residue: vec![initializer.clone()],
            },
            ProvisioningFlavor::SelfManaged(&home),
            &[state.clone(), local.clone()],
            true,
            true,
        );
        match merged {
            ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
                let mut expected = vec![local, state, degu, lock, initializer];
                expected.sort();
                assert_eq!(failure, "original failure");
                assert_eq!(residue, expected);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn assert_self_scaffold_residue(
        error: ActivationAnchorProvisioningError,
        home: &Path,
    ) -> String {
        let local = home.join(".local");
        let state = local.join("state");
        let degu = state.join("degu");
        let lock = degu.join(PROVISIONING_LOCK_NAME);
        let mut expected = vec![local, state, degu, lock];
        expected.sort();
        match error {
            ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
                assert_eq!(residue, expected);
                failure
            }
            other => panic!("expected machine-readable scaffold residue, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn plant_ineffective_access_acl(path: &Path) {
        use std::os::fd::AsRawFd;

        let file = File::open(path).unwrap();
        let euid = rustix::process::geteuid().as_raw();
        let named_uid = if euid < u32::MAX - 1 { euid + 1 } else { 1 };
        let mut acl = Vec::new();
        acl.extend_from_slice(&2_u32.to_le_bytes());
        for (tag, permissions, qualifier) in [
            (1_u16, 7_u16, u32::MAX),
            (2_u16, 4_u16, named_uid),
            (4_u16, 0_u16, u32::MAX),
            (0x10_u16, 0_u16, u32::MAX),
            (0x20_u16, 0_u16, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&qualifier.to_le_bytes());
        }
        // SAFETY: the held directory FD, xattr name, and ACL bytes remain live
        // for the syscall. The zero mask makes the named entry ineffective, so
        // mode-only trusted ancestry still accepts the directory.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "failed to plant test ACL: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap().mode() & 0o7777,
            0o700
        );
    }

    #[cfg(target_os = "macos")]
    fn plant_ineffective_access_acl(path: &Path) {
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "failed to plant test ACL");
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn trusted_symlink_is_rejected_by_runtime_preflight_before_leaf_publication() {
        let outer = crate::secure_test_tempdir().unwrap();
        let outer = outer.path().canonicalize().unwrap();
        let real_home = outer.join("real-home");
        let alias_home = outer.join("alias-home");
        std::fs::create_dir(&real_home).unwrap();
        std::fs::set_permissions(&real_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real_home, &alias_home).unwrap();

        let error = provision_self_test(&alias_home).unwrap_err();
        assert!(matches!(
            error,
            ActivationAnchorProvisioningError::RuntimeIncompatible { .. }
        ));
        assert!(
            !real_home.join(".local").exists(),
            "runtime-incompatible account path created a scaffold"
        );
        let leaf = real_home
            .join(".local/state/degu/store-activation")
            .join(rustix::process::geteuid().as_raw().to_string());
        assert!(
            !leaf.exists(),
            "runtime-incompatible ancestry published a leaf"
        );
    }

    #[test]
    fn account_acl_is_rejected_by_the_shared_runtime_contract() {
        let home = crate::secure_test_tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        plant_ineffective_access_acl(&home);

        let error = provision_self_test(&home).unwrap_err();
        assert!(error.to_string().contains("runtime contract"));
        assert!(error.to_string().contains("ACL"));
        assert!(
            !home.join(".local").exists(),
            "ACL-incompatible account path created a scaffold"
        );
        let leaf = home
            .join(".local/state/degu/store-activation")
            .join(rustix::process::geteuid().as_raw().to_string());
        assert!(!leaf.exists(), "ACL-incompatible ancestry published a leaf");
    }

    #[test]
    fn account_home_a_to_b_drift_blocks_commit_and_rolls_back_leaf() {
        let a = crate::secure_test_tempdir().unwrap();
        let b = crate::secure_test_tempdir().unwrap();
        let a = a.path().canonicalize().unwrap();
        let b = b.path().canonicalize().unwrap();
        let mut answers = std::collections::VecDeque::from([a.clone(), a.clone(), a.clone(), b]);
        let euid = rustix::process::geteuid().as_raw();
        let error = provision_current_euid_self_with_lookup(euid, || {
            Ok(answers
                .pop_front()
                .expect("bounded account lookup sequence"))
        })
        .unwrap_err();
        let failure = assert_self_scaffold_residue(error, &a);
        assert!(failure.contains("account database home changed"));
        let leaf = a
            .join(".local/state/degu/store-activation")
            .join(euid.to_string());
        assert!(
            !leaf.exists(),
            "account drift left a published authority leaf"
        );
        assert!(
            answers.is_empty(),
            "final commit gate did not re-read account facts"
        );
    }

    #[test]
    fn public_self_entry_rejects_root_and_exposes_no_uid_or_path_selector() {
        if rustix::process::geteuid().is_root() {
            assert!(matches!(
                provision_current_euid_self_activation_anchor(),
                Err(ActivationAnchorProvisioningError::RootCannotSelfProvision)
            ));
        }
        let entry: fn() -> Result<_, _> = provision_current_euid_self_activation_anchor;
        let _ = entry;
    }

    #[test]
    fn production_entry_requires_real_root() {
        if !rustix::process::geteuid().is_root() {
            assert!(matches!(
                provision_activation_anchor(test_uid(), true),
                Err(ActivationAnchorProvisioningError::NotRoot)
            ));
        }
    }
}
