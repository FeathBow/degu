//! Durable, whole-store activation and discovery authority.
//!
//! The seal WAL cannot prove its own continued existence.  This module places a
//! fixed activation record below canonical HOME, outside the relocatable state
//! store, and requires a reciprocal marker in the exact store. Stable state
//! retains matching `prepare` and `active` locator/identity records, so loss of
//! `active` alone resumes from `prepare`. A missing recorded store is lost
//! authority, never permission to create an empty one under a changed XDG.
//!
//! The trust boundary is the same as `seal_store`: root and malicious same-EUID
//! processes are out of scope. Foreign users are excluded by no-follow,
//! EUID-owned 0700 directories, EUID-owned 0600 single-link records, absent
//! ACLs, certified local backends, strong birth identity, and held-FD checks.

use crate::local_backend::{CertificationError, CertifiedLocalBackend, require_held_fd_acl_absent};
use crate::seal_store::{
    SealWalStore, StoreError, StructuralEntryProbe, open_authenticated_parent,
    probe_private_parent_entry, probe_store_parent_backend,
    probe_store_parent_backend_after_authority_absence, validate_directory,
};
use crate::seal_wal::{ExclusiveFileLock, RecoveryLockError, StrongObjectIdentity};
use crate::staging_recovery::strong_identity_fd;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed HOME-relative root; it intentionally does not honor any XDG variable.
pub const AUTHORITY_DIRECTORY_NAME: &str = ".degu-store-authority";
pub const PREPARING_RECORD_NAME: &str = "sealed-staging.prepare";
pub const ACTIVE_RECORD_NAME: &str = "sealed-staging.active";
pub const STORE_BINDING_NAME: &str = "store.activation";

const DIRECTORY_MODE: Mode = Mode::RWXU;
const RECORD_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_RECORD: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const MAGIC_PREPARE: &[u8; 8] = b"DGUAPRP1";
const MAGIC_ACTIVE: &[u8; 8] = b"DGUACTV1";
const ACTIVATION_ID_LEN: usize = 32;
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_LOCATOR_BYTES: usize = 64 * 1024;
static NEXT_TEMP_NAME: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreActivationKind {
    NeverActivated,
    UnsupportedNeverActivated,
    Preparing,
    Activated,
    Lost,
    CorruptOrReplaced,
}

/// Result of fixed-root discovery. Only `Activated` carries a store handle.
pub enum StoreActivationState {
    NeverActivated,
    /// No authority exists and the desired store backend is explicitly outside
    /// the certified platform/filesystem set. This is the only legacy escape.
    UnsupportedNeverActivated,
    Preparing,
    Activated(ActivatedSealWalStore),
    Lost,
    CorruptOrReplaced,
}

impl StoreActivationState {
    pub fn kind(&self) -> StoreActivationKind {
        match self {
            Self::NeverActivated => StoreActivationKind::NeverActivated,
            Self::UnsupportedNeverActivated => StoreActivationKind::UnsupportedNeverActivated,
            Self::Preparing => StoreActivationKind::Preparing,
            Self::Activated(_) => StoreActivationKind::Activated,
            Self::Lost => StoreActivationKind::Lost,
            Self::CorruptOrReplaced => StoreActivationKind::CorruptOrReplaced,
        }
    }
}

/// Exact store handle delivered only after both activation records and all live
/// identities have been authenticated. It carries no forward-staging method.
pub struct ActivatedSealWalStore {
    store: SealWalStore,
    locator: PathBuf,
}

impl ActivatedSealWalStore {
    pub fn locator(&self) -> &Path {
        &self.locator
    }

    pub fn store(&self) -> &SealWalStore {
        &self.store
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreActivationError {
    #[error("canonical HOME is not a safe no-follow authority root: {0}")]
    UnsafeHome(#[source] StoreError),
    #[error("store activation I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("store activation requires a certified backend: {0:?}")]
    Backend(CertificationError),
    #[error("store activation strong identity is unavailable")]
    Identity,
    #[error("seal WAL store operation failed: {0}")]
    Store(#[source] StoreError),
    #[error("activation is not in a resumable never/preparing state")]
    NotResumable,
    #[error("activation record locator is invalid")]
    InvalidLocator,
    #[error("activation record inspection was uncertain at {path}: {reason:?}")]
    RecordInspection {
        path: PathBuf,
        reason: CertificationError,
    },
    #[error("durability of activation publication is uncertain at {0}")]
    SyncUncertain(&'static str),
    #[error("operating-system randomness for activation id failed: {0}")]
    Random(#[source] getrandom::Error),
}

#[derive(Clone, PartialEq, Eq)]
struct PrepareRecord {
    activation_id: [u8; ACTIVATION_ID_LEN],
    authority_locator: PathBuf,
    authority_identity: StrongObjectIdentity,
    authority_backend: CertifiedLocalBackend,
    store_locator: PathBuf,
    store_identity: StrongObjectIdentity,
    store_backend: CertifiedLocalBackend,
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveRecord {
    prepare: PrepareRecord,
}

struct AuthorityRoot {
    _home: OwnedFd,
    directory: OwnedFd,
    path: PathBuf,
    identity: StrongObjectIdentity,
    backend: CertifiedLocalBackend,
    _lock: ExclusiveFileLock,
}

/// Read the fixed canonical-HOME authority. `desired_store` is inspected only
/// after the authority entry is authoritatively absent; an existing authority
/// always goes through strict backend/ACL authentication and every failure
/// blocks. The structural absence probe grants no store or mutation authority.
pub fn discover_store_activation(
    canonical_home: &Path,
    desired_store: &Path,
) -> Result<StoreActivationState, StoreActivationError> {
    discover_store_activation_with_probe(canonical_home, desired_store, |path| {
        probe_desired_store_support_after_authority_absence(path)
    })
}

fn discover_store_activation_with_probe<F>(
    canonical_home: &Path,
    desired_store: &Path,
    mut support_probe: F,
) -> Result<StoreActivationState, StoreActivationError>
where
    F: FnMut(&Path) -> Result<(), StoreActivationError>,
{
    // Recheck absence through the same held HOME descriptor after the support
    // probe. This closes the only benign publication race without treating the
    // structure-only descriptor as authority.
    for _ in 0..8 {
        match probe_authority_entry(canonical_home)? {
            StructuralEntryProbe::Present => {
                if let Some(authority) = open_authority_root(canonical_home, false)? {
                    return discover_with_authority(&authority);
                }
            }
            StructuralEntryProbe::Absent(absence) => {
                let support = support_probe(desired_store);
                if !absence
                    .is_still_absent()
                    .map_err(StoreActivationError::UnsafeHome)?
                {
                    continue;
                }
                return match support {
                    Ok(()) => Ok(StoreActivationState::NeverActivated),
                    Err(StoreActivationError::Backend(
                        CertificationError::UnsupportedPlatform
                        | CertificationError::UnsupportedFilesystem,
                    )) => Ok(StoreActivationState::UnsupportedNeverActivated),
                    Err(error) => Err(error),
                };
            }
        }
    }
    Err(StoreActivationError::Io {
        path: canonical_home.join(AUTHORITY_DIRECTORY_NAME),
        source: io::Error::other("activation authority entry changed during discovery"),
    })
}

fn probe_authority_entry(
    canonical_home: &Path,
) -> Result<StructuralEntryProbe, StoreActivationError> {
    validate_absolute_locator(canonical_home)?;
    probe_private_parent_entry(&canonical_home.join(AUTHORITY_DIRECTORY_NAME))
        .map_err(StoreActivationError::UnsafeHome)
}

/// Begin or resume crash-safe activation. `desired_store` is consulted only in
/// `NeverActivated`; a durable preparing record always wins over changed XDG.
pub fn activate_or_resume_store(
    canonical_home: &Path,
    desired_store: &Path,
) -> Result<ActivatedSealWalStore, StoreActivationError> {
    // The first probe occurs before authority-root creation, so an explicitly
    // unsupported first use cannot leave evidence that later blocks legacy.
    let authority = match open_authority_root(canonical_home, false)? {
        Some(authority) => authority,
        None => {
            probe_desired_store_support(desired_store)?;
            open_authority_root(canonical_home, true)?.expect("create requested")
        }
    };
    match discover_with_authority(&authority)? {
        StoreActivationState::Activated(store) => return Ok(store),
        StoreActivationState::Lost | StoreActivationState::CorruptOrReplaced => {
            return Err(StoreActivationError::NotResumable);
        }
        StoreActivationState::NeverActivated
        | StoreActivationState::UnsupportedNeverActivated
        | StoreActivationState::Preparing => {}
    }

    let (prepare, store) = match read_optional_prepare(&authority)
        .map_err(store_error_from_record_read)?
    {
        Some(record) => {
            if classify_preparing(&authority, &record)?.kind() != StoreActivationKind::Preparing {
                return Err(StoreActivationError::NotResumable);
            }
            let store = match open_recorded_store(&record.store_locator)? {
                RecordedStore::Open(store) => store,
                RecordedStore::Lost | RecordedStore::Corrupt => {
                    return Err(StoreActivationError::NotResumable);
                }
            };
            (record, store)
        }
        None => {
            // Re-probe while holding the authority lock. The support decision
            // may have changed after discovery or the pre-creation probe.
            probe_desired_store_support(desired_store)?;
            let store =
                SealWalStore::open_or_create(desired_store).map_err(StoreActivationError::Store)?;
            store
                .revalidate_binding()
                .map_err(StoreActivationError::Store)?;
            let mut activation_id = [0_u8; ACTIVATION_ID_LEN];
            getrandom::fill(&mut activation_id).map_err(StoreActivationError::Random)?;
            let record = PrepareRecord {
                activation_id,
                authority_locator: authority.path.clone(),
                authority_identity: authority.identity,
                authority_backend: authority.backend,
                store_locator: desired_store.to_path_buf(),
                store_identity: strong_identity_fd(store.directory_fd())
                    .map_err(|_| StoreActivationError::Identity)?,
                store_backend: store.certified_backend(),
            };
            publish_record(
                &authority.directory,
                &authority.path,
                PREPARING_RECORD_NAME,
                &encode_prepare(&record)?,
                "preparing record",
            )?;
            (record, store)
        }
    };
    sync_fd(&authority.directory, "resumed preparing record")?;

    let active = ActiveRecord { prepare };
    let active_bytes = encode_active(&active)?;
    publish_or_verify_store_binding(&store, &active_bytes)?;
    publish_record(
        &authority.directory,
        &authority.path,
        ACTIVE_RECORD_NAME,
        &active_bytes,
        "active record",
    )?;
    // Prepare is intentionally permanent locator redundancy. Losing active
    // alone can therefore resume without consulting a changed desired locator.

    match validate_activated(&authority, active)? {
        StoreActivationState::Activated(store) => Ok(store),
        StoreActivationState::NeverActivated
        | StoreActivationState::UnsupportedNeverActivated
        | StoreActivationState::Preparing
        | StoreActivationState::Lost
        | StoreActivationState::CorruptOrReplaced => Err(StoreActivationError::NotResumable),
    }
}

fn probe_desired_store_support(desired_store: &Path) -> Result<(), StoreActivationError> {
    probe_desired_store_support_with(desired_store, probe_store_parent_backend)
}

fn probe_desired_store_support_after_authority_absence(
    desired_store: &Path,
) -> Result<(), StoreActivationError> {
    probe_desired_store_support_with(
        desired_store,
        probe_store_parent_backend_after_authority_absence,
    )
}

fn probe_desired_store_support_with(
    desired_store: &Path,
    probe: impl FnOnce(&Path) -> Result<CertifiedLocalBackend, StoreError>,
) -> Result<(), StoreActivationError> {
    validate_absolute_locator(desired_store)?;
    match probe(desired_store) {
        Ok(_) => Ok(()),
        Err(StoreError::ParentBackend { reason, .. }) => Err(StoreActivationError::Backend(reason)),
        Err(error) => Err(StoreActivationError::Store(error)),
    }
}

fn discover_with_authority(
    authority: &AuthorityRoot,
) -> Result<StoreActivationState, StoreActivationError> {
    match read_optional_active(authority) {
        Ok(Some(active)) => match read_optional_prepare(authority) {
            Ok(Some(prepare)) if prepare == active.prepare => validate_activated(authority, active),
            Ok(Some(_)) | Ok(None) | Err(RecordReadError::Corrupt) => {
                Ok(StoreActivationState::CorruptOrReplaced)
            }
            Err(RecordReadError::Io(path, source)) => {
                Err(StoreActivationError::Io { path, source })
            }
            Err(error @ RecordReadError::Inspection(_, _)) => {
                Err(store_error_from_record_read(error))
            }
        },
        Ok(None) => match read_optional_prepare(authority) {
            Ok(Some(prepare)) => classify_preparing(authority, &prepare),
            Ok(None) => Ok(StoreActivationState::NeverActivated),
            Err(RecordReadError::Corrupt) => Ok(StoreActivationState::CorruptOrReplaced),
            Err(RecordReadError::Io(path, source)) => {
                Err(StoreActivationError::Io { path, source })
            }
            Err(error @ RecordReadError::Inspection(_, _)) => {
                Err(store_error_from_record_read(error))
            }
        },
        Err(RecordReadError::Corrupt) => Ok(StoreActivationState::CorruptOrReplaced),
        Err(RecordReadError::Io(path, source)) => Err(StoreActivationError::Io { path, source }),
        Err(error @ RecordReadError::Inspection(_, _)) => Err(store_error_from_record_read(error)),
    }
}

enum RecordedStore {
    Open(SealWalStore),
    Lost,
    Corrupt,
}

fn open_recorded_store(locator: &Path) -> Result<RecordedStore, StoreActivationError> {
    match SealWalStore::open_existing(locator) {
        Ok(store) => Ok(RecordedStore::Open(store)),
        Err(StoreError::MissingStore { .. }) => Ok(RecordedStore::Lost),
        // These are deterministic evidence that an object exists at the bound
        // namespace but no longer satisfies the authenticated store contract.
        Err(
            StoreError::InvalidPath(_)
            | StoreError::UnsafeDirectory { .. }
            | StoreError::UnsafeWal { .. }
            | StoreError::MissingWal { .. },
        ) => Ok(RecordedStore::Corrupt),
        // Busy, I/O/fsync failures, and backend inspection uncertainty are not
        // durable state evidence. Preserve them as blocking errors.
        Err(
            error @ (StoreError::Io { .. }
            | StoreError::ParentBackend { .. }
            | StoreError::BackendInspection { .. }
            | StoreError::Lease(_)),
        ) => Err(StoreActivationError::Store(error)),
    }
}

fn classify_store_binding(
    store: &SealWalStore,
    prepare: &PrepareRecord,
) -> Result<bool, StoreActivationError> {
    if store.certified_backend() != prepare.store_backend
        || strong_identity_fd(store.directory_fd()).map_err(|_| StoreActivationError::Identity)?
            != prepare.store_identity
    {
        return Ok(false);
    }
    match store.revalidate_binding() {
        Ok(()) => Ok(true),
        Err(
            StoreError::InvalidPath(_)
            | StoreError::UnsafeDirectory { .. }
            | StoreError::UnsafeWal { .. }
            | StoreError::MissingStore { .. }
            | StoreError::MissingWal { .. },
        ) => Ok(false),
        Err(
            error @ (StoreError::Io { .. }
            | StoreError::ParentBackend { .. }
            | StoreError::BackendInspection { .. }
            | StoreError::Lease(_)),
        ) => Err(StoreActivationError::Store(error)),
    }
}

fn classify_preparing(
    authority: &AuthorityRoot,
    prepare: &PrepareRecord,
) -> Result<StoreActivationState, StoreActivationError> {
    if prepare.authority_locator != authority.path
        || prepare.authority_identity != authority.identity
        || prepare.authority_backend != authority.backend
    {
        return Ok(StoreActivationState::CorruptOrReplaced);
    }
    let store = match open_recorded_store(&prepare.store_locator)? {
        RecordedStore::Open(store) => store,
        RecordedStore::Lost => return Ok(StoreActivationState::Lost),
        RecordedStore::Corrupt => return Ok(StoreActivationState::CorruptOrReplaced),
    };
    if !classify_store_binding(&store, prepare)? {
        return Ok(StoreActivationState::CorruptOrReplaced);
    }
    Ok(StoreActivationState::Preparing)
}

fn validate_activated(
    authority: &AuthorityRoot,
    active: ActiveRecord,
) -> Result<StoreActivationState, StoreActivationError> {
    if active.prepare.authority_locator != authority.path
        || active.prepare.authority_identity != authority.identity
        || active.prepare.authority_backend != authority.backend
    {
        return Ok(StoreActivationState::CorruptOrReplaced);
    }
    let store = match open_recorded_store(&active.prepare.store_locator)? {
        RecordedStore::Open(store) => store,
        RecordedStore::Lost => return Ok(StoreActivationState::Lost),
        RecordedStore::Corrupt => return Ok(StoreActivationState::CorruptOrReplaced),
    };
    if !classify_store_binding(&store, &active.prepare)? {
        return Ok(StoreActivationState::CorruptOrReplaced);
    }
    let expected = encode_active(&active)?;
    match read_exact_record(
        store.directory_fd(),
        &active.prepare.store_locator,
        STORE_BINDING_NAME,
    ) {
        Ok(bytes) if bytes == expected => {}
        Ok(_) | Err(RecordReadError::Corrupt) => {
            return Ok(StoreActivationState::CorruptOrReplaced);
        }
        Err(RecordReadError::Io(_path, source)) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(StoreActivationState::CorruptOrReplaced);
        }
        Err(RecordReadError::Io(path, source)) => {
            return Err(StoreActivationError::Io { path, source });
        }
        Err(error @ RecordReadError::Inspection(_, _)) => {
            return Err(store_error_from_record_read(error));
        }
    }
    sync_fd(store.directory_fd(), "activated store directory")?;
    sync_fd(&authority.directory, "activation authority directory")?;
    Ok(StoreActivationState::Activated(ActivatedSealWalStore {
        locator: active.prepare.store_locator,
        store,
    }))
}

fn open_authority_root(
    canonical_home: &Path,
    create: bool,
) -> Result<Option<AuthorityRoot>, StoreActivationError> {
    validate_absolute_locator(canonical_home)?;
    let authority_path = canonical_home.join(AUTHORITY_DIRECTORY_NAME);
    let (home, name, opened_home_path) =
        open_authenticated_parent(&authority_path).map_err(StoreActivationError::UnsafeHome)?;
    if opened_home_path != canonical_home {
        return Err(StoreActivationError::InvalidLocator);
    }
    validate_canonical_home(&home, canonical_home)?;

    let mut created = false;
    let directory = match rustix::fs::openat(&home, &name, OPEN_DIRECTORY, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(rustix::io::Errno::NOENT) => {
            match rustix::fs::mkdirat(&home, &name, DIRECTORY_MODE) {
                Ok(()) => created = true,
                // Another activator may publish between the absent probe and
                // mkdir. Reopen and authenticate its object; never replace it.
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => {
                    return Err(StoreActivationError::Io {
                        path: authority_path.clone(),
                        source: error.into(),
                    });
                }
            }
            rustix::fs::openat(&home, &name, OPEN_DIRECTORY, Mode::empty())
                .map_err(io::Error::from)
                .map_err(|source| StoreActivationError::Io {
                    path: authority_path.clone(),
                    source,
                })?
        }
        Err(error) => {
            return Err(StoreActivationError::Io {
                path: authority_path,
                source: error.into(),
            });
        }
    };
    if created {
        rustix::fs::fchmod(&directory, DIRECTORY_MODE)
            .map_err(io::Error::from)
            .map_err(|source| StoreActivationError::Io {
                path: authority_path.clone(),
                source,
            })?;
    }
    if validate_directory(&directory, &authority_path).is_err() {
        return Err(StoreActivationError::UnsafeHome(
            StoreError::UnsafeDirectory {
                path: authority_path,
                reason: "activation authority is not a private certified directory",
            },
        ));
    }
    let identity = strong_identity_fd(&directory).map_err(|_| StoreActivationError::Identity)?;
    let backend = crate::local_backend::certify_held_fd_backend(&directory)
        .map_err(StoreActivationError::Backend)?;
    if created {
        sync_fd(&directory, "new authority directory")?;
    }
    // Re-establish namespace durability after every successful authority open
    // and validation, not only after mkdir. A retry necessarily performs this
    // HOME fsync again before returning authority.
    sync_fd(&home, "HOME after authority validation")?;
    let lock = try_lock_directory(&directory).map_err(|source| StoreActivationError::Io {
        path: authority_path.clone(),
        source,
    })?;
    Ok(Some(AuthorityRoot {
        _home: home,
        directory,
        path: authority_path,
        identity,
        backend,
        _lock: lock,
    }))
}

fn validate_canonical_home(home: &OwnedFd, path: &Path) -> Result<(), StoreActivationError> {
    validate_canonical_home_structure(home, path)?;
    require_held_fd_acl_absent(home).map_err(|_| {
        StoreActivationError::UnsafeHome(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "canonical HOME ACL is present or could not be verified absent",
        })
    })?;
    crate::local_backend::certify_held_fd_backend(home).map_err(StoreActivationError::Backend)?;
    Ok(())
}

fn validate_canonical_home_structure(
    home: &OwnedFd,
    path: &Path,
) -> Result<(), StoreActivationError> {
    let stat = rustix::fs::fstat(home)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mode = stat.st_mode as u32;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || mode & 0o030 == 0o030
        || mode & 0o003 == 0o003
    {
        return Err(StoreActivationError::UnsafeHome(
            StoreError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: "canonical HOME is not an EUID-owned exclusive directory",
            },
        ));
    }
    Ok(())
}

fn try_lock_directory(directory: &OwnedFd) -> io::Result<ExclusiveFileLock> {
    let fd = rustix::fs::openat(directory, ".", OPEN_DIRECTORY, Mode::empty())
        .map_err(io::Error::from)?;
    ExclusiveFileLock::try_acquire(File::from(fd)).map_err(|error| match error {
        RecoveryLockError::Busy => io::Error::other("activation authority is busy"),
        RecoveryLockError::Io(error) => error,
    })
}

fn publish_or_verify_store_binding(
    store: &SealWalStore,
    bytes: &[u8],
) -> Result<(), StoreActivationError> {
    match read_exact_record(
        store.directory_fd(),
        Path::new("activated seal WAL store"),
        STORE_BINDING_NAME,
    ) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) | Err(RecordReadError::Corrupt) => return Err(StoreActivationError::NotResumable),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => {}
        Err(RecordReadError::Io(path, source)) => {
            return Err(StoreActivationError::Io { path, source });
        }
        Err(error @ RecordReadError::Inspection(_, _)) => {
            return Err(store_error_from_record_read(error));
        }
    }
    publish_record(
        store.directory_fd(),
        Path::new("activated seal WAL store"),
        STORE_BINDING_NAME,
        bytes,
        "reciprocal store binding",
    )?;
    store
        .revalidate_binding()
        .map_err(StoreActivationError::Store)
}

fn publish_record(
    directory: &OwnedFd,
    directory_path: &Path,
    final_name: &str,
    bytes: &[u8],
    boundary: &'static str,
) -> Result<(), StoreActivationError> {
    match read_exact_record(directory, directory_path, final_name) {
        Ok(existing) if existing == bytes => {
            sync_fd(directory, boundary)?;
            return Ok(());
        }
        Ok(_) | Err(RecordReadError::Corrupt) => return Err(StoreActivationError::NotResumable),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => {}
        Err(RecordReadError::Io(path, source)) => {
            return Err(StoreActivationError::Io { path, source });
        }
        Err(error @ RecordReadError::Inspection(_, _)) => {
            return Err(store_error_from_record_read(error));
        }
    }

    let mut prepared = None;
    for _ in 0..128 {
        let sequence = NEXT_TEMP_NAME.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{final_name}.tmp-{}-{sequence}", std::process::id());
        match rustix::fs::openat(
            directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            RECORD_MODE,
        ) {
            Ok(fd) => {
                prepared = Some((temporary, fd));
                break;
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => {
                return Err(StoreActivationError::Io {
                    path: directory_path.join(temporary),
                    source: error.into(),
                });
            }
        }
    }
    let (temporary, fd) = prepared.ok_or(StoreActivationError::Io {
        path: directory_path.to_path_buf(),
        source: io::Error::other("activation temporary names are exhausted"),
    })?;
    let temporary_path = directory_path.join(&temporary);
    rustix::fs::fchmod(&fd, RECORD_MODE)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: temporary_path.clone(),
            source,
        })?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|source| StoreActivationError::Io {
            path: temporary_path.clone(),
            source,
        })?;
    sync_file(&file, boundary)?;
    validate_record_fd(&file)
        .map_err(|error| store_error_from_record_validation(temporary_path.clone(), error))?;
    rustix::fs::renameat_with(
        directory,
        temporary.as_str(),
        directory,
        final_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
    .map_err(|source| StoreActivationError::Io {
        path: directory_path.join(final_name),
        source,
    })?;
    sync_fd(directory, boundary)
}

#[derive(Debug)]
enum RecordReadError {
    Corrupt,
    Io(PathBuf, io::Error),
    Inspection(PathBuf, CertificationError),
}

#[derive(Debug)]
enum RecordValidationError {
    Corrupt,
    Io(io::Error),
    Inspection(CertificationError),
}

fn store_error_from_record_validation(
    path: PathBuf,
    error: RecordValidationError,
) -> StoreActivationError {
    match error {
        RecordValidationError::Corrupt => StoreActivationError::NotResumable,
        RecordValidationError::Io(source) => StoreActivationError::Io { path, source },
        RecordValidationError::Inspection(reason) => {
            StoreActivationError::RecordInspection { path, reason }
        }
    }
}

fn store_error_from_record_read(error: RecordReadError) -> StoreActivationError {
    match error {
        RecordReadError::Corrupt => StoreActivationError::NotResumable,
        RecordReadError::Io(path, source) => StoreActivationError::Io { path, source },
        RecordReadError::Inspection(path, reason) => {
            StoreActivationError::RecordInspection { path, reason }
        }
    }
}

fn read_optional_prepare(
    authority: &AuthorityRoot,
) -> Result<Option<PrepareRecord>, RecordReadError> {
    match read_exact_record(&authority.directory, &authority.path, PREPARING_RECORD_NAME) {
        Ok(bytes) => decode_prepare(&bytes)
            .map(Some)
            .ok_or(RecordReadError::Corrupt),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_optional_active(
    authority: &AuthorityRoot,
) -> Result<Option<ActiveRecord>, RecordReadError> {
    match read_exact_record(&authority.directory, &authority.path, ACTIVE_RECORD_NAME) {
        Ok(bytes) => decode_active(&bytes)
            .map(Some)
            .ok_or(RecordReadError::Corrupt),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_exact_record(
    directory: &OwnedFd,
    directory_path: &Path,
    name: &str,
) -> Result<Vec<u8>, RecordReadError> {
    let path = directory_path.join(name);
    let fd = match rustix::fs::openat(directory, name, OPEN_RECORD, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::LOOP) => return Err(RecordReadError::Corrupt),
        Err(error) => return Err(RecordReadError::Io(path.clone(), error.into())),
    };
    let mut file = File::from(fd);
    validate_record_fd(&file).map_err(|error| match error {
        RecordValidationError::Corrupt => RecordReadError::Corrupt,
        RecordValidationError::Io(source) => RecordReadError::Io(path.clone(), source),
        RecordValidationError::Inspection(reason) => {
            RecordReadError::Inspection(path.clone(), reason)
        }
    })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| RecordReadError::Io(path.clone(), source))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordReadError::Corrupt);
    }
    validate_record_binding(directory, name, &file).map_err(|error| match error {
        RecordValidationError::Corrupt => RecordReadError::Corrupt,
        RecordValidationError::Io(source) => RecordReadError::Io(path.clone(), source),
        RecordValidationError::Inspection(reason) => {
            RecordReadError::Inspection(path.clone(), reason)
        }
    })?;
    Ok(bytes)
}

fn validate_record_fd<Fd: AsFd>(fd: Fd) -> Result<(), RecordValidationError> {
    let stat = record_fstat(&fd).map_err(RecordValidationError::Io)?;
    match record_acl_probe(&fd) {
        Ok(()) => {}
        Err(CertificationError::AclPresent) => return Err(RecordValidationError::Corrupt),
        Err(reason) => return Err(RecordValidationError::Inspection(reason)),
    }
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || raw_mode_u32(stat.st_mode) & 0o7777 != raw_mode_u32(RECORD_MODE.bits())
        || stat.st_nlink != 1
    {
        return Err(RecordValidationError::Corrupt);
    }
    Ok(())
}

fn validate_record_binding<Fd: AsFd>(
    directory: &OwnedFd,
    name: &str,
    fd: Fd,
) -> Result<(), RecordValidationError> {
    let opened = record_fstat(&fd).map_err(RecordValidationError::Io)?;
    let entry = record_statat(directory, name).map_err(RecordValidationError::Io)?;
    if opened.st_dev != entry.st_dev
        || opened.st_ino != entry.st_ino
        || FileType::from_raw_mode(entry.st_mode) != FileType::RegularFile
    {
        return Err(RecordValidationError::Corrupt);
    }
    Ok(())
}

fn record_fstat<Fd: AsFd>(fd: Fd) -> io::Result<rustix::fs::Stat> {
    #[cfg(test)]
    inject_record_validation_failure(RecordValidationStep::Fstat)?;
    rustix::fs::fstat(fd).map_err(io::Error::from)
}

fn record_statat(directory: &OwnedFd, name: &str) -> io::Result<rustix::fs::Stat> {
    #[cfg(test)]
    inject_record_validation_failure(RecordValidationStep::Statat)?;
    rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
}

fn record_acl_probe<Fd: AsFd>(fd: Fd) -> Result<(), CertificationError> {
    #[cfg(test)]
    if inject_record_acl_unknown() {
        return Err(CertificationError::AclProbeUnknown);
    }
    require_held_fd_acl_absent(fd)
}

fn encode_prepare(record: &PrepareRecord) -> Result<Vec<u8>, StoreActivationError> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_PREPARE);
    out.extend_from_slice(&record.activation_id);
    put_path(&mut out, &record.authority_locator)?;
    put_identity(&mut out, record.authority_identity);
    out.push(encode_backend(record.authority_backend));
    put_path(&mut out, &record.store_locator)?;
    put_identity(&mut out, record.store_identity);
    out.push(encode_backend(record.store_backend));
    Ok(out)
}

fn decode_prepare(bytes: &[u8]) -> Option<PrepareRecord> {
    let mut input = bytes;
    take_magic(&mut input, MAGIC_PREPARE)?;
    let activation_id = take_array::<ACTIVATION_ID_LEN>(&mut input)?;
    let authority_locator = take_path(&mut input)?;
    let authority_identity = take_identity(&mut input)?;
    let authority_backend = decode_backend(*take(&mut input, 1)?.first()?)?;
    let store_locator = take_path(&mut input)?;
    let store_identity = take_identity(&mut input)?;
    let store_backend = decode_backend(*take(&mut input, 1)?.first()?)?;
    input.is_empty().then_some(PrepareRecord {
        activation_id,
        authority_locator,
        authority_identity,
        authority_backend,
        store_locator,
        store_identity,
        store_backend,
    })
}

fn encode_active(record: &ActiveRecord) -> Result<Vec<u8>, StoreActivationError> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_ACTIVE);
    out.extend_from_slice(&record.prepare.activation_id);
    put_path(&mut out, &record.prepare.authority_locator)?;
    put_identity(&mut out, record.prepare.authority_identity);
    out.push(encode_backend(record.prepare.authority_backend));
    put_path(&mut out, &record.prepare.store_locator)?;
    put_identity(&mut out, record.prepare.store_identity);
    out.push(encode_backend(record.prepare.store_backend));
    Ok(out)
}

fn decode_active(bytes: &[u8]) -> Option<ActiveRecord> {
    let mut input = bytes;
    take_magic(&mut input, MAGIC_ACTIVE)?;
    let activation_id = take_array::<ACTIVATION_ID_LEN>(&mut input)?;
    let authority_locator = take_path(&mut input)?;
    let authority_identity = take_identity(&mut input)?;
    let authority_backend = decode_backend(*take(&mut input, 1)?.first()?)?;
    let store_locator = take_path(&mut input)?;
    let store_identity = take_identity(&mut input)?;
    let store_backend = decode_backend(*take(&mut input, 1)?.first()?)?;
    input.is_empty().then_some(ActiveRecord {
        prepare: PrepareRecord {
            activation_id,
            authority_locator,
            authority_identity,
            authority_backend,
            store_locator,
            store_identity,
            store_backend,
        },
    })
}

fn put_path(out: &mut Vec<u8>, path: &Path) -> Result<(), StoreActivationError> {
    validate_absolute_locator(path)?;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_LOCATOR_BYTES || bytes.len() > u32::MAX as usize {
        return Err(StoreActivationError::InvalidLocator);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_path(input: &mut &[u8]) -> Option<PathBuf> {
    let length = u32::from_be_bytes(take_array::<4>(input)?) as usize;
    if length > MAX_LOCATOR_BYTES {
        return None;
    }
    let path = PathBuf::from(OsString::from_vec(take(input, length)?.to_vec()));
    validate_absolute_locator(&path).ok()?;
    Some(path)
}

fn put_identity(out: &mut Vec<u8>, identity: StrongObjectIdentity) {
    out.extend_from_slice(&identity.device().to_be_bytes());
    out.extend_from_slice(&identity.inode().to_be_bytes());
    out.extend_from_slice(&identity.incarnation().get().to_be_bytes());
    out.extend_from_slice(&identity.mount_id().to_be_bytes());
}

fn take_identity(input: &mut &[u8]) -> Option<StrongObjectIdentity> {
    Some(StrongObjectIdentity::new_with_mount(
        u64::from_be_bytes(take_array::<8>(input)?),
        u64::from_be_bytes(take_array::<8>(input)?),
        crate::seal_wal::ObjectIncarnation::new(u64::from_be_bytes(take_array::<8>(input)?)),
        u64::from_be_bytes(take_array::<8>(input)?),
    ))
}

fn encode_backend(backend: CertifiedLocalBackend) -> u8 {
    match backend {
        CertifiedLocalBackend::Ext4 => 1,
        CertifiedLocalBackend::Xfs => 2,
        CertifiedLocalBackend::Apfs => 3,
    }
}

fn decode_backend(byte: u8) -> Option<CertifiedLocalBackend> {
    match byte {
        1 => Some(CertifiedLocalBackend::Ext4),
        2 => Some(CertifiedLocalBackend::Xfs),
        3 => Some(CertifiedLocalBackend::Apfs),
        _ => None,
    }
}

fn take_magic(input: &mut &[u8], magic: &[u8]) -> Option<()> {
    (take(input, magic.len())? == magic).then_some(())
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    take(input, N)?.try_into().ok()
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    if input.len() < length {
        return None;
    }
    let (head, tail) = input.split_at(length);
    *input = tail;
    Some(head)
}

fn validate_absolute_locator(path: &Path) -> Result<(), StoreActivationError> {
    if !path.is_absolute() {
        return Err(StoreActivationError::InvalidLocator);
    }
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) if !name.is_empty() => saw_normal = true,
            Component::Normal(_)
            | Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_) => {
                return Err(StoreActivationError::InvalidLocator);
            }
        }
    }
    saw_normal
        .then_some(())
        .ok_or(StoreActivationError::InvalidLocator)
}

fn sync_file(file: &File, boundary: &'static str) -> Result<(), StoreActivationError> {
    #[cfg(test)]
    if matches!(sync_failure_timing(), Some(SyncFailureTiming::Before)) {
        return Err(StoreActivationError::SyncUncertain(boundary));
    }
    file.sync_all()
        .map_err(|_| StoreActivationError::SyncUncertain(boundary))?;
    #[cfg(test)]
    if matches!(LAST_SYNC_TIMING.get(), Some(SyncFailureTiming::After)) {
        return Err(StoreActivationError::SyncUncertain(boundary));
    }
    Ok(())
}

fn sync_fd(fd: &OwnedFd, boundary: &'static str) -> Result<(), StoreActivationError> {
    #[cfg(test)]
    if matches!(sync_failure_timing(), Some(SyncFailureTiming::Before)) {
        return Err(StoreActivationError::SyncUncertain(boundary));
    }
    rustix::fs::fsync(fd).map_err(|_| StoreActivationError::SyncUncertain(boundary))?;
    #[cfg(test)]
    if matches!(LAST_SYNC_TIMING.get(), Some(SyncFailureTiming::After)) {
        return Err(StoreActivationError::SyncUncertain(boundary));
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordValidationStep {
    Fstat,
    Statat,
}

#[cfg(test)]
std::thread_local! {
    static FAIL_RECORD_VALIDATION_AT: std::cell::Cell<Option<RecordValidationStep>> = const { std::cell::Cell::new(None) };
    static FAIL_RECORD_ACL_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn inject_record_validation_failure(step: RecordValidationStep) -> io::Result<()> {
    FAIL_RECORD_VALIDATION_AT.with(|failure| {
        if failure.get() == Some(step) {
            failure.set(None);
            Err(io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
fn set_record_validation_failure(step: Option<RecordValidationStep>) {
    FAIL_RECORD_VALIDATION_AT.with(|failure| failure.set(step));
}

#[cfg(test)]
fn inject_record_acl_unknown() -> bool {
    FAIL_RECORD_ACL_UNKNOWN.with(|failure| {
        let fail = failure.get();
        failure.set(false);
        fail
    })
}

#[cfg(test)]
fn set_record_acl_unknown(fail: bool) {
    FAIL_RECORD_ACL_UNKNOWN.with(|failure| failure.set(fail));
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncFailureTiming {
    Before,
    After,
}

#[cfg(test)]
std::thread_local! {
    static FAIL_SYNC_AT: std::cell::Cell<Option<(usize, SyncFailureTiming)>> = const { std::cell::Cell::new(None) };
    static SYNC_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LAST_SYNC_TIMING: std::cell::Cell<Option<SyncFailureTiming>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn sync_failure_timing() -> Option<SyncFailureTiming> {
    let current = SYNC_COUNT.with(|count| {
        let current = count.get();
        count.set(current + 1);
        current
    });
    let timing = FAIL_SYNC_AT.with(|fail| {
        fail.get()
            .and_then(|(at, timing)| (at == current).then_some(timing))
    });
    LAST_SYNC_TIMING.set(timing);
    timing
}

#[cfg(test)]
fn inject_sync_failure(at: Option<usize>) {
    FAIL_SYNC_AT.with(|fail| fail.set(at.map(|at| (at, SyncFailureTiming::Before))));
    SYNC_COUNT.with(|count| count.set(0));
    LAST_SYNC_TIMING.set(None);
}

#[cfg(test)]
fn inject_sync_failure_after(at: usize) {
    FAIL_SYNC_AT.with(|fail| fail.set(Some((at, SyncFailureTiming::After))));
    SYNC_COUNT.with(|count| count.set(0));
    LAST_SYNC_TIMING.set(None);
}

#[cfg(target_vendor = "apple")]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(test)]
mod tests;
