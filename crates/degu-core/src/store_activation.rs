//! Durable, whole-store activation and discovery authority.
//!
//! The seal WAL cannot prove its own continued existence. This module places
//! activation records in one platform/EUID-derived, administrator-provisioned
//! system anchor outside HOME, XDG, configuration, and the relocatable state
//! store. Degu opens that anchor but never creates or replaces it. A missing or
//! unsafe anchor blocks rather than becoming first use or a legacy escape.
//!
//! Stable state retains matching `prepare` and `active` locator/identity records
//! plus a reciprocal marker in the exact store, so loss of `active` alone resumes
//! from `prepare`. A missing recorded store is lost authority, never permission
//! to create an empty one under a changed XDG.
//!
//! The trust boundary is the same as `seal_store`: root and malicious same-EUID
//! processes are out of scope. Foreign users are excluded by no-follow,
//! EUID-owned 0700 directories, EUID-owned 0600 single-link records, absent
//! ACLs, certified local backends, strong birth identity, and held-FD checks.

use crate::local_backend::{CertificationError, CertifiedLocalBackend, require_held_fd_acl_absent};
use crate::seal_store::{
    SealWalStore, StoreError, open_authenticated_parent,
    probe_store_parent_backend_for_activation_support, validate_directory,
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use crate::anchor_layout::SelfAnchorRootError;

pub const PREPARING_RECORD_NAME: &str = "sealed-staging.prepare";
pub const ACTIVE_RECORD_NAME: &str = "sealed-staging.active";
pub const STORE_BINDING_NAME: &str = "store.activation";

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
#[cfg(all(feature = "integration-test-anchor", not(debug_assertions)))]
compile_error!("integration-test-anchor must never be enabled in a release build");
#[cfg(feature = "integration-test-anchor")]
const INTEGRATION_TEST_ANCHOR_ENV: &str = "DEGU_INTEGRATION_TEST_ANCHOR";

/// The one activation anchor selected by platform and effective user.
///
/// There is deliberately no public arbitrary-path constructor: a locator read
/// from HOME, XDG, configuration, the environment, or a CLI flag could drift to
/// an empty directory and forget an earlier activation. Installers provision
/// [`Self::for_current_euid`] before degu is allowed to activate a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationAnchorLocator {
    path: PathBuf,
}

impl ActivationAnchorLocator {
    pub fn for_current_euid() -> Result<Self, StoreActivationError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let path = crate::anchor_layout::system_anchor_root()
                .join(rustix::process::geteuid().as_raw().to_string());
            Ok(Self { path })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(StoreActivationError::Backend(
                CertificationError::UnsupportedPlatform,
            ))
        }
    }

    /// Locator for the invoking account's own self-managed anchor, derived from
    /// account facts (getpwuid home plus the fixed XDG state suffix), never
    /// `$HOME`/`$XDG_STATE_HOME`, so ambient environment drift cannot select it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn for_current_euid_self() -> Result<Self, SelfAnchorRootError> {
        let path = crate::anchor_layout::self_anchor_root()?
            .join(rustix::process::geteuid().as_raw().to_string());
        Ok(Self { path })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// Read-only readiness evidence for the exact current-EUID activation anchor.
///
/// This carries no store, record, staging, or mutation capability. Constructing
/// it authenticates, locks, binding-checks, and syncs the same existing-only
/// anchor that activation will later use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationAnchorReadiness {
    backend: CertifiedLocalBackend,
}

impl ActivationAnchorReadiness {
    pub fn backend(self) -> CertifiedLocalBackend {
        self.backend
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActivationAnchorReadinessError {
    #[error("activation anchor is not provisioned at {path}")]
    Missing { path: PathBuf },
    #[error("activation anchor is unsafe at {path}: {source}")]
    Unsafe {
        path: PathBuf,
        #[source]
        source: StoreActivationError,
    },
    #[error("activation anchor is unsupported at {path}: {source}")]
    Unsupported {
        path: PathBuf,
        #[source]
        source: StoreActivationError,
    },
    #[error("activation anchor inspection is uncertain at {path}: {source}")]
    Uncertain {
        path: PathBuf,
        #[source]
        source: StoreActivationError,
    },
}

/// Validate that the fixed platform/EUID activation anchor is provisioned and
/// safe without creating an anchor, store, or activation record.
pub fn check_activation_anchor_readiness(
    locator: &ActivationAnchorLocator,
) -> Result<ActivationAnchorReadiness, ActivationAnchorReadinessError> {
    let authority = open_activation_anchor(locator)
        .map_err(|error| classify_readiness_error(locator.as_path(), error))?;
    Ok(ActivationAnchorReadiness {
        backend: authority.backend,
    })
}

fn classify_readiness_error(
    locator: &Path,
    error: StoreActivationError,
) -> ActivationAnchorReadinessError {
    let path = locator.to_path_buf();
    match &error {
        StoreActivationError::AnchorNotProvisioned { path } => {
            ActivationAnchorReadinessError::Missing { path: path.clone() }
        }
        StoreActivationError::UnsafeAnchor(StoreError::UnsafeDirectory { reason, .. })
            if *reason == crate::seal_store::DIRECTORY_UNSUPPORTED_BACKEND_REASON =>
        {
            ActivationAnchorReadinessError::Unsupported {
                path,
                source: error,
            }
        }
        StoreActivationError::UnsafeAnchor(
            StoreError::Io { .. }
            | StoreError::ParentBackend { .. }
            | StoreError::BackendInspection { .. }
            | StoreError::Lease(_),
        ) => ActivationAnchorReadinessError::Uncertain {
            path,
            source: error,
        },
        StoreActivationError::UnsafeAnchor(_) => ActivationAnchorReadinessError::Unsafe {
            path,
            source: error,
        },
        StoreActivationError::Backend(
            CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem,
        ) => ActivationAnchorReadinessError::Unsupported {
            path,
            source: error,
        },
        StoreActivationError::Backend(
            CertificationError::FilesystemMagicMismatch
            | CertificationError::NotDirectory
            | CertificationError::AclPresent,
        ) => ActivationAnchorReadinessError::Unsafe {
            path,
            source: error,
        },
        _ => ActivationAnchorReadinessError::Uncertain {
            path,
            source: error,
        },
    }
}

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
    /// The authenticated anchor is record-empty and the desired store backend
    /// is explicitly outside the certified platform/filesystem set. This state
    /// grants no activation or mutation authority.
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
    #[error("system activation anchor is not provisioned at {path}")]
    AnchorNotProvisioned { path: PathBuf },
    #[error("system activation anchor is unsafe: {0}")]
    UnsafeAnchor(#[source] StoreError),
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
    parent: OwnedFd,
    name: OsString,
    directory: OwnedFd,
    path: PathBuf,
    identity: StrongObjectIdentity,
    backend: CertifiedLocalBackend,
    _lock: ExclusiveFileLock,
}

/// Read the one stable, pre-provisioned activation anchor.
///
/// The desired store is inspected only when that authenticated anchor is
/// record-empty. Existing activation evidence always selects its recorded store
/// and every anchor/open/inspection uncertainty blocks.
pub fn discover_store_activation(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
) -> Result<StoreActivationState, StoreActivationError> {
    discover_store_activation_with_probe(anchor, desired_store, probe_desired_store_support)
}

/// Production mutation result. Both variants retain the authority that makes
/// their decision stable for the full mutation session.
pub enum MutationStoreActivation {
    Activated(ActivatedSealWalStore),
    UnsupportedNeverActivated(UnsupportedNeverActivatedLease),
}

/// Opaque proof that the authenticated anchor is record-empty and the desired
/// backend is explicitly unsupported. Retaining it keeps the anchor lock held,
/// so another process cannot activate a different XDG store while legacy
/// mutation is in progress.
pub struct UnsupportedNeverActivatedLease {
    _authority: AuthorityRoot,
}

/// Discover the fixed current-EUID whole-store authority and activate or resume
/// `desired_store` only when the authenticated record state permits it.
///
/// This is the production adapter boundary: callers can select the desired
/// relocatable store for genuine first use, but cannot supply or redirect the
/// external activation authority.
pub fn activate_current_euid_store(
    desired_store: &Path,
) -> Result<MutationStoreActivation, StoreActivationError> {
    let anchor = production_activation_anchor()?;
    activate_store_for_mutation(&anchor, desired_store)
}

fn production_activation_anchor() -> Result<ActivationAnchorLocator, StoreActivationError> {
    #[cfg(feature = "integration-test-anchor")]
    if let Some(path) = std::env::var_os(INTEGRATION_TEST_ANCHOR_ENV) {
        return Ok(ActivationAnchorLocator {
            path: PathBuf::from(path),
        });
    }
    ActivationAnchorLocator::for_current_euid()
}

fn activate_store_for_mutation(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
) -> Result<MutationStoreActivation, StoreActivationError> {
    activate_store_for_mutation_with_probe(anchor, desired_store, probe_desired_store_support)
}

fn activate_store_for_mutation_with_probe<F>(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
    support_probe: F,
) -> Result<MutationStoreActivation, StoreActivationError>
where
    F: FnOnce(&Path) -> Result<(), StoreActivationError>,
{
    let authority = open_activation_anchor(anchor)?;
    match discover_with_authority(&authority)? {
        StoreActivationState::Activated(store) => Ok(MutationStoreActivation::Activated(store)),
        StoreActivationState::Lost | StoreActivationState::CorruptOrReplaced => {
            Err(StoreActivationError::NotResumable)
        }
        StoreActivationState::NeverActivated => match support_probe(desired_store) {
            Ok(()) => {
                drop(authority);
                activate_or_resume_store(anchor, desired_store)
                    .map(MutationStoreActivation::Activated)
            }
            Err(StoreActivationError::Backend(
                CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem,
            )) => Ok(MutationStoreActivation::UnsupportedNeverActivated(
                UnsupportedNeverActivatedLease {
                    _authority: authority,
                },
            )),
            Err(error) => Err(error),
        },
        StoreActivationState::Preparing => {
            drop(authority);
            activate_or_resume_store(anchor, desired_store).map(MutationStoreActivation::Activated)
        }
        StoreActivationState::UnsupportedNeverActivated => {
            unreachable!("discover_with_authority never performs the desired-store support probe")
        }
    }
}

fn discover_store_activation_with_probe<F>(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
    support_probe: F,
) -> Result<StoreActivationState, StoreActivationError>
where
    F: FnOnce(&Path) -> Result<(), StoreActivationError>,
{
    let authority = open_activation_anchor(anchor)?;
    match discover_with_authority(&authority)? {
        StoreActivationState::NeverActivated => match support_probe(desired_store) {
            Ok(()) => Ok(StoreActivationState::NeverActivated),
            Err(StoreActivationError::Backend(
                CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem,
            )) => Ok(StoreActivationState::UnsupportedNeverActivated),
            Err(error) => Err(error),
        },
        state => Ok(state),
    }
}

/// Begin or resume crash-safe activation. `desired_store` is consulted only in
/// `NeverActivated`; a durable preparing record always wins over changed XDG.
pub fn activate_or_resume_store(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
) -> Result<ActivatedSealWalStore, StoreActivationError> {
    let authority = open_activation_anchor(anchor)?;
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
            // Probe while holding the anchor lock. Unsupported or uncertain
            // storage must not gain activation authority or create a store.
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
    probe_desired_store_support_with(
        desired_store,
        probe_store_parent_backend_for_activation_support,
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
    validate_activation_anchor_binding(
        &authority.parent,
        &authority.name,
        &authority.directory,
        &authority.path,
        authority.identity,
        authority.backend,
    )?;
    sync_fd(store.directory_fd(), "activated store directory")?;
    sync_fd(&authority.directory, "activation anchor directory")?;
    Ok(StoreActivationState::Activated(ActivatedSealWalStore {
        locator: active.prepare.store_locator,
        store,
    }))
}

fn open_activation_anchor(
    locator: &ActivationAnchorLocator,
) -> Result<AuthorityRoot, StoreActivationError> {
    let authority_path = locator.as_path();
    validate_absolute_locator(authority_path)?;
    let expected_parent = authority_path
        .parent()
        .ok_or(StoreActivationError::InvalidLocator)?;
    let (parent, name, opened_parent_path) = match open_authenticated_parent(authority_path) {
        Ok(opened) => opened,
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Err(StoreActivationError::AnchorNotProvisioned {
                path: authority_path.to_path_buf(),
            });
        }
        Err(error) => return Err(StoreActivationError::UnsafeAnchor(error)),
    };
    if opened_parent_path != expected_parent {
        return Err(StoreActivationError::InvalidLocator);
    }

    let directory = match rustix::fs::openat(&parent, &name, OPEN_DIRECTORY, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return Err(StoreActivationError::AnchorNotProvisioned {
                path: authority_path.to_path_buf(),
            });
        }
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
            return Err(unsafe_anchor(
                authority_path,
                "activation anchor is not a no-follow directory",
            ));
        }
        Err(error) => {
            return Err(StoreActivationError::Io {
                path: authority_path.to_path_buf(),
                source: error.into(),
            });
        }
    };
    validate_directory(&directory, authority_path).map_err(StoreActivationError::UnsafeAnchor)?;
    let identity = strong_identity_fd(&directory).map_err(|_| StoreActivationError::Identity)?;
    let backend = crate::local_backend::certify_held_fd_backend(&directory)
        .map_err(StoreActivationError::Backend)?;
    let lock = try_lock_directory(&directory).map_err(|source| StoreActivationError::Io {
        path: authority_path.to_path_buf(),
        source,
    })?;

    validate_activation_anchor_binding(
        &parent,
        &name,
        &directory,
        authority_path,
        identity,
        backend,
    )?;
    // The anchor is provisioned out of process. Re-establish durability of both
    // its exact contents and its parent binding on every successful open/retry.
    sync_fd(&directory, "activation anchor directory after validation")?;
    sync_fd(&parent, "activation anchor parent after validation")?;

    Ok(AuthorityRoot {
        parent,
        name,
        directory,
        path: authority_path.to_path_buf(),
        identity,
        backend,
        _lock: lock,
    })
}

fn validate_activation_anchor_binding(
    parent: &OwnedFd,
    name: &OsString,
    directory: &OwnedFd,
    path: &Path,
    expected_identity: StrongObjectIdentity,
    expected_backend: CertifiedLocalBackend,
) -> Result<(), StoreActivationError> {
    validate_directory(directory, path).map_err(StoreActivationError::UnsafeAnchor)?;
    let backend = crate::local_backend::certify_held_fd_backend(directory)
        .map_err(StoreActivationError::Backend)?;
    let identity = strong_identity_fd(directory).map_err(|_| StoreActivationError::Identity)?;
    if backend != expected_backend || identity != expected_identity {
        return Err(unsafe_anchor(
            path,
            "activation anchor backend or strong identity changed",
        ));
    }

    let parent_path = path.parent().unwrap_or_else(|| Path::new("/"));
    let parent_stat = rustix::fs::fstat(parent)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: parent_path.to_path_buf(),
            source,
        })?;
    let parent_mode = parent_stat.st_mode as u32;
    if parent_stat.st_uid != 0 && parent_stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(unsafe_anchor(
            parent_path,
            "activation anchor parent has a foreign non-root owner",
        ));
    }
    if parent_mode & 0o030 == 0o030 || parent_mode & 0o003 == 0o003 {
        return Err(unsafe_anchor(
            parent_path,
            "activation anchor parent grants foreign rename authority",
        ));
    }

    let entry = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let opened = rustix::fs::fstat(directory)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if entry.st_dev != opened.st_dev
        || entry.st_ino != opened.st_ino
        || FileType::from_raw_mode(entry.st_mode) != FileType::Directory
    {
        return Err(unsafe_anchor(
            path,
            "opened activation anchor is not its exact parent entry",
        ));
    }
    Ok(())
}

fn unsafe_anchor(path: &Path, reason: &'static str) -> StoreActivationError {
    StoreActivationError::UnsafeAnchor(StoreError::UnsafeDirectory {
        path: path.to_path_buf(),
        reason,
    })
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
