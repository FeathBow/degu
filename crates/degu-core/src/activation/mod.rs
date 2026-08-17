//! Durable, whole-store activation and discovery authority.
//!
//! The seal WAL cannot prove its own continued existence. Runtime selection
//! therefore authenticates two fixed current-account candidates: the optional
//! platform/EUID system anchor and the account-database-derived self-managed
//! anchor. Neither candidate is selected by ambient HOME, XDG, configuration,
//! cwd, or caller input. Unsafe or uncertain state blocks; an empty peer never
//! overrides existing activation evidence, and evidence in both roots is split
//! authority rather than a preference decision.
//!
//! Stable state retains matching `prepare` and `active` locator/identity records
//! plus a reciprocal marker in the exact store, so loss of `active` alone resumes
//! from `prepare`. A missing recorded store is lost authority, never permission
//! to create an empty one under a changed XDG. Mutation sessions retain every
//! existing candidate lock as well as the selected WAL lease.
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
use crate::seal_wal::{
    ExclusiveFileLock, RecoveryLockError, StagingTransactionMetadata, StrongObjectIdentity,
    TransactionId,
};
use crate::sealed_staging::{
    ReadyStagingEngine, SealedStagingEngine, StagingEngineError, StartupRecoveryAnchors,
    StartupRecoveryError, StartupRecoveryReport, StartupRecoverySummary,
};
use crate::staging_recovery::strong_identity_fd;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PREPARING_RECORD_NAME: &str = "sealed-staging.prepare";
pub const ACTIVE_RECORD_NAME: &str = "sealed-staging.active";
const AUTHORITY_RECORD_NAME: &str = "sealed-staging.authority";
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
const MAGIC_AUTHORITY: &[u8; 8] = b"DGUAUTH1";
const ACTIVATION_ID_LEN: usize = 32;
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_LOCATOR_BYTES: usize = 64 * 1024;
static NEXT_TEMP_NAME: AtomicU64 = AtomicU64::new(1);
#[cfg(all(feature = "integration-test-anchor", not(debug_assertions)))]
compile_error!("integration-test-anchor must never be enabled in a release build");
#[cfg(feature = "integration-test-anchor")]
const INTEGRATION_TEST_ANCHOR_ENV: &str = "DEGU_INTEGRATION_TEST_ANCHOR";

mod selection;
use selection::{
    ActivationAnchorLocator, AnchorKind, AuthorityCandidate, AuthoritySelection,
    ensure_authority_claim,
};
pub use selection::{
    ActivationAuthorityMode, CurrentEuidAuthorityReadiness, SelfAuthorityInitializationError,
    SelfAuthorityInitializationOutcome, activate_current_euid_store,
    check_current_euid_authority_readiness, initialize_current_euid_self_authority,
};
#[cfg(test)]
use selection::{
    AuthorityChoice, choose_authority, open_authority_candidate, require_current_self_path_with,
    select_authority_pair, selection_for_locator,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreActivationKind {
    NeverActivated,
    Preparing,
    Activated,
    Lost,
    CorruptOrReplaced,
}

/// Result of fixed-root discovery. Only `Activated` carries a store handle.
enum StoreActivationState {
    NeverActivated,
    Preparing,
    Activated(ActivatedSealWalStore),
    Lost,
    CorruptOrReplaced,
}

impl StoreActivationState {
    pub fn kind(&self) -> StoreActivationKind {
        match self {
            Self::NeverActivated => StoreActivationKind::NeverActivated,
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
    // Discovery may construct a read-only handle without retaining an anchor.
    // Every mutation entrypoint fills this lease before returning the handle.
    _authority: Option<Box<AuthorityLease>>,
}

impl ActivatedSealWalStore {
    pub fn locator(&self) -> &Path {
        &self.locator
    }

    /// Consume the activation handle into a WAL engine that cannot outlive the
    /// selected and peer authority locks.
    ///
    /// ```compile_fail,E0382
    /// fn cannot_detach(activated: degu_core::activation::ActivatedSealWalStore) {
    ///     let (_engine, _report) = activated.open_staging().unwrap();
    ///     drop(activated); // moved into the authority-bound engine
    /// }
    /// ```
    pub fn open_staging(
        self,
    ) -> Result<(ActivatedStagingEngine, StartupRecoveryReport), StagingEngineError> {
        let (engine, report) = SealedStagingEngine::open(&self.store)?;
        Ok((
            ActivatedStagingEngine {
                activation: self,
                engine,
            },
            report,
        ))
    }
}

pub struct ActivatedStagingEngine {
    activation: ActivatedSealWalStore,
    engine: SealedStagingEngine,
}

impl ActivatedStagingEngine {
    pub fn recover_startup<F>(
        self,
        report: StartupRecoveryReport,
        provide_anchors: F,
    ) -> Result<(ActivatedReadyStagingEngine, StartupRecoverySummary), StartupRecoveryError>
    where
        F: FnMut(TransactionId, &StagingTransactionMetadata) -> io::Result<StartupRecoveryAnchors>,
    {
        let (engine, summary) = self.engine.recover_startup(report, provide_anchors)?;
        Ok((
            ActivatedReadyStagingEngine {
                _activation: Some(self.activation),
                engine,
            },
            summary,
        ))
    }
}

/// Ready staging authority whose type owns both the WAL lease and every
/// selector lock. Deref exposes the existing engine operations without
/// allowing the authority lifetime to be detached.
pub struct ActivatedReadyStagingEngine {
    _activation: Option<ActivatedSealWalStore>,
    engine: ReadyStagingEngine,
}

impl ActivatedReadyStagingEngine {
    #[cfg(feature = "integration-test-anchor")]
    #[doc(hidden)]
    pub fn from_ready_for_integration_test(engine: ReadyStagingEngine) -> Self {
        Self {
            _activation: None,
            engine,
        }
    }
}

impl Deref for ActivatedReadyStagingEngine {
    type Target = ReadyStagingEngine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl DerefMut for ActivatedReadyStagingEngine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.engine
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreActivationError {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("current account activation-anchor base is unavailable: {0}")]
    AccountBase(#[from] crate::provision::AccountBaseError),
    #[error("current account activation-anchor path changed from {expected} to {actual}")]
    AccountBaseChanged { expected: PathBuf, actual: PathBuf },
    #[error("activation anchor is not provisioned at {path}")]
    AnchorNotProvisioned { path: PathBuf },
    #[error("activation anchor is unsafe: {0}")]
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
    #[error(
        "neither activation authority is provisioned (system: {system}; self-managed: {self_managed})"
    )]
    NoAuthority {
        system: PathBuf,
        self_managed: PathBuf,
    },
    #[error(
        "system and self-managed anchors both carry activation evidence (system: {system}; self-managed: {self_managed})"
    )]
    SplitAuthority {
        system: PathBuf,
        self_managed: PathBuf,
    },
    #[error("authority claim is invalid or conflicts with activation evidence at {path}")]
    AuthorityClaimInvalid { path: PathBuf },
    #[error(
        "authority selected by the durable witness is missing (selected: {selected}; witness: {witness})"
    )]
    SelectedAuthorityLost { selected: PathBuf, witness: PathBuf },
    #[error("self-managed activation requires an explicit initial declaration")]
    SelfInitializationRequired,
    #[error("self-managed initialization requires an explicit initial-use assertion")]
    InitialAssertionRequired,
    #[error("self-managed initialization is blocked by an existing system authority at {path}")]
    SystemAuthorityPresent { path: PathBuf },
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrepareRecord {
    activation_id: [u8; ACTIVATION_ID_LEN],
    authority_locator: PathBuf,
    authority_identity: StrongObjectIdentity,
    authority_backend: CertifiedLocalBackend,
    store_locator: PathBuf,
    store_identity: StrongObjectIdentity,
    store_backend: CertifiedLocalBackend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRecord {
    prepare: PrepareRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorityRecord {
    selection_id: [u8; ACTIVATION_ID_LEN],
    selected_locator: PathBuf,
    selected_identity: StrongObjectIdentity,
    selected_backend: CertifiedLocalBackend,
}

struct AuthorityLease {
    _selected: AuthorityRoot,
    _peer: Option<AuthorityRoot>,
}

struct AuthorityRoot {
    kind: AnchorKind,
    _provisioning_lock: Option<ExclusiveFileLock>,
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
#[cfg(test)]
fn discover_store_activation(
    anchor: &ActivationAnchorLocator,
    _desired_store: &Path,
) -> Result<StoreActivationState, StoreActivationError> {
    let authority = open_activation_anchor(anchor)?;
    discover_with_authority(&authority)
}

/// Production mutation result. Both variants retain the authority that makes
/// their decision stable for the full mutation session.
pub enum MutationStoreActivation {
    Activated(ActivatedSealWalStore),
    UnsupportedNeverActivated(UnsupportedNeverActivatedLease),
}

/// Opaque proof that every authenticated candidate is record-empty and the
/// desired backend is explicitly unsupported. Retaining it keeps both selector
/// locks held, so no competing authority can activate while the legacy
/// lifecycle is in progress.
pub struct UnsupportedNeverActivatedLease {
    _authorities: AuthorityLease,
}

#[cfg(test)]
fn activate_store_for_mutation(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
) -> Result<MutationStoreActivation, StoreActivationError> {
    activate_store_for_mutation_with_probe(anchor, desired_store, probe_desired_store_support)
}

#[cfg(test)]
fn activate_store_for_mutation_with_probe<F>(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
    support_probe: F,
) -> Result<MutationStoreActivation, StoreActivationError>
where
    F: FnOnce(&Path) -> Result<(), StoreActivationError>,
{
    activate_authority_selection_with_probe(
        selection_for_locator(anchor)?,
        desired_store,
        support_probe,
    )
}

fn activate_authority_selection_with_probe<F>(
    selection: AuthoritySelection,
    desired_store: &Path,
    support_probe: F,
) -> Result<MutationStoreActivation, StoreActivationError>
where
    F: FnOnce(&Path) -> Result<(), StoreActivationError>,
{
    let AuthoritySelection {
        mode,
        selected:
            AuthorityCandidate {
                authority,
                state,
                claim,
            },
        peer,
    } = selection;
    match state {
        StoreActivationState::Activated(mut store) => {
            ensure_authority_claim(&authority, peer.as_ref(), claim.as_ref())?;
            store._authority = Some(Box::new(AuthorityLease {
                _selected: authority,
                _peer: peer.map(|candidate| candidate.authority),
            }));
            Ok(MutationStoreActivation::Activated(store))
        }
        StoreActivationState::Lost | StoreActivationState::CorruptOrReplaced => {
            Err(StoreActivationError::NotResumable)
        }
        StoreActivationState::NeverActivated => {
            if mode == ActivationAuthorityMode::SelfManaged && claim.is_none() {
                return Err(StoreActivationError::SelfInitializationRequired);
            }
            match support_probe(desired_store) {
                Ok(()) => {
                    activate_or_resume_with_authorities(authority, peer, claim, desired_store, true)
                        .map(MutationStoreActivation::Activated)
                }
                Err(StoreActivationError::Backend(
                    CertificationError::UnsupportedPlatform
                    | CertificationError::UnsupportedFilesystem,
                )) => {
                    if claim.is_some() {
                        ensure_authority_claim(&authority, peer.as_ref(), claim.as_ref())?;
                    }
                    Ok(MutationStoreActivation::UnsupportedNeverActivated(
                        UnsupportedNeverActivatedLease {
                            _authorities: AuthorityLease {
                                _selected: authority,
                                _peer: peer.map(|candidate| candidate.authority),
                            },
                        },
                    ))
                }
                Err(error) => Err(error),
            }
        }
        StoreActivationState::Preparing => {
            activate_or_resume_with_authorities(authority, peer, claim, desired_store, false)
                .map(MutationStoreActivation::Activated)
        }
    }
}

/// Begin or resume crash-safe activation for test and internal single-anchor
/// callers. Production uses the selector-only [`activate_current_euid_store`].
#[cfg(test)]
fn activate_or_resume_store(
    anchor: &ActivationAnchorLocator,
    desired_store: &Path,
) -> Result<ActivatedSealWalStore, StoreActivationError> {
    let selection = selection_for_locator(anchor)?;
    let AuthoritySelection {
        selected:
            AuthorityCandidate {
                authority,
                state,
                claim,
            },
        peer,
        ..
    } = selection;
    match state {
        StoreActivationState::Activated(mut store) => {
            ensure_authority_claim(&authority, peer.as_ref(), claim.as_ref())?;
            store._authority = Some(Box::new(AuthorityLease {
                _selected: authority,
                _peer: peer.map(|candidate| candidate.authority),
            }));
            Ok(store)
        }
        StoreActivationState::Lost | StoreActivationState::CorruptOrReplaced => {
            Err(StoreActivationError::NotResumable)
        }
        StoreActivationState::NeverActivated | StoreActivationState::Preparing => {
            activate_or_resume_with_authorities(authority, peer, claim, desired_store, false)
        }
    }
}

fn activate_or_resume_with_authorities(
    authority: AuthorityRoot,
    peer: Option<AuthorityCandidate>,
    existing_claim: Option<AuthorityRecord>,
    desired_store: &Path,
    store_support_proven: bool,
) -> Result<ActivatedSealWalStore, StoreActivationError> {
    let claim = ensure_authority_claim(&authority, peer.as_ref(), existing_claim.as_ref())?;
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
            // Probe while holding every selector lock. Unsupported or uncertain
            // storage must not gain activation authority or create a store.
            if !store_support_proven {
                probe_desired_store_support(desired_store)?;
            }
            let store =
                SealWalStore::open_or_create(desired_store).map_err(StoreActivationError::Store)?;
            store
                .revalidate_binding()
                .map_err(StoreActivationError::Store)?;
            let record = PrepareRecord {
                activation_id: claim.selection_id,
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
        StoreActivationState::Activated(mut store) => {
            store._authority = Some(Box::new(AuthorityLease {
                _selected: authority,
                _peer: peer.map(|candidate| candidate.authority),
            }));
            Ok(store)
        }
        StoreActivationState::NeverActivated
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

fn preparing_store_binding_is_resumable(
    store: &SealWalStore,
    prepare: &PrepareRecord,
) -> Result<bool, StoreActivationError> {
    let expected = encode_active(&ActiveRecord {
        prepare: prepare.clone(),
    })?;
    match read_exact_record(
        store.directory_fd(),
        &prepare.store_locator,
        STORE_BINDING_NAME,
    ) {
        Ok(bytes) => Ok(bytes == expected),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(RecordReadError::Corrupt) => Ok(false),
        Err(RecordReadError::Io(path, source)) => Err(StoreActivationError::Io { path, source }),
        Err(error @ RecordReadError::Inspection(_, _)) => Err(store_error_from_record_read(error)),
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
    if !classify_store_binding(&store, prepare)?
        || !preparing_store_binding_is_resumable(&store, prepare)?
    {
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
        authority.kind,
    )?;
    sync_fd(store.directory_fd(), "activated store directory")?;
    sync_fd(&authority.directory, "activation anchor directory")?;
    Ok(StoreActivationState::Activated(ActivatedSealWalStore {
        locator: active.prepare.store_locator,
        store,
        _authority: None,
    }))
}

fn lock_activation_provisioning(
    locator: &ActivationAnchorLocator,
) -> Result<Option<ExclusiveFileLock>, StoreActivationError> {
    #[cfg(test)]
    if locator.kind == AnchorKind::Test {
        return Ok(None);
    }
    #[cfg(feature = "integration-test-anchor")]
    if locator.kind == AnchorKind::IntegrationTest {
        return Ok(None);
    }

    let store_parent = locator
        .path
        .parent()
        .ok_or(StoreActivationError::InvalidLocator)?;
    let product_root = store_parent
        .parent()
        .ok_or(StoreActivationError::InvalidLocator)?;
    let lock_path = product_root.join(crate::provision::PROVISIONING_LOCK_NAME);
    match std::fs::symlink_metadata(&lock_path) {
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreActivationError::Io {
                path: lock_path,
                source,
            });
        }
    }
    let (parent, name, opened_parent_path) =
        open_authenticated_parent(&lock_path).map_err(StoreActivationError::UnsafeAnchor)?;
    if opened_parent_path != product_root {
        return Err(StoreActivationError::InvalidLocator);
    }
    let directory = rustix::fs::openat(&parent, &name, OPEN_DIRECTORY, Mode::empty())
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let stat = rustix::fs::fstat(&directory)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let euid = rustix::process::geteuid().as_raw();
    let owner_matches = match locator.kind {
        AnchorKind::System => stat.st_uid == 0,
        AnchorKind::SelfManaged => stat.st_uid == euid,
        #[cfg(test)]
        AnchorKind::Test => true,
        #[cfg(feature = "integration-test-anchor")]
        AnchorKind::IntegrationTest => true,
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || raw_mode_u32(stat.st_mode) & 0o7777 != 0o700
        || !owner_matches
    {
        return Err(unsafe_anchor(
            &lock_path,
            "activation provisioning lock has the wrong type, owner, or mode",
        ));
    }
    require_held_fd_acl_absent(&directory).map_err(StoreActivationError::Backend)?;
    crate::local_backend::certify_held_fd_backend(&directory)
        .map_err(StoreActivationError::Backend)?;
    let entry = rustix::fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .map_err(|source| StoreActivationError::Io {
            path: lock_path.clone(),
            source,
        })?;
    if entry.st_dev != stat.st_dev
        || entry.st_ino != stat.st_ino
        || FileType::from_raw_mode(entry.st_mode) != FileType::Directory
    {
        return Err(unsafe_anchor(
            &lock_path,
            "activation provisioning lock is not its exact parent entry",
        ));
    }
    let lock = try_lock_directory(&directory).map_err(|source| StoreActivationError::Io {
        path: lock_path,
        source,
    })?;
    Ok(Some(lock))
}

fn open_activation_anchor(
    locator: &ActivationAnchorLocator,
) -> Result<AuthorityRoot, StoreActivationError> {
    // Provisioning publishes the leaf before its final account/binding/fsync
    // commit gate. Taking the flavor's separate provisioning lock first makes
    // that interval invisible to runtime selection and activation.
    let provisioning_lock = lock_activation_provisioning(locator)?;
    let authority_path = locator.as_path();
    validate_absolute_locator(authority_path)?;
    if provisioning_lock.is_none()
        && matches!(
            std::fs::symlink_metadata(authority_path),
            Err(source) if source.kind() == io::ErrorKind::NotFound
        )
    {
        return Err(StoreActivationError::AnchorNotProvisioned {
            path: authority_path.to_path_buf(),
        });
    }
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
    let lock_may_be_absent = {
        #[cfg(test)]
        {
            locator.kind == AnchorKind::Test
        }
        #[cfg(not(test))]
        {
            false
        }
    } || {
        #[cfg(feature = "integration-test-anchor")]
        {
            locator.kind == AnchorKind::IntegrationTest
        }
        #[cfg(not(feature = "integration-test-anchor"))]
        {
            false
        }
    };
    if provisioning_lock.is_none() && !lock_may_be_absent {
        return Err(unsafe_anchor(
            authority_path,
            "activation anchor appeared without its provisioning commit lock",
        ));
    }
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
        locator.kind,
    )?;
    // The anchor is provisioned out of process. Re-establish durability of both
    // its exact contents and its parent binding on every successful open/retry.
    sync_fd(&directory, "activation anchor directory after validation")?;
    sync_fd(&parent, "activation anchor parent after validation")?;

    Ok(AuthorityRoot {
        kind: locator.kind,
        _provisioning_lock: provisioning_lock,
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
    kind: AnchorKind,
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
    let euid = rustix::process::geteuid().as_raw();
    let owner_matches = match kind {
        AnchorKind::System => parent_stat.st_uid == 0,
        AnchorKind::SelfManaged => parent_stat.st_uid == euid,
        #[cfg(test)]
        AnchorKind::Test => parent_stat.st_uid == 0 || parent_stat.st_uid == euid,
        #[cfg(feature = "integration-test-anchor")]
        AnchorKind::IntegrationTest => parent_stat.st_uid == 0 || parent_stat.st_uid == euid,
    };
    if !owner_matches {
        return Err(unsafe_anchor(
            parent_path,
            "activation anchor parent owner does not match its authority mode",
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

fn read_optional_authority(
    authority: &AuthorityRoot,
) -> Result<Option<AuthorityRecord>, RecordReadError> {
    match read_exact_record(&authority.directory, &authority.path, AUTHORITY_RECORD_NAME) {
        Ok(bytes) => decode_authority(&bytes)
            .map(Some)
            .ok_or(RecordReadError::Corrupt),
        Err(RecordReadError::Io(_, source)) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
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

fn encode_authority(record: &AuthorityRecord) -> Result<Vec<u8>, StoreActivationError> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_AUTHORITY);
    out.extend_from_slice(&record.selection_id);
    put_path(&mut out, &record.selected_locator)?;
    put_identity(&mut out, record.selected_identity);
    out.push(encode_backend(record.selected_backend));
    Ok(out)
}

fn decode_authority(bytes: &[u8]) -> Option<AuthorityRecord> {
    let mut input = bytes;
    take_magic(&mut input, MAGIC_AUTHORITY)?;
    let selection_id = take_array::<ACTIVATION_ID_LEN>(&mut input)?;
    let selected_locator = take_path(&mut input)?;
    let selected_identity = take_identity(&mut input)?;
    let selected_backend = decode_backend(*take(&mut input, 1)?.first()?)?;
    input.is_empty().then_some(AuthorityRecord {
        selection_id,
        selected_locator,
        selected_identity,
        selected_backend,
    })
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
