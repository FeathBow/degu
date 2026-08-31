//! Crash-recovery rebind and execution boundary for sealed staging.
//!
//! Durable paths and inode numbers are never promoted to authority. A recovery
//! capability owns freshly opened parent/object descriptors, re-certifies the
//! exact binding against backend, mount, filesystem-id, dev/inode and birth-time,
//! and rechecks that binding immediately before any held-FD mode restoration.

mod stream_v3;

use crate::authority::TransactionState;
use crate::backend::held::{HeldTreeError, HeldTreeInventory, HeldTreeLimits, HeldTreePurgeError};
use crate::backend::{
    CertificationError, CertifiedLocalBackend, HeldLocalBackendEvidence,
    LocalModeRevalidationFailure, certify_held_fd, certify_held_fd_backend,
};
use crate::seal::executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeTransform, RecoveryLocator,
    execute_staging_local_mode_mutation,
};
use crate::seal::sidecar::{TreeSidecarCommitment, TreeSidecarError, TreeSidecarStore};
use crate::seal::wal::{
    AppendError, ApplicationStatus, DurablePermission, DurableTreeManifest,
    DurableUndoRenameOutcome, PermissionResolution, RecoverySession, RecoveryWork, ResolveError,
    SealWal, StagingLocator, StagingTransactionMetadata, StrongObjectIdentity, TransactionId,
};
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
std::thread_local! {
    static RECOVERY_NAME_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BEFORE_PERMISSION_RESOLUTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static UNDO_FAIL_STEP: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
    pub(crate) static AFTER_UNDO_MODES_RESTORED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static BEFORE_UNDO_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static PURGE_FAIL_AFTER_CLAIM: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    pub(crate) static PURGE_FAIL_PROGRESS_AT: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    pub(crate) static PURGE_FAIL_AFTER_OUTCOME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static RECOVERY_FD_OBSERVER: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct RecoveryFdObserverGuard;

#[cfg(test)]
impl Drop for RecoveryFdObserverGuard {
    fn drop(&mut self) {
        RECOVERY_FD_OBSERVER.with(|observer| *observer.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn install_recovery_fd_observer(
    observer: impl FnMut() + 'static,
) -> RecoveryFdObserverGuard {
    RECOVERY_FD_OBSERVER.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "recovery FD observer already installed"
        );
        *slot.borrow_mut() = Some(Box::new(observer));
    });
    RecoveryFdObserverGuard
}

#[cfg(test)]
fn observe_recovery_fds() {
    RECOVERY_FD_OBSERVER.with(|observer| {
        if let Some(observer) = observer.borrow_mut().as_mut() {
            observer();
        }
    });
}

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Debug, thiserror::Error)]
pub(crate) enum RecoveryRebindError {
    #[error("recovery work and durable transaction metadata disagree")]
    TransactionMismatch,
    #[error("startup recovery candidate belongs to another engine generation")]
    CandidateFromAnotherEngine,
    #[error("rename outcome is unknown; no source or destination lookup is permitted")]
    RenameOutcomeUnknown,
    #[error("recovery locator is outside its authenticated anchor")]
    InvalidLocator,
    #[error("recovery locator anchor or intermediate controller admits foreign namespace writers")]
    LocatorControllerNotExclusive,
    #[error("recovery filesystem id does not match the durable transaction")]
    FilesystemChanged,
    #[error("recovery backend differs from the durable transaction")]
    BackendChanged,
    #[error("recovery mount differs from its authenticated anchor")]
    MountChanged,
    #[error("strong object incarnation is unavailable on this platform/filesystem")]
    StrongIdentityUnavailable,
    #[error("legacy WAL schema v{0} lacks durable mount identity; automatic recovery is forbidden")]
    LegacySchemaMissingMountIdentity(u16),
    #[error("transaction is already durably marked recovery-required")]
    RecordedRecoveryRequired,
    #[error("the exact recovery name now refers to another object")]
    BindingChanged,
    #[error("recovery target mode differs from the durable applied seal")]
    ModeChanged,
    #[error("fresh staged seal evidence changed: {0:?}")]
    SealChanged(LocalModeRevalidationFailure),
    #[error("held recovery object could not be certified: {0:?}")]
    Certification(CertificationError),
    #[error("recovery descriptor operation failed: {0}")]
    Io(#[source] io::Error),
    #[error("recovery WAL transition failed: {0}")]
    Wal(#[from] AppendError),
    #[error("uncertain staging permission could not be resolved: {0}")]
    Resolution(#[from] ResolveError),
    #[error("held recovery mutation failed: {0}")]
    Execution(#[from] LocalModeExecutionError),
    #[error("recovery tree sidecar failed authentication: {0}")]
    Sidecar(#[source] TreeSidecarError),
    #[error("published recovery tree sidecar does not match its durable manifest")]
    SidecarManifestChanged,
    #[error("committed tree no longer exactly matches its sealed content manifest")]
    UndoManifestChanged,
    #[error("verified undo destination is occupied")]
    UndoDestinationOccupied,
    #[error("verified undo rename outcome is unknown: {0}")]
    UndoRenameUnknown(#[source] io::Error),
    #[error("verified undo parent fsync failed: {0}")]
    UndoParentSync(#[source] io::Error),
    #[error("sealed purge does not support a tree containing multi-link regular-file groups")]
    PurgeUnsupportedInternalHardLinks,
    #[error("sealed purge does not support a tree containing ordinary regular-file xattrs")]
    PurgeUnsupportedRegularXattrs,
    #[error("object-bound purge execution failed: {0}")]
    PurgeExecution(#[source] HeldTreeError),
}

impl From<CertificationError> for RecoveryRebindError {
    fn from(error: CertificationError) -> Self {
        Self::Certification(error)
    }
}

/// A separately authenticated filesystem anchor. Its descriptor remains live
/// for the entire rebind and capability construction operation.
#[derive(Debug)]
pub(crate) struct RecoveryFilesystemAnchor {
    fd: OwnedFd,
    filesystem_id: String,
    backend: CertifiedLocalBackend,
    mount_key: u64,
}

impl RecoveryFilesystemAnchor {
    pub(crate) fn certify(fd: OwnedFd, filesystem_id: String) -> Result<Self, RecoveryRebindError> {
        if filesystem_id.is_empty() {
            return Err(RecoveryRebindError::FilesystemChanged);
        }
        let backend = certify_held_fd_backend(&fd)?;
        if held_filesystem_id(&fd)? != filesystem_id {
            return Err(RecoveryRebindError::FilesystemChanged);
        }
        let mount_key = held_mount_key(&fd)?;
        // Require strong evidence on the anchor too. This prevents a caller from
        // turning an unsupported platform into a path-only recovery anchor.
        let _ = strong_identity_fd(&fd)?;
        Ok(Self {
            fd,
            filesystem_id,
            backend,
            mount_key,
        })
    }

    /// Binds durable locator evidence to an already-held parent descriptor by
    /// reopening the locator beneath this exact authenticated anchor and
    /// requiring both descriptors to name the same strong object.
    fn duplicate_authority(&self) -> Result<Self, RecoveryRebindError> {
        Ok(Self {
            fd: rustix::io::dup(&self.fd)
                .map_err(io::Error::from)
                .map_err(RecoveryRebindError::Io)?,
            filesystem_id: self.filesystem_id.clone(),
            backend: self.backend,
            mount_key: self.mount_key,
        })
    }

    pub(crate) fn verify_locator_binding(
        &self,
        locator: &StagingLocator,
        held_parent: &OwnedFd,
        expected: StrongObjectIdentity,
    ) -> Result<(), RecoveryRebindError> {
        if locator.filesystem_id() != self.filesystem_id {
            return Err(RecoveryRebindError::FilesystemChanged);
        }
        let reopened = open_confined_directory_with_exclusive_ancestors(
            &self.fd,
            locator.relative_path(),
            self.mount_key,
        )?;
        validate_fd(self, &reopened, expected)?;
        validate_fd(self, held_parent, expected)
    }
}

#[derive(Debug)]
pub(crate) struct RecoveryAnchors {
    pub(crate) source: RecoveryFilesystemAnchor,
    pub(crate) destination: RecoveryFilesystemAnchor,
}

impl RecoveryAnchors {
    fn duplicate(&self) -> Result<Self, RecoveryRebindError> {
        Ok(Self {
            source: self.source.duplicate_authority()?,
            destination: self.destination.duplicate_authority()?,
        })
    }
}

/// Retained authority to re-open and compare a rebound object's complete
/// anchor-relative parent attachment immediately before proof or mutation.
#[derive(Debug)]
struct LocatorAttachment {
    anchor: RecoveryFilesystemAnchor,
    parent_locator: PathBuf,
    parent_identity: StrongObjectIdentity,
}

impl LocatorAttachment {
    fn bind(
        anchor: &RecoveryFilesystemAnchor,
        object_path: &Path,
        parent: &OwnedFd,
    ) -> Result<Self, RecoveryRebindError> {
        let parent_locator = object_path
            .parent()
            .ok_or(RecoveryRebindError::InvalidLocator)?
            .to_path_buf();
        Ok(Self {
            anchor: anchor.duplicate_authority()?,
            parent_locator,
            parent_identity: strong_identity_fd(parent)?,
        })
    }

    fn verify(&self, held_parent: &OwnedFd) -> Result<(), RecoveryRebindError> {
        let reopened = if self.parent_locator.as_os_str().is_empty() {
            rustix::io::dup(&self.anchor.fd)
                .map_err(io::Error::from)
                .map_err(RecoveryRebindError::Io)?
        } else {
            open_confined_directory_with_exclusive_ancestors(
                &self.anchor.fd,
                &self.parent_locator,
                self.anchor.mount_key,
            )?
        };
        require_exclusive_controller(&reopened)?;
        validate_fd(&self.anchor, &reopened, self.parent_identity)?;
        validate_fd(&self.anchor, held_parent, self.parent_identity)
    }
}

/// One exact, freshly rebound object. The parent, object, and complete locator
/// attachment are retained together; the value is neither Clone nor Copy and
/// is consumed by restoration.
#[derive(Debug)]
enum ReboundBinding {
    Named {
        attachment: Option<LocatorAttachment>,
        parent: OwnedFd,
        basename: OsString,
    },
    Anchor(RecoveryFilesystemAnchor),
}

#[derive(Debug)]
struct ReboundObject {
    binding: ReboundBinding,
    object_check_fd: OwnedFd,
    relative_path: PathBuf,
    identity: StrongObjectIdentity,
    held: HeldLocalBackendEvidence,
}

impl ReboundObject {
    fn verify_fresh_binding(&self) -> Result<(), RecoveryRebindError> {
        match &self.binding {
            ReboundBinding::Named {
                attachment,
                parent,
                basename,
            } => {
                if let Some(attachment) = attachment {
                    attachment.verify(parent)?;
                }
                require_exclusive_controller(parent)?;
                let current = open_directory_at(parent, basename)?;
                if strong_identity_fd(&current)? != self.identity {
                    return Err(RecoveryRebindError::BindingChanged);
                }
            }
            ReboundBinding::Anchor(anchor) => {
                require_exclusive_controller(&anchor.fd)?;
                validate_fd(anchor, &self.object_check_fd, self.identity)?;
            }
        }
        if strong_identity_fd(&self.object_check_fd)? != self.identity || !self.held.is_live() {
            return Err(RecoveryRebindError::BindingChanged);
        }
        Ok(())
    }

    fn verify_fresh_sealed_directory(&self, expected_mode: u32) -> Result<(), RecoveryRebindError> {
        self.verify_fresh_binding()?;
        self.held
            .verify_current_mode(expected_mode)
            .map_err(RecoveryRebindError::SealChanged)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryAnchorSide {
    Source,
    Destination,
}

#[derive(Debug)]
struct PlannedDirectoryEvidence {
    identity: StrongObjectIdentity,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    effective_uid: u32,
    effective_groups: BTreeSet<u32>,
}

/// Durable permission data plus a non-authoritative snapshot of every directory
/// crossed while reopening it. No descriptor is retained by an entry: authority
/// always comes from the separately retained recovery anchor at execution time.
#[derive(Debug)]
struct RecoveryPermissionPlan {
    permission: DurablePermission,
    side: RecoveryAnchorSide,
    relative_path: PathBuf,
    chain: Vec<PlannedDirectoryEvidence>,
}

impl RecoveryPermissionPlan {
    fn permission(&self) -> &DurablePermission {
        &self.permission
    }
}

#[derive(Debug)]
struct ReboundRestore {
    transaction: TransactionId,
    source_parent_last: PathBuf,
    anchors: RecoveryAnchors,
    metadata: StagingTransactionMetadata,
    entries: Vec<RecoveryPermissionPlan>,
    completion: TransactionState,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StagedVerificationError {
    #[error("staged verification capability is not at StagedUnverified")]
    InvalidState,
    #[error("verified staged state was not durable: {0}")]
    StagedSealedNotDurable(#[source] AppendError),
    #[error("staged verification failed ({failure}) and quarantine was not durable: {source}")]
    QuarantineNotDurable {
        failure: StagedVerificationFailure,
        #[source]
        source: AppendError,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StagedVerificationFailure {
    #[error("durable tree manifest is missing")]
    MissingManifest,
    #[error("staged held-tree inspection failed: {0}")]
    HeldTree(#[from] HeldTreeError),
    #[error("staged binding changed: {0}")]
    Rebind(#[from] RecoveryRebindError),
    #[error("durable tree-seal coverage is not exact")]
    SealCoverage,
    #[error("staged tree does not match its durable manifest")]
    ManifestMismatch,
}

/// One-use internal proof that exact held-tree verification completed. Its
/// fields are private to this module, so WAL callers cannot manufacture the
/// `StagedUnverified -> StagedSealed` authority from a transaction ID.
pub(crate) struct ExactStagedVerification {
    transaction: TransactionId,
}

impl ExactStagedVerification {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

/// One-use proof minted only after fresh held-descriptor verification of the
/// committed staged object, destination parent, locator, strong identities,
/// sealed modes/ACL policy, and complete content manifest.
pub(crate) struct ExactPurgeVerification {
    transaction: TransactionId,
    manifest: DurableTreeManifest,
}

impl ExactPurgeVerification {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub(crate) fn manifest(&self) -> DurableTreeManifest {
        self.manifest
    }

    #[cfg(test)]
    pub(crate) fn for_test(transaction: TransactionId, manifest: DurableTreeManifest) -> Self {
        Self {
            transaction,
            manifest,
        }
    }
}

/// One-use proofs confined to the ordered source-parent recovery path. Their
/// fields are private, so WAL code cannot advance these authority states from a
/// transaction ID alone.
pub(crate) struct ExactSourceParentRestoreIntent {
    transaction: TransactionId,
}

impl ExactSourceParentRestoreIntent {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

pub(crate) struct ExactSourceParentRestored {
    transaction: TransactionId,
}

impl ExactSourceParentRestored {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

pub(crate) struct ExactVerifiedCommit {
    transaction: TransactionId,
}

impl ExactVerifiedCommit {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

pub(crate) fn certify_verified_commit(
    wal: &SealWal<RecoverySession>,
    transaction: TransactionId,
) -> Result<ExactVerifiedCommit, RecoveryRebindError> {
    (wal.transaction_state(transaction) == Some(TransactionState::SourceParentRestored))
        .then_some(ExactVerifiedCommit { transaction })
        .ok_or(RecoveryRebindError::TransactionMismatch)
}

/// Nonforgeable proof that this exact leased transaction reached only
/// `StagedSealed`. It intentionally has no restore, commit, purge, or namespace
/// mutation operation.
pub(crate) struct VerifiedStagedTree<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
}

impl VerifiedStagedTree<'_> {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub(crate) fn wal_state(&self) -> Option<TransactionState> {
        self.wal.transaction_state(self.transaction)
    }

    pub(crate) fn startup_is_blocked(&self) -> bool {
        *self.startup_blocked
    }
}

pub(crate) enum StagedVerificationOutcome<'a> {
    StagedSealed(VerifiedStagedTree<'a>),
    Quarantined(StagedVerificationFailure),
}

/// Capability returned for post-rename verification. It keeps the exact staged
/// root, destination anchor, descriptor-free tree-seal plan, and WAL lease live,
/// but exposes no chmod, unlink, rename, or purge operation.
pub(crate) struct CertifiedStagedRecovery<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    destination_anchor: RecoveryFilesystemAnchor,
    metadata: StagingTransactionMetadata,
    root: ReboundObject,
    expected_manifest: Option<DurableTreeManifest>,
    sidecar_commitment: Option<TreeSidecarCommitment>,
    tree_seal_plan: Vec<RecoveryPermissionPlan>,
}

impl<'a> CertifiedStagedRecovery<'a> {
    pub(crate) fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub(crate) fn verify_fresh(&self) -> Result<(), RecoveryRebindError> {
        self.root.verify_fresh_binding()
    }

    /// Keeps the exact WAL lease observably tied to this capability's lifetime.
    pub(crate) fn wal_state(&self) -> Option<TransactionState> {
        self.wal.transaction_state(self.transaction)
    }

    pub(crate) fn verification_is_pending(&self) -> bool {
        *self.startup_blocked
    }

    /// Consumes the one-shot recovery capability. Verification is read-only; the
    /// only possible durable success is `StagedUnverified -> StagedSealed`.
    pub(crate) fn verify_or_quarantine(
        self,
    ) -> Result<StagedVerificationOutcome<'a>, StagedVerificationError> {
        self.verify_or_quarantine_with_limits(HeldTreeLimits::default())
    }

    fn verify_or_quarantine_with_limits(
        mut self,
        limits: HeldTreeLimits,
    ) -> Result<StagedVerificationOutcome<'a>, StagedVerificationError> {
        if self.wal.transaction_state(self.transaction) != Some(TransactionState::StagedUnverified)
        {
            return Err(StagedVerificationError::InvalidState);
        }
        let verification = self.verify_staged_tree(limits);
        if let Err(failure) = verification {
            return match self
                .wal
                .transition_staging_foundation(self.transaction, TransactionState::Quarantined)
            {
                Ok(()) => Ok(StagedVerificationOutcome::Quarantined(failure)),
                Err(source) => {
                    Err(StagedVerificationError::QuarantineNotDurable { failure, source })
                }
            };
        }
        self.wal
            .record_staged_sealed(ExactStagedVerification {
                transaction: self.transaction,
            })
            .map_err(StagedVerificationError::StagedSealedNotDurable)?;
        Ok(StagedVerificationOutcome::StagedSealed(
            VerifiedStagedTree {
                wal: self.wal,
                startup_blocked: self.startup_blocked,
                transaction: self.transaction,
            },
        ))
    }

    fn verify_staged_tree(
        &mut self,
        limits: HeldTreeLimits,
    ) -> Result<(), StagedVerificationFailure> {
        let expected = self
            .expected_manifest
            .ok_or(StagedVerificationFailure::MissingManifest)?;
        let v3_commitment = if expected.schema_version == 3 {
            let Some(commitment) = self.sidecar_commitment else {
                if let Err(error) = self.sidecars.cleanup_unpublished(self.wal) {
                    return Err(RecoveryRebindError::Sidecar(error).into());
                }
                return Err(StagedVerificationFailure::MissingManifest);
            };
            if let Err(error) = self.sidecars.verify(commitment) {
                // The authenticated published baseline retains precedence, but
                // an earlier unpublished recovery attempt must not leak runs.
                let _ = self.sidecars.cleanup_unpublished(self.wal);
                return Err(RecoveryRebindError::Sidecar(error).into());
            }
            Some(commitment)
        } else {
            None
        };
        self.root.verify_fresh_binding()?;
        for plan in &self.tree_seal_plan {
            let rebound = reopen_permission_plan(&self.destination_anchor, plan, &self.metadata)?;
            rebound.verify_fresh_sealed_directory(plan.permission.expected_mode)?;
        }
        if let Some(commitment) = v3_commitment {
            return stream_v3::verify_rebound_v3(
                self.wal,
                self.sidecars,
                stream_v3::ReboundV3Verification {
                    transaction: self.transaction,
                    commitment,
                    expected_manifest: expected,
                    root: &self.root,
                    metadata: &self.metadata,
                    plans: &self.tree_seal_plan,
                    modes_restored: false,
                    limits,
                },
            )
            .map(|_| ())
            .map_err(|error| match error {
                RecoveryRebindError::UndoManifestChanged => {
                    StagedVerificationFailure::ManifestMismatch
                }
                error => StagedVerificationFailure::Rebind(error),
            });
        }
        let inventory = collect_rebound_staged_tree(&self.root, limits, expected.schema_version)?;
        require_exact_tree_seal_coverage(
            &inventory,
            &self.root.relative_path,
            &self.tree_seal_plan,
        )?;
        inventory.rewalk_structure()?;
        self.root.verify_fresh_binding()?;
        for plan in &self.tree_seal_plan {
            let rebound = reopen_permission_plan(&self.destination_anchor, plan, &self.metadata)?;
            rebound.verify_fresh_sealed_directory(plan.permission.expected_mode)?;
        }
        let actual = inventory
            .fingerprint_for_schema(expected.schema_version)
            .ok_or(StagedVerificationFailure::ManifestMismatch)?;
        if actual.entry_count != expected.entry_count || actual.sha256 != expected.sha256 {
            return Err(StagedVerificationFailure::ManifestMismatch);
        }
        Ok(())
    }
}

fn collect_rebound_staged_tree(
    root: &ReboundObject,
    limits: HeldTreeLimits,
    manifest_schema: u16,
) -> Result<HeldTreeInventory, StagedVerificationFailure> {
    root.verify_fresh_binding()?;
    let ReboundBinding::Named {
        parent, basename, ..
    } = &root.binding
    else {
        return Err(RecoveryRebindError::InvalidLocator.into());
    };
    let parent = rustix::io::dup(parent)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let held_parent = certify_held_fd(parent).map_err(RecoveryRebindError::Certification)?;
    let protected_names = crate::safety::PROTECTED_DESCENDANT_DIR_NAMES
        .iter()
        .map(OsString::from)
        .collect();
    let inventory = HeldTreeInventory::collect_for_schema(
        held_parent,
        basename,
        protected_names,
        limits,
        manifest_schema,
    )?;
    root.verify_fresh_binding()?;
    Ok(inventory)
}

fn require_exact_tree_seal_coverage(
    inventory: &HeldTreeInventory,
    destination_root: &Path,
    seals: &[RecoveryPermissionPlan],
) -> Result<(), StagedVerificationFailure> {
    let mut held = BTreeMap::new();
    for directory in inventory.directories_deepest_first() {
        if held
            .insert(
                directory.relative_path,
                (
                    directory.device,
                    directory.inode,
                    directory.incarnation,
                    directory.observed_mode,
                ),
            )
            .is_some()
        {
            return Err(StagedVerificationFailure::SealCoverage);
        }
    }
    let mut durable = BTreeMap::new();
    for plan in seals {
        let permission = plan.permission();
        if permission.phase != TransactionState::TreeSealIntent
            || permission.application != ApplicationStatus::Applied
            || permission.reverses_mutation_id.is_some()
            || permission.expected_mode
                != plan
                    .chain
                    .last()
                    .ok_or(StagedVerificationFailure::SealCoverage)?
                    .mode
        {
            return Err(StagedVerificationFailure::SealCoverage);
        }
        let suffix = plan
            .relative_path
            .strip_prefix(destination_root)
            .map_err(|_| StagedVerificationFailure::SealCoverage)?
            .to_path_buf();
        if durable
            .insert(
                suffix,
                (
                    permission.evidence.device(),
                    permission.evidence.inode(),
                    permission
                        .evidence
                        .generation_or_btime()
                        .ok_or(StagedVerificationFailure::SealCoverage)?,
                    permission.expected_mode,
                ),
            )
            .is_some()
        {
            return Err(StagedVerificationFailure::SealCoverage);
        }
    }
    if held != durable {
        return Err(StagedVerificationFailure::SealCoverage);
    }
    Ok(())
}

pub(crate) enum StartupRecoveryCapability<'a> {
    Restore(Box<RecoveryRestoreSession<'a>>),
    /// Nonforgeable continuation requiring staged-tree verification. Merely
    /// checking liveness never clears the startup mutation block.
    PendingVerification(Box<CertifiedStagedRecovery<'a>>),
    /// Object-bound continuation for a previously admitted verified undo.
    VerifiedUndo(Box<VerifiedUndoRecoverySession<'a>>),
}

/// Owns only the recovery anchors and borrows the exact leased WAL until ordered
/// transient restore completes or the session is dropped.
pub(crate) struct RecoveryRestoreSession<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    restore: ReboundRestore,
}

impl RecoveryRestoreSession<'_> {
    pub(crate) fn execute(mut self) -> Result<(), RecoveryRebindError> {
        let transaction = self.restore.transaction;
        let current = self.wal.transaction_state(transaction);
        let intent = match self.restore.completion {
            TransactionState::Restored => TransactionState::RestoreIntent,
            TransactionState::SourceParentRestored => TransactionState::SourceParentRestoreIntent,
            TransactionState::Quarantined => TransactionState::Quarantined,
            _ => return Err(RecoveryRebindError::TransactionMismatch),
        };
        if current != Some(intent) {
            if intent == TransactionState::SourceParentRestoreIntent {
                self.wal
                    .record_source_parent_restore_intent(ExactSourceParentRestoreIntent {
                        transaction,
                    })?;
            } else {
                self.wal
                    .transition_staging_foundation(transaction, intent)?;
            }
        }

        // Sorting is repeated here rather than trusting serialized/report order.
        // The exact source parent is forced after every descendant and sibling.
        sort_restore_plans(&mut self.restore.entries, &self.restore.source_parent_last);

        for plan in self.restore.entries {
            let original = plan.permission.clone();
            let anchor = match plan.side {
                RecoveryAnchorSide::Source => &self.restore.anchors.source,
                RecoveryAnchorSide::Destination => &self.restore.anchors.destination,
            };
            let mut rebound = reopen_permission_plan(anchor, &plan, &self.restore.metadata)?;
            rebound.verify_fresh_binding()?;
            rebound
                .held
                .bind_recovered_seal_lineage(
                    transaction,
                    original.mutation_id,
                    original.pre_mode,
                    original.expected_mode,
                    self.restore.metadata.backend(),
                    original.evidence.device(),
                    original.evidence.inode(),
                )
                .map_err(LocalModeExecutionError::Preparation)?;
            let mutation_id = self.wal.next_recovery_mutation_id(transaction).ok_or(
                AppendError::InvalidState("recovery mutation id space exhausted"),
            )?;
            execute_staging_local_mode_mutation(
                self.wal,
                &mut rebound.held,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id,
                    locator: RecoveryLocator::durable_restore(
                        rebound.relative_path,
                        original.evidence.filesystem_id().map(str::to_owned),
                    ),
                    transform: LocalModeTransform::Restore { original },
                },
            )?;
        }
        if self.wal.transaction_state(transaction) != Some(self.restore.completion) {
            if self.restore.completion == TransactionState::SourceParentRestored {
                self.wal
                    .record_source_parent_restored(ExactSourceParentRestored { transaction })?;
            } else {
                self.wal
                    .transition_staging_foundation(transaction, self.restore.completion)?;
            }
        }
        *self.startup_blocked = !self.wal.can_begin_staging_transaction();
        Ok(())
    }
}

#[derive(Debug)]
struct ReboundVerifiedUndo {
    anchors: RecoveryAnchors,
    metadata: StagingTransactionMetadata,
    source_parent: OwnedFd,
    destination_parent: OwnedFd,
    root: ReboundObject,
    tree_seals: Vec<RecoveryPermissionPlan>,
    expected_manifest: DurableTreeManifest,
    sidecar_commitment: Option<TreeSidecarCommitment>,
}

/// One-shot continuation for committed-mode restoration and rename-back. Root
/// and parent descriptors remain retained; descendants are transiently reopened
/// from the authenticated anchor and durable data is never authority by itself.
pub(crate) struct VerifiedUndoRecoverySession<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    undo: ReboundVerifiedUndo,
}

/// Held, one-use object material retained by the public PurgeAuthority. It is
/// deliberately opaque outside the core crate and cannot be reconstructed from
/// durable projections.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct VerifiedPurgeAuthorityMaterial {
    committed: ReboundVerifiedUndo,
    inventory: HeldTreeInventory,
}

pub(crate) struct VerifiedPurgeSession<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    committed: ReboundVerifiedUndo,
}

impl VerifiedPurgeAuthorityMaterial {
    /// Executes the one-shot authority while the exact WAL lease, staged root,
    /// trash parent, directory set and content-proven inventory are all live.
    pub(crate) fn execute(
        self,
        wal: &mut SealWal<RecoverySession>,
        startup_blocked: &mut bool,
        transaction: TransactionId,
    ) -> Result<u64, RecoveryRebindError> {
        if wal.transaction_state(transaction) != Some(TransactionState::Purgeable)
            || self.committed.metadata.root_identity() != self.inventory.root_strong_identity()
        {
            return Err(RecoveryRebindError::TransactionMismatch);
        }
        // PurgeIntent is the last pre-mutation boundary. Any later error leaves
        // the engine blocked; restart records RecoveryRequired rather than
        // guessing from a potentially partial namespace.
        wal.record_purge_intent(transaction)?;
        *startup_blocked = true;
        #[cfg(test)]
        if PURGE_FAIL_AFTER_CLAIM.with(std::cell::Cell::get) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after durable purge claim",
            )));
        }
        let removed = self
            .inventory
            .purge_postorder(|removed, path| {
                #[cfg(test)]
                if PURGE_FAIL_PROGRESS_AT.with(|at| at.get() == Some(removed)) {
                    return Err(AppendError::InvalidState(
                        "injected crash before durable purge progress",
                    ));
                }
                wal.record_purge_progress(transaction, removed, path)
            })
            .map_err(|error| match error {
                HeldTreePurgeError::Tree(error) => RecoveryRebindError::PurgeExecution(error),
                HeldTreePurgeError::Journal(error) => RecoveryRebindError::Wal(error),
            })?;
        wal.record_purge_outcome(transaction)?;
        #[cfg(test)]
        if PURGE_FAIL_AFTER_OUTCOME.with(std::cell::Cell::get) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after durable purge outcome",
            )));
        }
        wal.record_purged(transaction)?;
        *startup_blocked = !wal.can_begin_staging_transaction();
        Ok(removed)
    }
}

impl VerifiedPurgeSession<'_> {
    pub(crate) fn authorize(self) -> Result<VerifiedPurgeAuthorityMaterial, RecoveryRebindError> {
        let transaction = self.transaction;
        let verifier = VerifiedUndoRecoverySession {
            wal: self.wal,
            sidecars: self.sidecars,
            startup_blocked: self.startup_blocked,
            transaction,
            undo: self.committed,
        };
        let verified = verifier
            .collect_exact_tree()
            .and_then(|inventory| verifier.verify_purge_layout().map(|()| inventory));
        let inventory = match verified {
            Ok(inventory) => inventory,
            Err(error) => {
                // A request which reached the exact committed association but found
                // replacement, inode reuse, ACL/mode/content drift, or mount/parent
                // namespace change can no longer be treated as a healthy terminal.
                verifier.wal.transition_recovery_required(transaction)?;
                *verifier.startup_blocked = true;
                return Err(error);
            }
        };
        // This admission gate deliberately precedes PurgeAuthorized/Purgeable,
        // PurgeIntent, every progress frame, and every unlink. Internal hardlink
        // topology is supported for staging and undo, but partial unlinking would
        // destroy the complete alias set and is therefore not authorized.
        if inventory
            .regular_hard_link_topology()
            .contains_multi_link_group()
        {
            *verifier.startup_blocked = !verifier.wal.can_begin_staging_transaction();
            return Err(RecoveryRebindError::PurgeUnsupportedInternalHardLinks);
        }
        if inventory.regular_xattr_topology().contains_xattrs() {
            *verifier.startup_blocked = !verifier.wal.can_begin_staging_transaction();
            return Err(RecoveryRebindError::PurgeUnsupportedRegularXattrs);
        }
        let manifest = verifier.undo.expected_manifest;
        if verifier.wal.transaction_state(transaction) == Some(TransactionState::VerifiedCommitted)
        {
            verifier.wal.record_purgeable(ExactPurgeVerification {
                transaction,
                manifest,
            })?;
        }
        *verifier.startup_blocked = !verifier.wal.can_begin_staging_transaction();
        Ok(VerifiedPurgeAuthorityMaterial {
            committed: verifier.undo,
            inventory,
        })
    }
}

impl VerifiedUndoRecoverySession<'_> {
    pub(crate) fn execute(mut self) -> Result<TransactionState, RecoveryRebindError> {
        let transaction = self.transaction;
        let state = self
            .wal
            .transaction_state(transaction)
            .ok_or(RecoveryRebindError::TransactionMismatch)?;
        if state == TransactionState::VerifiedCommitted {
            self.verify_exact_tree_or_block_unusable_v3_baseline()?;
            self.verify_parents_and_layout(true)?;
            self.wal.record_verified_undo_intent(transaction)?;
            #[cfg(test)]
            if UNDO_FAIL_STEP.with(|step| step.get() == Some("intent")) {
                return Err(RecoveryRebindError::Io(io::Error::other(
                    "injected crash after UndoIntent",
                )));
            }
        } else if !matches!(
            state,
            TransactionState::UndoIntent | TransactionState::UndoModesRestored
        ) {
            return Err(RecoveryRebindError::TransactionMismatch);
        }

        if self.wal.transaction_state(transaction) == Some(TransactionState::UndoIntent) {
            // Durable evidence order is ignored; descriptor-free plans are
            // independently sorted deepest-first before any inverse fchmod.
            self.undo.tree_seals.sort_by(|left, right| {
                let left = left.permission();
                let right = right.permission();
                right
                    .evidence
                    .relative_path()
                    .components()
                    .count()
                    .cmp(&left.evidence.relative_path().components().count())
                    .then_with(|| left.mutation_id.cmp(&right.mutation_id))
            });
            for plan in &self.undo.tree_seals {
                let original = plan.permission.clone();
                let snapshot = self
                    .wal
                    .recovery_snapshot(transaction)
                    .ok_or(RecoveryRebindError::TransactionMismatch)?;
                let restored = snapshot.permissions.iter().any(|permission| {
                    permission.application == ApplicationStatus::Applied
                        && permission.phase == TransactionState::UndoIntent
                        && permission.reverses_mutation_id == Some(original.mutation_id)
                });
                if restored {
                    continue;
                }
                let mut rebound = reopen_permission_plan(
                    &self.undo.anchors.destination,
                    plan,
                    &self.undo.metadata,
                )?;
                rebound.verify_fresh_sealed_directory(original.expected_mode)?;
                rebound
                    .held
                    .bind_recovered_seal_lineage(
                        transaction,
                        original.mutation_id,
                        original.pre_mode,
                        original.expected_mode,
                        self.undo.metadata.backend(),
                        original.evidence.device(),
                        original.evidence.inode(),
                    )
                    .map_err(LocalModeExecutionError::Preparation)?;
                let mutation_id = self.wal.next_recovery_mutation_id(transaction).ok_or(
                    AppendError::InvalidState("undo mutation id space exhausted"),
                )?;
                execute_staging_local_mode_mutation(
                    self.wal,
                    &mut rebound.held,
                    LocalModeMutationRequest {
                        transaction,
                        mutation_id,
                        locator: RecoveryLocator::durable_restore(
                            rebound.relative_path.clone(),
                            original.evidence.filesystem_id().map(str::to_owned),
                        ),
                        transform: LocalModeTransform::Restore { original },
                    },
                )?;
            }
            let restored_modes = self
                .undo
                .tree_seals
                .iter()
                .map(|plan| {
                    let target = plan
                        .chain
                        .last()
                        .ok_or(RecoveryRebindError::InvalidLocator)?;
                    Ok((target.identity, plan.permission.pre_mode))
                })
                .collect::<Result<Vec<_>, RecoveryRebindError>>()?;
            for plan in &mut self.undo.tree_seals {
                for evidence in &mut plan.chain {
                    if let Some((_, mode)) = restored_modes
                        .iter()
                        .find(|(identity, _)| *identity == evidence.identity)
                    {
                        evidence.mode = *mode;
                    }
                }
            }
            self.wal.record_undo_modes_restored(transaction)?;
            #[cfg(test)]
            AFTER_UNDO_MODES_RESTORED.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            #[cfg(test)]
            if UNDO_FAIL_STEP.with(|step| step.get() == Some("modes")) {
                return Err(RecoveryRebindError::Io(io::Error::other(
                    "injected crash after UndoModesRestored",
                )));
            }
        }

        self.verify_exact_tree_or_block_unusable_v3_baseline()?;
        self.verify_parents_and_layout(true)?;
        self.wal.record_undo_rename_intent(transaction)?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("rename-intent")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after UndoRenameIntent",
            )));
        }
        #[cfg(test)]
        BEFORE_UNDO_RENAME.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });

        match rustix::fs::renameat_with(
            &self.undo.destination_parent,
            self.undo.metadata.destination_basename(),
            &self.undo.source_parent,
            self.undo.metadata.source_basename(),
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {
                self.verify_parents_and_layout(false)?;
                self.wal.record_undo_rename_outcome(
                    transaction,
                    DurableUndoRenameOutcome::ConfirmedCollisionAtStaged(
                        self.undo.metadata.root_identity(),
                    ),
                )?;
                self.wal
                    .record_undo_terminal(transaction, TransactionState::UndoConflict)?;
                *self.startup_blocked = !self.wal.can_begin_staging_transaction();
                return Ok(TransactionState::UndoConflict);
            }
            Err(error) => {
                let error = io::Error::from(error);
                let _ = self.wal.transition_recovery_required(transaction);
                return Err(RecoveryRebindError::UndoRenameUnknown(error));
            }
        }

        self.verify_applied_layout()?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("rename")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after undo rename syscall",
            )));
        }
        rustix::fs::fsync(&self.undo.destination_parent)
            .map_err(io::Error::from)
            .map_err(RecoveryRebindError::UndoParentSync)?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("destination-fsync")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after undo destination-parent fsync",
            )));
        }
        rustix::fs::fsync(&self.undo.source_parent)
            .map_err(io::Error::from)
            .map_err(RecoveryRebindError::UndoParentSync)?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("source-fsync")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after undo source-parent fsync",
            )));
        }
        self.verify_applied_layout()?;
        self.wal.record_undo_rename_outcome(
            transaction,
            DurableUndoRenameOutcome::AppliedAndParentsSynced(self.undo.metadata.root_identity()),
        )?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("outcome")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after durable undo rename outcome",
            )));
        }
        self.wal
            .record_undo_terminal(transaction, TransactionState::Restored)?;
        #[cfg(test)]
        if UNDO_FAIL_STEP.with(|step| step.get() == Some("terminal")) {
            return Err(RecoveryRebindError::Io(io::Error::other(
                "injected crash after durable undo terminal",
            )));
        }
        *self.startup_blocked = !self.wal.can_begin_staging_transaction();
        Ok(TransactionState::Restored)
    }

    fn verify_exact_tree_or_block_unusable_v3_baseline(
        &mut self,
    ) -> Result<(), RecoveryRebindError> {
        match self.verify_exact_tree() {
            Ok(()) => Ok(()),
            Err(error) => {
                let missing_v3_sidecar = self.undo.expected_manifest.schema_version == 3
                    && self.undo.sidecar_commitment.is_none();
                // A missing or unauthentic published v3 baseline is not live-tree
                // drift and cannot remain retryable at either proof boundary.
                if missing_v3_sidecar
                    || matches!(
                        error,
                        RecoveryRebindError::Sidecar(_)
                            | RecoveryRebindError::SidecarManifestChanged
                    )
                {
                    self.wal.transition_recovery_required(self.transaction)?;
                    *self.startup_blocked = true;
                }
                Err(error)
            }
        }
    }

    fn verify_exact_tree(&mut self) -> Result<(), RecoveryRebindError> {
        if self.undo.expected_manifest.schema_version == 3 {
            let commitment = self
                .undo
                .sidecar_commitment
                .ok_or(RecoveryRebindError::UndoManifestChanged)?;
            let modes_restored = self.wal.transaction_state(self.transaction)
                == Some(TransactionState::UndoModesRestored);
            stream_v3::verify_rebound_v3(
                self.wal,
                self.sidecars,
                stream_v3::ReboundV3Verification {
                    transaction: self.transaction,
                    commitment,
                    expected_manifest: self.undo.expected_manifest,
                    root: &self.undo.root,
                    metadata: &self.undo.metadata,
                    plans: &self.undo.tree_seals,
                    modes_restored,
                    limits: HeldTreeLimits::default(),
                },
            )?;
            return Ok(());
        }
        self.collect_exact_tree().map(|_| ())
    }

    fn collect_exact_tree(&self) -> Result<HeldTreeInventory, RecoveryRebindError> {
        self.undo.root.verify_fresh_binding()?;
        let modes_restored = self.wal.transaction_state(self.transaction)
            == Some(TransactionState::UndoModesRestored);
        if !modes_restored {
            for plan in &self.undo.tree_seals {
                let rebound = reopen_permission_plan(
                    &self.undo.anchors.destination,
                    plan,
                    &self.undo.metadata,
                )?;
                rebound
                    .held
                    .verify_current_mode(
                        plan.chain
                            .last()
                            .ok_or(RecoveryRebindError::InvalidLocator)?
                            .mode,
                    )
                    .map_err(RecoveryRebindError::SealChanged)?;
            }
        }
        let inventory = collect_rebound_staged_tree(
            &self.undo.root,
            HeldTreeLimits::default(),
            self.undo.expected_manifest.schema_version,
        )
        .map_err(|_| RecoveryRebindError::UndoManifestChanged)?;
        let source_root = self
            .undo
            .metadata
            .source_parent()
            .relative_path()
            .join(self.undo.metadata.source_basename());
        let mut expected_modes = BTreeMap::new();
        let mut expected_identities = BTreeMap::new();
        for plan in &self.undo.tree_seals {
            let permission = plan.permission();
            let suffix = permission
                .evidence
                .relative_path()
                .strip_prefix(&source_root)
                .map_err(|_| RecoveryRebindError::InvalidLocator)?
                .to_path_buf();
            expected_modes.insert(suffix.clone(), permission.expected_mode);
            expected_identities.insert(
                suffix,
                (
                    permission.evidence.device(),
                    permission.evidence.inode(),
                    permission
                        .evidence
                        .generation_or_btime()
                        .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
                ),
            );
        }
        let actual_identities = inventory
            .directories_deepest_first()
            .map(|directory| {
                (
                    directory.relative_path,
                    (directory.device, directory.inode, directory.incarnation),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if expected_identities != actual_identities {
            return Err(RecoveryRebindError::UndoManifestChanged);
        }
        inventory
            .rewalk_structure()
            .map_err(|_| RecoveryRebindError::UndoManifestChanged)?;
        let normalized = inventory
            .fingerprint_with_directory_modes(&expected_modes)
            .map_err(|_| RecoveryRebindError::UndoManifestChanged)?;
        if normalized.entry_count != self.undo.expected_manifest.entry_count
            || normalized.sha256 != self.undo.expected_manifest.sha256
        {
            return Err(RecoveryRebindError::UndoManifestChanged);
        }
        self.undo.root.verify_fresh_binding()?;
        Ok(inventory)
    }

    fn verify_purge_layout(&self) -> Result<(), RecoveryRebindError> {
        self.undo.anchors.destination.verify_locator_binding(
            self.undo.metadata.destination_parent(),
            &self.undo.destination_parent,
            self.undo.metadata.destination_parent_identity(),
        )?;
        certify_held_fd(
            rustix::io::dup(&self.undo.destination_parent)
                .map_err(io::Error::from)
                .map_err(RecoveryRebindError::Io)?,
        )?
        .verify_namespace_exclusive()
        .map_err(RecoveryRebindError::SealChanged)?;
        self.undo.root.verify_fresh_binding()
    }

    fn verify_parents_and_layout(&self, require_absent: bool) -> Result<(), RecoveryRebindError> {
        self.undo.anchors.source.verify_locator_binding(
            self.undo.metadata.source_parent(),
            &self.undo.source_parent,
            self.undo.metadata.source_parent_identity(),
        )?;
        self.undo.anchors.destination.verify_locator_binding(
            self.undo.metadata.destination_parent(),
            &self.undo.destination_parent,
            self.undo.metadata.destination_parent_identity(),
        )?;
        certify_held_fd(
            rustix::io::dup(&self.undo.source_parent)
                .map_err(io::Error::from)
                .map_err(RecoveryRebindError::Io)?,
        )?
        .verify_namespace_exclusive()
        .map_err(RecoveryRebindError::SealChanged)?;
        certify_held_fd(
            rustix::io::dup(&self.undo.destination_parent)
                .map_err(io::Error::from)
                .map_err(RecoveryRebindError::Io)?,
        )?
        .verify_namespace_exclusive()
        .map_err(RecoveryRebindError::SealChanged)?;
        self.undo.root.verify_fresh_binding()?;
        match rustix::fs::statat(
            &self.undo.source_parent,
            self.undo.metadata.source_basename(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error) if error == rustix::io::Errno::NOENT && require_absent => Ok(()),
            Ok(_) if !require_absent => Ok(()),
            Err(error) => Err(RecoveryRebindError::Io(io::Error::from(error))),
            Ok(_) => Err(RecoveryRebindError::UndoDestinationOccupied),
        }
    }

    fn verify_applied_layout(&self) -> Result<(), RecoveryRebindError> {
        self.undo.anchors.source.verify_locator_binding(
            self.undo.metadata.source_parent(),
            &self.undo.source_parent,
            self.undo.metadata.source_parent_identity(),
        )?;
        self.undo.anchors.destination.verify_locator_binding(
            self.undo.metadata.destination_parent(),
            &self.undo.destination_parent,
            self.undo.metadata.destination_parent_identity(),
        )?;
        let restored = open_directory_at(
            &self.undo.source_parent,
            self.undo.metadata.source_basename(),
        )?;
        if strong_identity_fd(&restored)? != self.undo.metadata.root_identity()
            || strong_identity_fd(&self.undo.root.object_check_fd)?
                != self.undo.metadata.root_identity()
        {
            return Err(RecoveryRebindError::BindingChanged);
        }
        match rustix::fs::statat(
            &self.undo.destination_parent,
            self.undo.metadata.destination_basename(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(RecoveryRebindError::Io(io::Error::from(error))),
            Ok(_) => Err(RecoveryRebindError::BindingChanged),
        }
    }
}

fn sort_restore_plans(entries: &mut [RecoveryPermissionPlan], source_parent: &Path) {
    entries.sort_by(|left, right| {
        compare_restore_permissions(left.permission(), right.permission(), source_parent)
    });
}

fn sort_restore_entries<T>(entries: &mut [(DurablePermission, T)], source_parent: &Path) {
    entries
        .sort_by(|(left, _), (right, _)| compare_restore_permissions(left, right, source_parent));
}

fn compare_restore_permissions(
    left: &DurablePermission,
    right: &DurablePermission,
    source_parent: &Path,
) -> std::cmp::Ordering {
    let left_is_parent = left.evidence.relative_path() == source_parent;
    let right_is_parent = right.evidence.relative_path() == source_parent;
    left_is_parent.cmp(&right_is_parent).then_with(|| {
        right
            .evidence
            .relative_path()
            .components()
            .count()
            .cmp(&left.evidence.relative_path().components().count())
            .then_with(|| left.mutation_id.cmp(&right.mutation_id))
    })
}

/// Rebind startup work under fresh authenticated anchors. On any inability to
/// establish strong authority, no path is mutated and the transaction is moved
/// to durable `RecoveryRequired` when that transition can be recorded.
pub(crate) fn prepare_startup_recovery<'a>(
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    anchors: RecoveryAnchors,
) -> Result<StartupRecoveryCapability<'a>, RecoveryRebindError> {
    // Recompute from the exact leased WAL after every durable uncertainty
    // resolution. No caller can supply/omit a permission or choose a rename side.
    let (metadata, tree_manifest, sidecar_commitment, work) = loop {
        let snapshot = wal
            .recovery_snapshot(transaction)
            .ok_or(RecoveryRebindError::TransactionMismatch)?;
        let work = crate::seal::wal::decide_recovery(&snapshot, |_| {
            crate::seal::wal::RecoveryIdentity::Reestablished
        });
        // Preserve the typed RenameIntent+missing-outcome ambiguity. Repeated
        // attempts must never turn it into a generic state that permits lookup.
        if recovery_lookup_is_forbidden(&work) {
            return fail_closed(wal, transaction, RecoveryRebindError::RenameOutcomeUnknown);
        }
        if let RecoveryWork::RecoveryRequired { reason, .. } = &work {
            return match reason {
                crate::seal::wal::RecoveryRequiredReason::LegacySchemaMissingMountIdentity {
                    version,
                } => fail_closed(
                    wal,
                    transaction,
                    RecoveryRebindError::LegacySchemaMissingMountIdentity(*version),
                ),
                crate::seal::wal::RecoveryRequiredReason::RecordedRecoveryRequired => {
                    Err(RecoveryRebindError::RecordedRecoveryRequired)
                }
                crate::seal::wal::RecoveryRequiredReason::InsufficientPersistentIdentity => {
                    fail_closed(
                        wal,
                        transaction,
                        RecoveryRebindError::StrongIdentityUnavailable,
                    )
                }
                crate::seal::wal::RecoveryRequiredReason::RenameOutcomeUnknown => {
                    unreachable!("rename ambiguity handled before recovery-required dispatch")
                }
                crate::seal::wal::RecoveryRequiredReason::InterruptedPurge => fail_closed(
                    wal,
                    transaction,
                    RecoveryRebindError::RecordedRecoveryRequired,
                ),
            };
        }
        let metadata = snapshot
            .staging
            .ok_or(RecoveryRebindError::TransactionMismatch)?;
        if let RecoveryWork::ResolveUncertainPermissions { permissions, .. } = work {
            if let Err(error) =
                resolve_uncertain_permissions(wal, transaction, &metadata, &anchors, permissions)
            {
                return fail_closed(wal, transaction, error);
            }
            continue;
        }
        break (
            metadata,
            snapshot.tree_manifest,
            snapshot.tree_sidecar,
            work,
        );
    };

    if matches!(
        &work,
        RecoveryWork::RestoreBeforeRename { permissions, .. } if permissions.is_empty()
    ) && matches!(
        wal.transaction_state(transaction),
        Some(TransactionState::Prepared | TransactionState::ParentSealIntent)
    ) {
        return Ok(StartupRecoveryCapability::Restore(Box::new(
            RecoveryRestoreSession {
                wal,
                startup_blocked,
                restore: ReboundRestore {
                    transaction,
                    source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                    anchors,
                    metadata,
                    entries: Vec::new(),
                    completion: TransactionState::Restored,
                },
            },
        )));
    }

    match rebind_work(&metadata, tree_manifest, sidecar_commitment, work, &anchors) {
        Ok(ReboundWork::Restore(restore)) => Ok(StartupRecoveryCapability::Restore(Box::new(
            RecoveryRestoreSession {
                wal,
                startup_blocked,
                restore: *restore,
            },
        ))),
        Ok(ReboundWork::VerifyStaged(staged)) => {
            staged.root.verify_fresh_binding()?;
            // A crash after the durable applied+parents-synced outcome but
            // before the state append leaves RenameIntent as the durable state.
            // The exact outcome and fresh destination rebind jointly authorize
            // only this normalization; verification remains mandatory.
            if wal.transaction_state(transaction) == Some(TransactionState::RenameIntent) {
                wal.transition_staging_foundation(transaction, TransactionState::StagedUnverified)?;
            }
            if wal.transaction_state(transaction) != Some(TransactionState::StagedUnverified) {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            Ok(StartupRecoveryCapability::PendingVerification(Box::new(
                CertifiedStagedRecovery {
                    wal,
                    sidecars,
                    startup_blocked,
                    transaction,
                    destination_anchor: staged.destination_anchor,
                    metadata: staged.metadata,
                    root: staged.root,
                    expected_manifest: staged.expected_manifest,
                    sidecar_commitment: staged.sidecar_commitment,
                    tree_seal_plan: staged.tree_seals,
                },
            )))
        }
        Ok(ReboundWork::VerifiedUndo(undo)) => Ok(StartupRecoveryCapability::VerifiedUndo(
            Box::new(VerifiedUndoRecoverySession {
                wal,
                sidecars,
                startup_blocked,
                transaction,
                undo: *undo,
            }),
        )),
        Err(error) => fail_closed(wal, transaction, error),
    }
}

pub(crate) fn prepare_verified_undo<'a>(
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    anchors: RecoveryAnchors,
) -> Result<VerifiedUndoRecoverySession<'a>, RecoveryRebindError> {
    let snapshot = wal
        .recovery_snapshot(transaction)
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    if snapshot.state != TransactionState::VerifiedCommitted {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let metadata = snapshot
        .staging
        .clone()
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    let work = RecoveryWork::ResumeVerifiedUndo {
        transaction,
        permissions: snapshot.permissions,
    };
    match rebind_work(
        &metadata,
        snapshot.tree_manifest,
        snapshot.tree_sidecar,
        work,
        &anchors,
    ) {
        Ok(ReboundWork::VerifiedUndo(undo)) => Ok(VerifiedUndoRecoverySession {
            wal,
            sidecars,
            startup_blocked,
            transaction,
            undo: *undo,
        }),
        Ok(ReboundWork::Restore(_) | ReboundWork::VerifyStaged(_)) => {
            Err(RecoveryRebindError::TransactionMismatch)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn prepare_verified_purge<'a>(
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &'a TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    anchors: RecoveryAnchors,
) -> Result<VerifiedPurgeSession<'a>, RecoveryRebindError> {
    let snapshot = wal
        .recovery_snapshot(transaction)
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    if !matches!(
        snapshot.state,
        TransactionState::VerifiedCommitted | TransactionState::Purgeable
    ) {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let metadata = snapshot
        .staging
        .clone()
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    if metadata.production_association().is_none() {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let work = RecoveryWork::ResumeVerifiedUndo {
        transaction,
        permissions: snapshot.permissions,
    };
    match rebind_work(
        &metadata,
        snapshot.tree_manifest,
        snapshot.tree_sidecar,
        work,
        &anchors,
    ) {
        Ok(ReboundWork::VerifiedUndo(committed)) => Ok(VerifiedPurgeSession {
            wal,
            sidecars,
            startup_blocked,
            transaction,
            committed: *committed,
        }),
        Ok(ReboundWork::Restore(_) | ReboundWork::VerifyStaged(_)) => {
            Err(RecoveryRebindError::TransactionMismatch)
        }
        Err(error) => {
            // Rebinding an exact committed request already detected that its
            // durable authority projection is stale. Persist the fail-closed
            // condition whenever the WAL remains writable.
            if matches!(
                wal.transaction_state(transaction),
                Some(TransactionState::VerifiedCommitted | TransactionState::Purgeable)
            ) {
                wal.transition_recovery_required(transaction)?;
                *startup_blocked = true;
            }
            Err(error)
        }
    }
}

fn fail_closed<T>(
    wal: &mut SealWal<RecoverySession>,
    transaction: TransactionId,
    error: RecoveryRebindError,
) -> Result<T, RecoveryRebindError> {
    if wal.transaction_state(transaction) != Some(TransactionState::RecoveryRequired) {
        wal.transition_staging_foundation(transaction, TransactionState::RecoveryRequired)?;
    }
    Err(error)
}

struct ReboundStaged {
    destination_anchor: RecoveryFilesystemAnchor,
    metadata: StagingTransactionMetadata,
    root: ReboundObject,
    expected_manifest: Option<DurableTreeManifest>,
    sidecar_commitment: Option<TreeSidecarCommitment>,
    tree_seals: Vec<RecoveryPermissionPlan>,
}

enum ReboundWork {
    Restore(Box<ReboundRestore>),
    VerifyStaged(Box<ReboundStaged>),
    VerifiedUndo(Box<ReboundVerifiedUndo>),
}

fn resolve_uncertain_permissions(
    wal: &mut SealWal<RecoverySession>,
    transaction: TransactionId,
    metadata: &StagingTransactionMetadata,
    anchors: &RecoveryAnchors,
    permissions: Vec<DurablePermission>,
) -> Result<(), RecoveryRebindError> {
    validate_anchors(metadata, anchors)?;
    let snapshot = wal
        .recovery_snapshot(transaction)
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    for permission in permissions {
        let (anchor, path) =
            uncertain_permission_location(&permission, &snapshot.permissions, metadata, anchors)?;
        let expected = StrongObjectIdentity::new_with_mount(
            permission.evidence.device(),
            permission.evidence.inode(),
            crate::seal::wal::ObjectIncarnation::new(
                permission
                    .evidence
                    .generation_or_btime()
                    .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
            ),
            anchor.mount_key,
        );
        let rebound = rebind_permission_object(anchor, &path, expected, metadata, None)?;
        resolve_rebound_permission(wal, transaction, &permission, &rebound)?;
    }
    Ok(())
}

fn resolve_rebound_permission(
    wal: &mut SealWal<RecoverySession>,
    transaction: TransactionId,
    permission: &DurablePermission,
    rebound: &ReboundObject,
) -> Result<PermissionResolution, RecoveryRebindError> {
    rebound.verify_fresh_binding()?;
    #[cfg(test)]
    BEFORE_PERMISSION_RESOLUTION.with(|slot| {
        if let Some(operation) = slot.borrow_mut().take() {
            operation();
        }
    });
    wal.resolve_staging_permission(transaction, permission.mutation_id, |_| {
        let current = rebound.held.fresh_mode()?;
        if current == permission.expected_mode {
            Ok(PermissionResolution::Applied)
        } else if current == permission.pre_mode {
            Ok(PermissionResolution::ConfirmedNotApplied)
        } else {
            Err(io::Error::other(
                "held permission mode drifted before durable resolution",
            ))
        }
    })
    .map_err(RecoveryRebindError::Resolution)
}

fn uncertain_permission_location<'a>(
    permission: &DurablePermission,
    all_permissions: &[DurablePermission],
    metadata: &StagingTransactionMetadata,
    anchors: &'a RecoveryAnchors,
) -> Result<(&'a RecoveryFilesystemAnchor, PathBuf), RecoveryRebindError> {
    let Some(original_id) = permission.reverses_mutation_id else {
        if !matches!(
            permission.phase,
            TransactionState::ParentSealIntent | TransactionState::TreeSealIntent
        ) {
            return Err(RecoveryRebindError::TransactionMismatch);
        }
        return Ok((
            &anchors.source,
            permission.evidence.relative_path().to_path_buf(),
        ));
    };
    let original = all_permissions
        .iter()
        .find(|candidate| candidate.mutation_id == original_id)
        .ok_or(RecoveryRebindError::TransactionMismatch)?;
    if original.application != crate::seal::wal::ApplicationStatus::Applied
        || original.reverses_mutation_id.is_some()
        || !matches!(
            original.phase,
            TransactionState::ParentSealIntent | TransactionState::TreeSealIntent
        )
        || permission.pre_mode != original.expected_mode
        || permission.expected_mode != original.pre_mode
        || permission.evidence.filesystem_id() != original.evidence.filesystem_id()
        || permission.evidence.device() != original.evidence.device()
        || permission.evidence.inode() != original.evidence.inode()
        || permission.evidence.generation_or_btime() != original.evidence.generation_or_btime()
    {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let (anchor, expected_path) = match permission.phase {
        TransactionState::RestoreIntent => (
            &anchors.source,
            original.evidence.relative_path().to_path_buf(),
        ),
        TransactionState::SourceParentRestoreIntent
            if original.phase == TransactionState::ParentSealIntent =>
        {
            (
                &anchors.source,
                original.evidence.relative_path().to_path_buf(),
            )
        }
        TransactionState::Quarantined if original.phase == TransactionState::ParentSealIntent => (
            &anchors.source,
            original.evidence.relative_path().to_path_buf(),
        ),
        TransactionState::Quarantined if original.phase == TransactionState::TreeSealIntent => {
            let source_root = metadata
                .source_parent()
                .relative_path()
                .join(metadata.source_basename());
            let suffix = original
                .evidence
                .relative_path()
                .strip_prefix(&source_root)
                .map_err(|_| RecoveryRebindError::InvalidLocator)?;
            (
                &anchors.destination,
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename())
                    .join(suffix),
            )
        }
        TransactionState::UndoIntent if original.phase == TransactionState::TreeSealIntent => {
            let source_root = metadata
                .source_parent()
                .relative_path()
                .join(metadata.source_basename());
            let suffix = original
                .evidence
                .relative_path()
                .strip_prefix(&source_root)
                .map_err(|_| RecoveryRebindError::InvalidLocator)?;
            (
                &anchors.destination,
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename())
                    .join(suffix),
            )
        }
        _ => return Err(RecoveryRebindError::TransactionMismatch),
    };
    if permission.evidence.relative_path() != expected_path {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    Ok((anchor, expected_path))
}

fn rebind_work(
    metadata: &StagingTransactionMetadata,
    tree_manifest: Option<DurableTreeManifest>,
    sidecar_commitment: Option<TreeSidecarCommitment>,
    work: RecoveryWork,
    anchors: &RecoveryAnchors,
) -> Result<ReboundWork, RecoveryRebindError> {
    validate_anchors(metadata, anchors)?;
    let transaction = recovery_transaction(&work);

    // Both durable parent bindings are authenticated before choosing any target.
    let source_parent = rebind_locator(
        &anchors.source,
        metadata.source_parent(),
        metadata.source_parent_identity(),
    )?;
    let destination_parent = rebind_locator(
        &anchors.destination,
        metadata.destination_parent(),
        metadata.destination_parent_identity(),
    )?;

    match work {
        RecoveryWork::RestoreBeforeRename {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let root = rebind_named_child(
                &anchors.source,
                source_parent,
                metadata.source_basename(),
                metadata.root_identity(),
                metadata
                    .source_parent()
                    .relative_path()
                    .join(metadata.source_basename()),
                metadata,
                None,
            )?;
            drop(root);
            drop(destination_parent);
            let entries = rebind_permissions(&anchors.source, metadata, permissions)?;
            Ok(ReboundWork::Restore(Box::new(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                anchors: anchors.duplicate()?,
                metadata: metadata.clone(),
                entries,
                completion: TransactionState::Restored,
            })))
        }
        RecoveryWork::RestoreSourceParentAfterRename {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let staged = rebind_named_child(
                &anchors.destination,
                destination_parent,
                metadata.destination_basename(),
                metadata.root_identity(),
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename()),
                metadata,
                None,
            )?;
            drop(staged);
            drop(source_parent);
            let entries = rebind_permissions(&anchors.source, metadata, permissions)?;
            Ok(ReboundWork::Restore(Box::new(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                anchors: anchors.duplicate()?,
                metadata: metadata.clone(),
                entries,
                completion: TransactionState::SourceParentRestored,
            })))
        }
        RecoveryWork::RestoreQuarantinedSeals {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let staged = rebind_named_child(
                &anchors.destination,
                destination_parent,
                metadata.destination_basename(),
                metadata.root_identity(),
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename()),
                metadata,
                None,
            )?;
            drop(staged);
            drop(source_parent);
            let entries = rebind_quarantined_permissions(anchors, metadata, permissions)?;
            Ok(ReboundWork::Restore(Box::new(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                anchors: anchors.duplicate()?,
                metadata: metadata.clone(),
                entries,
                completion: TransactionState::Quarantined,
            })))
        }
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            drop(source_parent);
            let root = rebind_named_child(
                &anchors.destination,
                destination_parent,
                metadata.destination_basename(),
                metadata.root_identity(),
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename()),
                metadata,
                None,
            )?;
            let tree_seals = rebind_staged_tree_seals(&anchors.destination, metadata, permissions)?;
            Ok(ReboundWork::VerifyStaged(Box::new(ReboundStaged {
                destination_anchor: anchors.destination.duplicate_authority()?,
                metadata: metadata.clone(),
                root,
                expected_manifest: tree_manifest,
                sidecar_commitment,
                tree_seals,
            })))
        }
        RecoveryWork::ResumeVerifiedUndo {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let expected_manifest =
                tree_manifest.ok_or(RecoveryRebindError::UndoManifestChanged)?;
            if !expected_manifest.has_content_proof() {
                // Backward replay remains available, but a legacy metadata-only
                // VerifiedCommitted record can never authorize automatic undo.
                return Err(RecoveryRebindError::UndoManifestChanged);
            }
            let root = rebind_named_child(
                &anchors.destination,
                rustix::io::dup(&destination_parent)
                    .map_err(io::Error::from)
                    .map_err(RecoveryRebindError::Io)?,
                metadata.destination_basename(),
                metadata.root_identity(),
                metadata
                    .destination_parent()
                    .relative_path()
                    .join(metadata.destination_basename()),
                metadata,
                None,
            )?;
            let tree_seals =
                rebind_verified_undo_tree_seals(&anchors.destination, metadata, permissions)?;
            Ok(ReboundWork::VerifiedUndo(Box::new(ReboundVerifiedUndo {
                anchors: anchors.duplicate()?,
                metadata: metadata.clone(),
                source_parent,
                destination_parent,
                root,
                tree_seals,
                expected_manifest,
                sidecar_commitment,
            })))
        }
        RecoveryWork::RecoveryRequired { .. }
        | RecoveryWork::ResolveUncertainPermissions { .. }
        | RecoveryWork::PreserveCommittedSeal { .. }
        | RecoveryWork::PreserveQuarantine { .. }
        | RecoveryWork::PreserveUndoConflict { .. }
        | RecoveryWork::FinalizePurge { .. }
        | RecoveryWork::FinalizeVerifiedCommit { .. }
        | RecoveryWork::FinalizeVerifiedUndo { .. }
        | RecoveryWork::Nothing => Err(RecoveryRebindError::TransactionMismatch),
    }
}

fn recovery_lookup_is_forbidden(work: &RecoveryWork) -> bool {
    matches!(
        work,
        RecoveryWork::RecoveryRequired {
            reason: crate::seal::wal::RecoveryRequiredReason::RenameOutcomeUnknown,
            ..
        }
    )
}

pub(crate) fn recovery_transaction(work: &RecoveryWork) -> TransactionId {
    match work {
        RecoveryWork::RestoreBeforeRename { transaction, .. }
        | RecoveryWork::VerifyOrQuarantineAfterRename { transaction, .. }
        | RecoveryWork::RestoreSourceParentAfterRename { transaction, .. }
        | RecoveryWork::RestoreQuarantinedSeals { transaction, .. }
        | RecoveryWork::ResolveUncertainPermissions { transaction, .. }
        | RecoveryWork::PreserveCommittedSeal { transaction, .. }
        | RecoveryWork::PreserveQuarantine { transaction }
        | RecoveryWork::FinalizeVerifiedCommit { transaction }
        | RecoveryWork::ResumeVerifiedUndo { transaction, .. }
        | RecoveryWork::FinalizeVerifiedUndo { transaction, .. }
        | RecoveryWork::PreserveUndoConflict { transaction }
        | RecoveryWork::FinalizePurge { transaction }
        | RecoveryWork::RecoveryRequired { transaction, .. } => *transaction,
        RecoveryWork::Nothing => TransactionId([0; 16]),
    }
}

fn validate_anchors(
    metadata: &StagingTransactionMetadata,
    anchors: &RecoveryAnchors,
) -> Result<(), RecoveryRebindError> {
    if anchors.source.filesystem_id != metadata.filesystem_id()
        || anchors.destination.filesystem_id != metadata.filesystem_id()
    {
        return Err(RecoveryRebindError::FilesystemChanged);
    }
    if anchors.source.backend != metadata.backend()
        || anchors.destination.backend != metadata.backend()
    {
        return Err(RecoveryRebindError::BackendChanged);
    }
    if anchors.source.mount_key != anchors.destination.mount_key
        || metadata.source_parent_identity().mount_id() == 0
        || metadata.root_identity().mount_id() == 0
        || metadata.destination_parent_identity().mount_id() == 0
        || metadata.source_parent_identity().mount_id() != anchors.source.mount_key
        || metadata.root_identity().mount_id() != anchors.source.mount_key
        || metadata.destination_parent_identity().mount_id() != anchors.destination.mount_key
    {
        return Err(RecoveryRebindError::MountChanged);
    }
    Ok(())
}

fn rebind_locator(
    anchor: &RecoveryFilesystemAnchor,
    locator: &StagingLocator,
    expected: StrongObjectIdentity,
) -> Result<OwnedFd, RecoveryRebindError> {
    if locator.filesystem_id() != anchor.filesystem_id {
        return Err(RecoveryRebindError::FilesystemChanged);
    }
    let fd = open_confined_directory(&anchor.fd, locator.relative_path(), anchor.mount_key)?;
    validate_fd(anchor, &fd, expected)?;
    Ok(fd)
}

fn capture_directory_evidence(
    fd: &OwnedFd,
    metadata: &StagingTransactionMetadata,
) -> Result<PlannedDirectoryEvidence, RecoveryRebindError> {
    let identity = strong_identity_fd(fd)?;
    let held = certify_held_fd(
        rustix::io::dup(fd)
            .map_err(io::Error::from)
            .map_err(RecoveryRebindError::Io)?,
    )?;
    #[cfg(test)]
    observe_recovery_fds();
    if held.backend() != metadata.backend() {
        return Err(RecoveryRebindError::BackendChanged);
    }
    if held.mount_id() != identity.mount_id()
        || held.mount_id() != metadata.root_identity().mount_id()
    {
        return Err(RecoveryRebindError::MountChanged);
    }
    held.verify_current_mode(held.mode())
        .map_err(RecoveryRebindError::SealChanged)?;
    Ok(PlannedDirectoryEvidence {
        identity,
        owner_uid: held.owner_uid(),
        group_gid: held.group_gid(),
        mode: held.mode(),
        backend: held.backend(),
        mount_id: held.mount_id(),
        effective_uid: held.effective_uid(),
        effective_groups: held.effective_groups().clone(),
    })
}

fn build_permission_plan(
    anchor: &RecoveryFilesystemAnchor,
    side: RecoveryAnchorSide,
    relative_path: PathBuf,
    permission: DurablePermission,
    expected_current_mode: u32,
    metadata: &StagingTransactionMetadata,
) -> Result<RecoveryPermissionPlan, RecoveryRebindError> {
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || permission.evidence.filesystem_id() != Some(metadata.filesystem_id())
        || permission.evidence.expected_mode() != permission.expected_mode
        || permission.expected_mode > 0o7777
        || permission.pre_mode > 0o7777
    {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let expected = StrongObjectIdentity::new_with_mount(
        permission.evidence.device(),
        permission.evidence.inode(),
        crate::seal::wal::ObjectIncarnation::new(
            permission
                .evidence
                .generation_or_btime()
                .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
        ),
        anchor.mount_key,
    );
    let mut current = rustix::io::dup(&anchor.fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let mut chain = Vec::new();
    require_exclusive_controller(&current)?;
    if relative_path.as_os_str().is_empty() {
        chain.push(capture_directory_evidence(&current, metadata)?);
    } else {
        let mut components = relative_path.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(RecoveryRebindError::InvalidLocator);
            };
            current = open_directory_at(&current, name)?;
            if held_mount_key(&current)? != anchor.mount_key {
                return Err(RecoveryRebindError::MountChanged);
            }
            if components.peek().is_some() {
                require_exclusive_controller(&current)?;
            }
            chain.push(capture_directory_evidence(&current, metadata)?);
        }
    }
    let target = chain.last().ok_or(RecoveryRebindError::InvalidLocator)?;
    if target.identity != expected || target.mode != expected_current_mode {
        return Err(RecoveryRebindError::BindingChanged);
    }
    Ok(RecoveryPermissionPlan {
        permission,
        side,
        relative_path,
        chain,
    })
}

fn verify_held_evidence(
    held: &HeldLocalBackendEvidence,
    expected: &PlannedDirectoryEvidence,
) -> Result<(), RecoveryRebindError> {
    held.verify_current_mode(expected.mode)
        .map_err(RecoveryRebindError::SealChanged)?;
    if held.backend() != expected.backend {
        return Err(RecoveryRebindError::BackendChanged);
    }
    if held.mount_id() != expected.mount_id {
        return Err(RecoveryRebindError::MountChanged);
    }
    if held.device() != expected.identity.device()
        || held.inode() != expected.identity.inode()
        || held.owner_uid() != expected.owner_uid
        || held.group_gid() != expected.group_gid
        || held.effective_uid() != expected.effective_uid
        || held.effective_groups() != &expected.effective_groups
    {
        return Err(RecoveryRebindError::BindingChanged);
    }
    Ok(())
}

fn verify_planned_evidence(
    fd: &OwnedFd,
    expected: &PlannedDirectoryEvidence,
) -> Result<HeldLocalBackendEvidence, RecoveryRebindError> {
    if strong_identity_fd(fd)? != expected.identity {
        return Err(RecoveryRebindError::BindingChanged);
    }
    let held = certify_held_fd(
        rustix::io::dup(fd)
            .map_err(io::Error::from)
            .map_err(RecoveryRebindError::Io)?,
    )?;
    verify_held_evidence(&held, expected)?;
    Ok(held)
}

/// Reopen one plan entry from its retained authenticated anchor. All ancestor
/// descriptors are transient and dropped before the next entry is considered.
fn reopen_permission_plan(
    anchor: &RecoveryFilesystemAnchor,
    plan: &RecoveryPermissionPlan,
    metadata: &StagingTransactionMetadata,
) -> Result<ReboundObject, RecoveryRebindError> {
    if plan.relative_path.is_absolute()
        || plan
            .relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || anchor.backend != metadata.backend()
        || anchor.mount_key != metadata.root_identity().mount_id()
        || plan.permission.evidence.filesystem_id() != Some(metadata.filesystem_id())
        || plan.permission.evidence.expected_mode() != plan.permission.expected_mode
    {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let mut current = rustix::io::dup(&anchor.fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let mut parent = None;
    let mut basename = None;
    require_exclusive_controller(&current)?;
    if plan.relative_path.as_os_str().is_empty() {
        if plan.chain.len() != 1 {
            return Err(RecoveryRebindError::InvalidLocator);
        }
        verify_planned_evidence(&current, &plan.chain[0])?;
    } else {
        let components = plan.relative_path.components().collect::<Vec<_>>();
        if components.len() != plan.chain.len() {
            return Err(RecoveryRebindError::InvalidLocator);
        }
        for (index, component) in components.into_iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(RecoveryRebindError::InvalidLocator);
            };
            let next = open_directory_at(&current, name)?;
            if index + 1 < plan.chain.len() {
                require_exclusive_controller(&next)?;
            }
            verify_planned_evidence(&next, &plan.chain[index])?;
            if index + 1 == plan.chain.len() {
                parent = Some(current);
                basename = Some(name.to_os_string());
            }
            current = next;
        }
    }
    let target = plan
        .chain
        .last()
        .ok_or(RecoveryRebindError::InvalidLocator)?;
    if target.identity.device() != plan.permission.evidence.device()
        || target.identity.inode() != plan.permission.evidence.inode()
        || target.identity.incarnation().get()
            != plan
                .permission
                .evidence
                .generation_or_btime()
                .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?
        || target.identity.mount_id() != anchor.mount_key
    {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    let object_check_fd = rustix::io::dup(&current)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let held = certify_held_fd(current)?;
    verify_held_evidence(&held, target)?;
    let binding = match (parent, basename) {
        (Some(parent), Some(basename)) => ReboundBinding::Named {
            attachment: None,
            parent,
            basename,
        },
        (None, None) => ReboundBinding::Anchor(anchor.duplicate_authority()?),
        _ => return Err(RecoveryRebindError::InvalidLocator),
    };
    #[cfg(test)]
    observe_recovery_fds();
    Ok(ReboundObject {
        binding,
        object_check_fd,
        relative_path: plan.relative_path.clone(),
        identity: target.identity,
        held,
    })
}

fn rebind_staged_tree_seals(
    destination_anchor: &RecoveryFilesystemAnchor,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<RecoveryPermissionPlan>, RecoveryRebindError> {
    let source_root = metadata
        .source_parent()
        .relative_path()
        .join(metadata.source_basename());
    let destination_root = metadata
        .destination_parent()
        .relative_path()
        .join(metadata.destination_basename());
    let mut plans = Vec::new();
    let mut mutation_ids = BTreeSet::new();
    for permission in permissions {
        if permission.application != ApplicationStatus::Applied
            || permission.reverses_mutation_id.is_some()
            || !mutation_ids.insert(permission.mutation_id)
            || permission.evidence.filesystem_id() != Some(metadata.filesystem_id())
            || permission.evidence.expected_mode() != permission.expected_mode
        {
            return Err(RecoveryRebindError::TransactionMismatch);
        }
        if permission.phase == TransactionState::ParentSealIntent {
            continue;
        }
        if permission.phase != TransactionState::TreeSealIntent {
            return Err(RecoveryRebindError::TransactionMismatch);
        }
        let suffix = permission
            .evidence
            .relative_path()
            .strip_prefix(&source_root)
            .map_err(|_| RecoveryRebindError::InvalidLocator)?;
        let path = destination_root.join(suffix);
        let expected_mode = permission.expected_mode;
        plans.push(build_permission_plan(
            destination_anchor,
            RecoveryAnchorSide::Destination,
            path,
            permission,
            expected_mode,
            metadata,
        )?);
    }
    Ok(plans)
}

fn rebind_verified_undo_tree_seals(
    destination_anchor: &RecoveryFilesystemAnchor,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<RecoveryPermissionPlan>, RecoveryRebindError> {
    let source_root = metadata
        .source_parent()
        .relative_path()
        .join(metadata.source_basename());
    let destination_root = metadata
        .destination_parent()
        .relative_path()
        .join(metadata.destination_basename());
    let originals = permissions
        .iter()
        .filter(|permission| {
            permission.phase == TransactionState::TreeSealIntent
                && permission.application == ApplicationStatus::Applied
                && permission.reverses_mutation_id.is_none()
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut mutation_ids = BTreeSet::new();
    let mut plans = Vec::with_capacity(originals.len());
    for original in originals {
        if !mutation_ids.insert(original.mutation_id)
            || original.evidence.filesystem_id() != Some(metadata.filesystem_id())
            || original.evidence.expected_mode() != original.expected_mode
        {
            return Err(RecoveryRebindError::TransactionMismatch);
        }
        let suffix = original
            .evidence
            .relative_path()
            .strip_prefix(&source_root)
            .map_err(|_| RecoveryRebindError::InvalidLocator)?;
        let inverse_applied = permissions.iter().any(|inverse| {
            inverse.phase == TransactionState::UndoIntent
                && inverse.application == ApplicationStatus::Applied
                && inverse.reverses_mutation_id == Some(original.mutation_id)
                && inverse.pre_mode == original.expected_mode
                && inverse.expected_mode == original.pre_mode
                && inverse.evidence.filesystem_id() == original.evidence.filesystem_id()
                && inverse.evidence.device() == original.evidence.device()
                && inverse.evidence.inode() == original.evidence.inode()
                && inverse.evidence.generation_or_btime() == original.evidence.generation_or_btime()
        });
        let target_path = destination_root.join(suffix);
        if inverse_applied {
            // A crash can occur after a descendant was restored but before the
            // durable UndoModesRestored marker. Reopening that already-restored
            // entry would require traversing a parent whose namespace-write
            // mode was intentionally restored. Keep its durable identity as a
            // data-only plan and skip it during replay; remaining plans are
            // ordered deepest-first, so their controllers are still sealed.
            plans.push(RecoveryPermissionPlan {
                permission: original.clone(),
                side: RecoveryAnchorSide::Destination,
                relative_path: target_path,
                chain: vec![PlannedDirectoryEvidence {
                    identity: StrongObjectIdentity::new_with_mount(
                        original.evidence.device(),
                        original.evidence.inode(),
                        crate::seal::wal::ObjectIncarnation::new(
                            original
                                .evidence
                                .generation_or_btime()
                                .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
                        ),
                        destination_anchor.mount_key,
                    ),
                    owner_uid: rustix::process::geteuid().as_raw(),
                    group_gid: 0,
                    mode: original.pre_mode,
                    backend: metadata.backend(),
                    mount_id: destination_anchor.mount_key,
                    effective_uid: rustix::process::geteuid().as_raw(),
                    effective_groups: BTreeSet::new(),
                }],
            });
        } else {
            plans.push(build_permission_plan(
                destination_anchor,
                RecoveryAnchorSide::Destination,
                target_path,
                original.clone(),
                original.expected_mode,
                metadata,
            )?);
        }
    }
    if plans.is_empty() {
        return Err(RecoveryRebindError::UndoManifestChanged);
    }
    Ok(plans)
}

fn rebind_permissions(
    anchor: &RecoveryFilesystemAnchor,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<RecoveryPermissionPlan>, RecoveryRebindError> {
    let source_parent = metadata.source_parent().relative_path();
    let source_root = source_parent.join(metadata.source_basename());
    let mut mutation_ids = BTreeSet::new();
    permissions
        .into_iter()
        .map(|permission| {
            let path = permission.evidence.relative_path().to_path_buf();
            let path_matches_phase = match permission.phase {
                TransactionState::ParentSealIntent => path == source_parent,
                TransactionState::TreeSealIntent => path.starts_with(&source_root),
                _ => false,
            };
            if permission.application != ApplicationStatus::Applied
                || permission.reverses_mutation_id.is_some()
                || !path_matches_phase
                || !mutation_ids.insert(permission.mutation_id)
            {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let expected_mode = permission.expected_mode;
            build_permission_plan(
                anchor,
                RecoveryAnchorSide::Source,
                path,
                permission,
                expected_mode,
                metadata,
            )
        })
        .collect()
}

fn rebind_quarantined_permissions(
    anchors: &RecoveryAnchors,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<RecoveryPermissionPlan>, RecoveryRebindError> {
    let source_root = metadata
        .source_parent()
        .relative_path()
        .join(metadata.source_basename());
    let destination_root = metadata
        .destination_parent()
        .relative_path()
        .join(metadata.destination_basename());
    let mut mutation_ids = BTreeSet::new();
    permissions
        .into_iter()
        .map(|permission| {
            if permission.application != ApplicationStatus::Applied
                || permission.reverses_mutation_id.is_some()
                || !mutation_ids.insert(permission.mutation_id)
            {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let (anchor, side, path) = if permission.phase == TransactionState::ParentSealIntent {
                if permission.evidence.relative_path() != metadata.source_parent().relative_path() {
                    return Err(RecoveryRebindError::TransactionMismatch);
                }
                (
                    &anchors.source,
                    RecoveryAnchorSide::Source,
                    permission.evidence.relative_path().to_path_buf(),
                )
            } else if permission.phase == TransactionState::TreeSealIntent {
                let suffix = permission
                    .evidence
                    .relative_path()
                    .strip_prefix(&source_root)
                    .map_err(|_| RecoveryRebindError::InvalidLocator)?;
                (
                    &anchors.destination,
                    RecoveryAnchorSide::Destination,
                    destination_root.join(suffix),
                )
            } else {
                return Err(RecoveryRebindError::TransactionMismatch);
            };
            let expected_mode = permission.expected_mode;
            build_permission_plan(anchor, side, path, permission, expected_mode, metadata)
        })
        .collect()
}

fn rebind_permission_object(
    anchor: &RecoveryFilesystemAnchor,
    relative_path: &Path,
    expected: StrongObjectIdentity,
    metadata: &StagingTransactionMetadata,
    expected_mode: Option<u32>,
) -> Result<ReboundObject, RecoveryRebindError> {
    if !relative_path.as_os_str().is_empty() {
        let (parent, basename) = open_confined_parent(&anchor.fd, relative_path, anchor.mount_key)?;
        return rebind_named_child(
            anchor,
            parent,
            &basename,
            expected,
            relative_path.to_path_buf(),
            metadata,
            expected_mode,
        );
    }
    if !metadata
        .source_parent()
        .relative_path()
        .as_os_str()
        .is_empty()
        || expected != metadata.source_parent_identity()
    {
        return Err(RecoveryRebindError::InvalidLocator);
    }
    let object = rustix::io::dup(&anchor.fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    validate_fd(anchor, &object, expected)?;
    let object_check_fd = rustix::io::dup(&object)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let held = certify_held_fd(object)?;
    if held.backend() != metadata.backend()
        || held.mount_id() != expected.mount_id()
        || held.device() != expected.device()
        || held.inode() != expected.inode()
        || expected_mode.is_some_and(|mode| held.mode() != mode)
    {
        return Err(RecoveryRebindError::BindingChanged);
    }
    Ok(ReboundObject {
        binding: ReboundBinding::Anchor(anchor.duplicate_authority()?),
        object_check_fd,
        relative_path: PathBuf::new(),
        identity: expected,
        held,
    })
}

fn rebind_named_child(
    anchor: &RecoveryFilesystemAnchor,
    parent: OwnedFd,
    basename: &OsStr,
    expected: StrongObjectIdentity,
    relative_path: PathBuf,
    metadata: &StagingTransactionMetadata,
    expected_mode: Option<u32>,
) -> Result<ReboundObject, RecoveryRebindError> {
    if !normal_basename(basename) {
        return Err(RecoveryRebindError::InvalidLocator);
    }
    let attachment = LocatorAttachment::bind(anchor, &relative_path, &parent)?;
    attachment.verify(&parent)?;
    let fd = open_directory_at(&parent, basename)?;
    if strong_identity_fd(&fd)? != expected {
        return Err(RecoveryRebindError::BindingChanged);
    }
    let object_check_fd = rustix::io::dup(&fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let held = certify_held_fd(fd)?;
    if held.backend() != metadata.backend() {
        return Err(RecoveryRebindError::BackendChanged);
    }
    if held.mount_id() != expected.mount_id() {
        return Err(RecoveryRebindError::MountChanged);
    }
    if held.device() != expected.device() || held.inode() != expected.inode() {
        return Err(RecoveryRebindError::BindingChanged);
    }
    if let Some(expected_mode) = expected_mode
        && held.mode() != expected_mode
    {
        return Err(RecoveryRebindError::ModeChanged);
    }
    Ok(ReboundObject {
        binding: ReboundBinding::Named {
            attachment: Some(attachment),
            parent,
            basename: basename.to_os_string(),
        },
        object_check_fd,
        relative_path,
        identity: expected,
        held,
    })
}

fn validate_fd(
    anchor: &RecoveryFilesystemAnchor,
    fd: &OwnedFd,
    expected: StrongObjectIdentity,
) -> Result<(), RecoveryRebindError> {
    if certify_held_fd_backend(fd)? != anchor.backend {
        return Err(RecoveryRebindError::BackendChanged);
    }
    if held_mount_key(fd)? != anchor.mount_key {
        return Err(RecoveryRebindError::MountChanged);
    }
    if strong_identity_fd(fd)? != expected {
        return Err(RecoveryRebindError::BindingChanged);
    }
    Ok(())
}

fn require_exclusive_controller(fd: &OwnedFd) -> Result<(), RecoveryRebindError> {
    let duplicate = rustix::io::dup(fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    certify_held_fd(duplicate)?
        .verify_namespace_exclusive()
        .map_err(|_| RecoveryRebindError::LocatorControllerNotExclusive)
}

fn open_confined_directory_with_exclusive_ancestors(
    anchor: &OwnedFd,
    path: &Path,
    expected_mount: u64,
) -> Result<OwnedFd, RecoveryRebindError> {
    let mut current = rustix::io::dup(anchor)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    if path.as_os_str().is_empty() {
        require_exclusive_controller(&current)?;
        if held_mount_key(&current)? != expected_mount {
            return Err(RecoveryRebindError::MountChanged);
        }
        return Ok(current);
    }
    let mut saw_component = false;
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(RecoveryRebindError::InvalidLocator);
        };
        saw_component = true;
        require_exclusive_controller(&current)?;
        current = open_directory_at(&current, name)?;
        if held_mount_key(&current)? != expected_mount {
            return Err(RecoveryRebindError::MountChanged);
        }
    }
    saw_component
        .then_some(current)
        .ok_or(RecoveryRebindError::InvalidLocator)
}

fn open_confined_directory(
    anchor: &OwnedFd,
    path: &Path,
    expected_mount: u64,
) -> Result<OwnedFd, RecoveryRebindError> {
    open_confined_directory_with_exclusive_ancestors(anchor, path, expected_mount)
}

fn open_confined_parent(
    anchor: &OwnedFd,
    path: &Path,
    expected_mount: u64,
) -> Result<(OwnedFd, OsString), RecoveryRebindError> {
    let basename = path
        .file_name()
        .filter(|name| normal_basename(name))
        .ok_or(RecoveryRebindError::InvalidLocator)?
        .to_os_string();
    let parent = path.parent().ok_or(RecoveryRebindError::InvalidLocator)?;
    let parent_fd = if parent.as_os_str().is_empty() {
        rustix::io::dup(anchor)
            .map_err(io::Error::from)
            .map_err(RecoveryRebindError::Io)?
    } else {
        open_confined_directory(anchor, parent, expected_mount)?
    };
    require_exclusive_controller(&parent_fd)?;
    Ok((parent_fd, basename))
}

fn open_directory_at(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, RecoveryRebindError> {
    #[cfg(test)]
    RECOVERY_NAME_LOOKUPS.set(RECOVERY_NAME_LOOKUPS.get() + 1);
    rustix::fs::openat(parent, name, OPEN_DIRECTORY, Mode::empty())
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)
}

/// Canonical filesystem identity used both when the staging transaction is
/// created and when a crash-recovery anchor is certified. It is derived from
/// the held mount's kernel fsid, never accepted from a pathname.
pub(crate) fn held_filesystem_id(fd: &OwnedFd) -> Result<String, RecoveryRebindError> {
    let statfs = rustix::fs::fstatfs(fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let fsid = &statfs.f_fsid;
    // SAFETY: f_fsid is a fully initialized Copy field returned by fstatfs; the
    // byte view does not outlive it and is used only for deterministic encoding.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(fsid).cast::<u8>(),
            std::mem::size_of_val(fsid),
        )
    };
    let mut encoded = String::with_capacity(8 + bytes.len() * 2);
    encoded.push_str("fsid-v1:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn normal_basename(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(target_os = "linux")]
fn held_mount_key(fd: &OwnedFd) -> Result<u64, RecoveryRebindError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let statx = statx(fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    StatxFlags::from_bits_retain(statx.stx_mask)
        .contains(StatxFlags::MNT_ID)
        .then_some(statx.stx_mnt_id)
        .ok_or(RecoveryRebindError::MountChanged)
}

#[cfg(target_os = "macos")]
fn held_mount_key(fd: &OwnedFd) -> Result<u64, RecoveryRebindError> {
    let stat = rustix::fs::fstat(fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    u64::try_from(stat.st_dev).map_err(|_| RecoveryRebindError::MountChanged)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn held_mount_key(_fd: &OwnedFd) -> Result<u64, RecoveryRebindError> {
    Err(RecoveryRebindError::StrongIdentityUnavailable)
}

#[cfg(target_os = "linux")]
pub(crate) fn strong_identity_fd(
    fd: &OwnedFd,
) -> Result<StrongObjectIdentity, RecoveryRebindError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let requested = StatxFlags::BASIC_STATS | StatxFlags::BTIME | StatxFlags::MNT_ID;
    let statx = statx(fd, c"", AtFlags::EMPTY_PATH, requested)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let present = StatxFlags::from_bits_retain(statx.stx_mask);
    if !present.contains(StatxFlags::BTIME) || !present.contains(StatxFlags::MNT_ID) {
        return Err(RecoveryRebindError::StrongIdentityUnavailable);
    }
    let incarnation = timestamp_incarnation(statx.stx_btime.tv_sec, statx.stx_btime.tv_nsec)?;
    let stat = rustix::fs::fstat(fd)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    Ok(StrongObjectIdentity::new_with_mount(
        stat.st_dev,
        statx.stx_ino,
        crate::seal::wal::ObjectIncarnation::new(incarnation),
        statx.stx_mnt_id,
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn strong_identity_fd(
    fd: &OwnedFd,
) -> Result<StrongObjectIdentity, RecoveryRebindError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is valid writable storage and fd remains owned for the call.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(RecoveryRebindError::Io(io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized the complete structure.
    let stat = unsafe { stat.assume_init() };
    let incarnation = timestamp_incarnation(
        stat.st_birthtime,
        u32::try_from(stat.st_birthtime_nsec)
            .map_err(|_| RecoveryRebindError::StrongIdentityUnavailable)?,
    )?;
    let mount_id =
        u64::try_from(stat.st_dev).map_err(|_| RecoveryRebindError::StrongIdentityUnavailable)?;
    Ok(StrongObjectIdentity::new_with_mount(
        mount_id,
        stat.st_ino,
        crate::seal::wal::ObjectIncarnation::new(incarnation),
        mount_id,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn strong_identity_fd(
    _fd: &OwnedFd,
) -> Result<StrongObjectIdentity, RecoveryRebindError> {
    Err(RecoveryRebindError::StrongIdentityUnavailable)
}

fn timestamp_incarnation(seconds: i64, nanos: u32) -> Result<u64, RecoveryRebindError> {
    let seconds =
        u64::try_from(seconds).map_err(|_| RecoveryRebindError::StrongIdentityUnavailable)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u64::from(nanos)))
        .ok_or(RecoveryRebindError::StrongIdentityUnavailable)
}

#[cfg(test)]
mod tests;
