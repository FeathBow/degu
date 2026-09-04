//! Lease-bound held-FD staging rename implementation.
//!
//! This module has no direct CLI or lifecycle entry point. It may move
//! one exact, fully sealed local tree from an authenticated source parent to an
//! authenticated destination parent. It cannot restore, commit, purge, unlink,
//! or delete, and its only success state is `StagedUnverified`.

use crate::authority::TransactionState;
use crate::backend::held::{
    HardlinkTopologyFold, HeldTreeError, HeldTreeLimits, HeldTreeSealError, HeldTreeV3CollectError,
    ManifestV3CodecError, PendingV3Inventory, StreamedV3Inventory, StructureEvidence,
    decode_hardlink_scratch_record, decode_pre_seal_directory_plan_record,
    hardlink_scratch_sentinel_record, structure_evidence_from_v3_record,
};
use crate::backend::{
    CertificationError, HeldLocalBackendEvidence, LocalModeRevalidationFailure, certify_held_fd,
};
use crate::seal::executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeMutationResult, LocalModeTransform,
    RecoveryLocator, execute_staging_local_mode_mutation,
};
#[cfg(test)]
use crate::seal::sidecar::TreeDirectoryPlan;
#[cfg(test)]
type DirectoryPlanTestCallback = Box<dyn FnOnce(&TreeDirectoryPlan)>;
use crate::seal::sidecar::{
    TreeManifestFoldError, TreeManifestScratchBuildError, TreeSidecarCommitment, TreeSidecarError,
    TreeSidecarFoldError, TreeSidecarStore, TreeStructureScratchCursor,
};
use crate::seal::wal::{
    AppendError, DurableSourceParentStrategy, DurableTreeManifest, RecoverySession, SealWal,
    StagingLocator, StagingTransactionMetadata, StrongObjectIdentity, TransactionId,
};
use crate::staging::recovery::{
    RecoveryFilesystemAnchor, RecoveryRebindError, held_filesystem_id, strong_identity_fd,
};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[cfg(test)]
std::thread_local! {
    static BEFORE_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_PRE_SEAL_DIRECTORY_PLAN_PREFLIGHT: std::cell::RefCell<Option<DirectoryPlanTestCallback>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_PRE_SEAL_SCRATCH_READY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_PRE_SEAL_DIRECTORY_SEALS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_PRE_SEAL_INVENTORY_DROPPED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_STRUCTURE_SIDECAR_PREFLIGHT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static FAIL_PARENT_SYNC: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
    static RENAME_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static FAIL_WAL_STEP: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparedRootError {
    #[error("source or destination basename is not exactly one normal component")]
    InvalidBasename,
    #[error("source and destination locators do not match their held filesystem")]
    FilesystemChanged,
    #[error("source, root, and destination are not on one certified local backend and mount")]
    BackendOrMountChanged,
    #[error("source parent held evidence changed: {0:?}")]
    SourceParentChanged(LocalModeRevalidationFailure),
    #[error("destination parent held evidence changed: {0:?}")]
    DestinationParentChanged(LocalModeRevalidationFailure),
    #[error("source parent does not exclude foreign namespace writers")]
    SourceParentNotExclusive,
    #[error("destination parent does not exclude foreign namespace writers")]
    DestinationParentNotExclusive,
    #[error("destination name is already occupied")]
    DestinationOccupied,
    #[error("held object certification failed: {0:?}")]
    Certification(CertificationError),
    #[error("strong identity inspection failed: {0}")]
    Identity(#[from] RecoveryRebindError),
    #[error("held namespace inspection failed: {0}")]
    Io(#[source] io::Error),
    #[error("derived staging metadata violates its invariants")]
    InvalidMetadata,
}

impl From<CertificationError> for PreparedRootError {
    fn from(error: CertificationError) -> Self {
        Self::Certification(error)
    }
}

/// One-use binding between exact held source/destination parents and immutable
/// staging metadata derived from those descriptors. Durable locators remain
/// evidence; the retained descriptors are the namespace authority.
#[derive(Debug)]
pub(crate) struct PreparedRootBinding {
    metadata: StagingTransactionMetadata,
    source_anchor: RecoveryFilesystemAnchor,
    destination_anchor: RecoveryFilesystemAnchor,
    source_parent: OwnedFd,
    destination_parent: OwnedFd,
    source_parent_held: HeldLocalBackendEvidence,
    destination_parent_held: HeldLocalBackendEvidence,
    root_check_fd: OwnedFd,
}

impl PreparedRootBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        source_anchor: RecoveryFilesystemAnchor,
        source_parent: OwnedFd,
        source_parent_locator: StagingLocator,
        source_basename: OsString,
        destination_anchor: RecoveryFilesystemAnchor,
        destination_parent: OwnedFd,
        destination_parent_locator: StagingLocator,
        destination_basename: OsString,
    ) -> Result<Self, PreparedRootError> {
        Self::prepare_with_association(
            source_anchor,
            source_parent,
            source_parent_locator,
            source_basename,
            destination_anchor,
            destination_parent,
            destination_parent_locator,
            destination_basename,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_association(
        source_anchor: RecoveryFilesystemAnchor,
        source_parent: OwnedFd,
        source_parent_locator: StagingLocator,
        source_basename: OsString,
        destination_anchor: RecoveryFilesystemAnchor,
        destination_parent: OwnedFd,
        destination_parent_locator: StagingLocator,
        destination_basename: OsString,
        production_association: Option<crate::seal::wal::ProductionAssociation>,
        recovery_anchor: Option<PathBuf>,
    ) -> Result<Self, PreparedRootError> {
        if !normal_basename(&source_basename) || !normal_basename(&destination_basename) {
            return Err(PreparedRootError::InvalidBasename);
        }

        let source_parent_identity = strong_identity_fd(&source_parent)?;
        let destination_parent_identity = strong_identity_fd(&destination_parent)?;
        source_anchor.verify_locator_binding(
            &source_parent_locator,
            &source_parent,
            source_parent_identity,
        )?;
        destination_anchor.verify_locator_binding(
            &destination_parent_locator,
            &destination_parent,
            destination_parent_identity,
        )?;
        let source_filesystem = held_filesystem_id(&source_parent)?;
        let destination_filesystem = held_filesystem_id(&destination_parent)?;
        if source_filesystem != destination_filesystem
            || source_parent_locator.filesystem_id() != source_filesystem
            || destination_parent_locator.filesystem_id() != source_filesystem
        {
            return Err(PreparedRootError::FilesystemChanged);
        }

        let source_parent_held = certify_duplicate(&source_parent)?;
        let destination_parent_held = certify_duplicate(&destination_parent)?;
        destination_parent_held
            .verify_namespace_exclusive()
            .map_err(classify_destination_parent)?;

        let root_check_fd = open_directory_at(&source_parent, &source_basename)?;
        let root_identity = strong_identity_fd(&root_check_fd)?;
        let root_held = certify_duplicate(&root_check_fd)?;
        let backend = source_parent_held.backend();
        if destination_parent_held.backend() != backend
            || root_held.backend() != backend
            || source_parent_identity.mount_id() != destination_parent_identity.mount_id()
            || source_parent_identity.mount_id() != root_identity.mount_id()
            || source_parent_held.mount_id() != source_parent_identity.mount_id()
            || destination_parent_held.mount_id() != destination_parent_identity.mount_id()
            || root_held.mount_id() != root_identity.mount_id()
        {
            return Err(PreparedRootError::BackendOrMountChanged);
        }
        require_absent(&destination_parent, &destination_basename)?;

        let metadata = StagingTransactionMetadata::new(
            source_parent_locator,
            source_parent_identity,
            source_basename,
            root_identity,
            destination_parent_locator,
            destination_parent_identity,
            destination_basename,
            backend,
            DurableSourceParentStrategy::PermissionSeal,
        )
        .map(|metadata| match production_association {
            Some(association) => metadata.with_production_association(association),
            None => metadata,
        })
        .and_then(|metadata| match recovery_anchor {
            Some(path) => metadata.with_recovery_anchor(path),
            None => Some(metadata),
        })
        .ok_or(PreparedRootError::InvalidMetadata)?;

        Ok(Self {
            metadata,
            source_anchor,
            destination_anchor,
            source_parent,
            destination_parent,
            source_parent_held,
            destination_parent_held,
            root_check_fd,
        })
    }

    pub(crate) fn metadata(&self) -> &StagingTransactionMetadata {
        &self.metadata
    }

    fn verify_before_sealing(&self) -> Result<(), PreparedRootError> {
        self.source_anchor.verify_locator_binding(
            self.metadata.source_parent(),
            &self.source_parent,
            self.metadata.source_parent_identity(),
        )?;
        self.destination_anchor.verify_locator_binding(
            self.metadata.destination_parent(),
            &self.destination_parent,
            self.metadata.destination_parent_identity(),
        )?;
        verify_identity(&self.source_parent, self.metadata.source_parent_identity())?;
        verify_identity(
            &self.destination_parent,
            self.metadata.destination_parent_identity(),
        )?;
        verify_named_identity(
            &self.source_parent,
            self.metadata.source_basename(),
            self.metadata.root_identity(),
        )?;
        verify_identity(&self.root_check_fd, self.metadata.root_identity())?;
        self.source_parent_held
            .verify_current_mode(self.source_parent_held.mode())
            .map_err(PreparedRootError::SourceParentChanged)?;
        self.destination_parent_held
            .verify_namespace_exclusive()
            .map_err(classify_destination_parent)?;
        require_absent(
            &self.destination_parent,
            self.metadata.destination_basename(),
        )
    }

    fn verify_before_rename(&self) -> Result<(), PreparedRootError> {
        self.verify_before_sealing()?;
        self.source_parent_held
            .verify_namespace_exclusive()
            .map_err(classify_source_parent)
    }

    fn verify_confirmed_collision(&self) -> Result<(), PreparedRootError> {
        self.source_anchor.verify_locator_binding(
            self.metadata.source_parent(),
            &self.source_parent,
            self.metadata.source_parent_identity(),
        )?;
        self.destination_anchor.verify_locator_binding(
            self.metadata.destination_parent(),
            &self.destination_parent,
            self.metadata.destination_parent_identity(),
        )?;
        verify_identity(&self.source_parent, self.metadata.source_parent_identity())?;
        verify_identity(
            &self.destination_parent,
            self.metadata.destination_parent_identity(),
        )?;
        verify_named_identity(
            &self.source_parent,
            self.metadata.source_basename(),
            self.metadata.root_identity(),
        )?;
        verify_identity(&self.root_check_fd, self.metadata.root_identity())?;
        self.source_parent_held
            .verify_namespace_exclusive()
            .map_err(classify_source_parent)?;
        self.destination_parent_held
            .verify_namespace_exclusive()
            .map_err(classify_destination_parent)?;
        require_occupied(
            &self.destination_parent,
            self.metadata.destination_basename(),
        )
    }
}

/// One-use proof minted only after a successful exact rename, destination
/// postcheck, and both parent-directory fsyncs.
pub(crate) struct ParentsSyncedAppliedRename {
    identity: StrongObjectIdentity,
}

impl ParentsSyncedAppliedRename {
    pub(crate) fn identity(&self) -> StrongObjectIdentity {
        self.identity
    }
}

/// One-use proof minted only after a failed no-replace syscall and a fresh
/// strong-identity check of the original root at the source name.
pub(crate) struct FreshlyConfirmedSourceResident {
    identity: StrongObjectIdentity,
}

impl FreshlyConfirmedSourceResident {
    pub(crate) fn identity(&self) -> StrongObjectIdentity {
        self.identity
    }
}

#[derive(Debug)]
enum PostSealProducerError {
    Binding(PreparedRootError),
    Collect(HeldTreeV3CollectError<TreeSidecarError>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StagingRenameError {
    #[error("startup recovery or another active transaction blocks new staging")]
    StartupBlocked,
    #[error("prepared binding no longer matches its held namespace: {0}")]
    Binding(#[from] PreparedRootError),
    #[error("staging WAL operation failed before a confirmed rename: {0}")]
    Wal(#[from] AppendError),
    #[error("source-parent seal failed: {0}")]
    ParentSeal(#[from] LocalModeExecutionError),
    #[error("source-parent seal was confirmed not applied")]
    ParentSealNotApplied,
    #[error("held-tree operation failed: {0}")]
    HeldTree(#[from] HeldTreeError),
    #[error("held-tree seal failed: {0}")]
    TreeSeal(#[from] HeldTreeSealError),
    #[error("held-tree sidecar publication or verification failed: {0}")]
    Sidecar(#[from] TreeSidecarError),
    #[error("held-tree manifest sidecar codec failed: {0}")]
    ManifestCodec(#[from] ManifestV3CodecError),
    #[error("published held-tree sidecar does not match the exact manifest fingerprint")]
    ManifestMismatch,
    #[error("rename was confirmed not applied and the exact outcome is durable: {0}")]
    ConfirmedNotApplied(#[source] io::Error),
    #[error("rename outcome is unknown after syscall failure: {0}")]
    RenameOutcomeUnknown(#[source] io::Error),
    #[error("rename applied but destination/source postconditions could not be proved: {0}")]
    AppliedButUnverified(#[source] PreparedRootError),
    #[error("rename applied but {which} parent directory fsync failed: {source}")]
    ParentSync {
        which: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("rename applied and parents synced but its exact outcome was not durable: {0}")]
    AppliedOutcomeNotDurable(#[source] AppendError),
    #[error("applied rename outcome is durable but StagedUnverified was not durable: {0}")]
    StagedStateNotDurable(#[source] AppendError),
}

/// Nonforgeable live result of the held-FD seal/rename sequence. It retains
/// the exact leased WAL, both parents, the staged root, and the data-only tree
/// inventory with its root reopen anchor, but exposes no namespace, restore,
/// commit, purge, unlink, or deletion operation.
pub(crate) struct StagedUnverifiedTree<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    _source_parent: OwnedFd,
    _destination_parent: OwnedFd,
    _staged_root: OwnedFd,
    _source_parent_seal: HeldLocalBackendEvidence,
    _destination_parent_evidence: HeldLocalBackendEvidence,
    _sealed_tree: StreamedV3Inventory,
}

impl StagedUnverifiedTree<'_> {
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

pub(crate) fn execute_prepared_rename<'a>(
    wal: &'a mut SealWal<RecoverySession>,
    sidecars: &TreeSidecarStore,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    mut binding: PreparedRootBinding,
) -> Result<StagedUnverifiedTree<'a>, StagingRenameError> {
    // Defense in depth: sibling modules cannot bypass the engine wrapper's
    // startup gate by calling this core-private executor directly.
    if *startup_blocked || !wal.can_begin_staging_transaction() {
        return Err(StagingRenameError::StartupBlocked);
    }
    binding.verify_before_sealing()?;
    #[cfg(test)]
    if FAIL_WAL_STEP.with(|failure| failure.get() == Some("begin-poison")) {
        wal.poison_for_test();
    }
    wal.begin_staging(transaction, binding.metadata.clone())?;
    *startup_blocked = true;

    wal.transition_staging_foundation(transaction, TransactionState::ParentSealIntent)?;
    let parent_seal = execute_staging_local_mode_mutation(
        wal,
        &mut binding.source_parent_held,
        LocalModeMutationRequest {
            transaction,
            mutation_id: 0,
            locator: RecoveryLocator::held_staging(
                binding
                    .metadata
                    .source_parent()
                    .relative_path()
                    .to_path_buf(),
                binding.metadata.filesystem_id().to_owned(),
                binding
                    .metadata
                    .source_parent_identity()
                    .incarnation()
                    .get(),
            ),
            transform: LocalModeTransform::Seal {
                acquire_owner_write_search: true,
            },
        },
    )?;
    if parent_seal == LocalModeMutationResult::ConfirmedNotApplied {
        return Err(StagingRenameError::ParentSealNotApplied);
    }
    binding
        .source_parent_held
        .verify_namespace_exclusive()
        .map_err(classify_source_parent)?;
    wal.transition_staging_foundation(transaction, TransactionState::ParentSealed)?;

    let produced =
        sidecars.build_sorted_manifest_scratch_with_output(wal, transaction, |emit_record| {
            let parent = certify_duplicate(&binding.source_parent)
                .map_err(PostSealProducerError::Binding)?;
            PendingV3Inventory::collect_pre_seal(
                parent,
                binding.metadata.source_basename(),
                crate::backend::held_tree_protected_names(),
                HeldTreeLimits::default(),
                emit_record,
            )
            .map_err(PostSealProducerError::Collect)
        });
    let (mut pre_seal_scratch, collected_pre_seal) = match produced {
        Ok(produced) => produced,
        Err(TreeManifestScratchBuildError::Sidecar(error)) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::Sidecar(error));
        }
        Err(TreeManifestScratchBuildError::Produce(PostSealProducerError::Binding(error))) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::Binding(error));
        }
        Err(TreeManifestScratchBuildError::Produce(PostSealProducerError::Collect(error))) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(match error {
                HeldTreeV3CollectError::Tree(error) => StagingRenameError::HeldTree(error),
                HeldTreeV3CollectError::Codec(error) => StagingRenameError::ManifestCodec(error),
                HeldTreeV3CollectError::Emit(error) => StagingRenameError::Sidecar(error),
            });
        }
    };
    let directory_count = collected_pre_seal.directory_count();
    let directory_plan_build =
        sidecars.build_directory_plan_with_output(wal, transaction, directory_count, |emit| {
            collected_pre_seal.emit_directory_plan(emit)
        });
    let (mut directory_plan, pending_pre_seal) = match directory_plan_build {
        Ok(result) => result,
        Err(TreeManifestScratchBuildError::Sidecar(error)) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::Sidecar(error));
        }
        Err(TreeManifestScratchBuildError::Produce(error)) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(match error {
                HeldTreeV3CollectError::Tree(error) => StagingRenameError::HeldTree(error),
                HeldTreeV3CollectError::Codec(error) => StagingRenameError::ManifestCodec(error),
                HeldTreeV3CollectError::Emit(error) => StagingRenameError::Sidecar(error),
            });
        }
    };
    if let Err(error) = directory_plan.authenticate() {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::Sidecar(error));
    }
    let pre_seal_manifest =
        match sidecars.fingerprint_sorted_manifest_scratch(wal, transaction, &mut pre_seal_scratch)
        {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::Sidecar(error));
            }
        };
    let pre_seal_finalizer = match pending_pre_seal.into_finalizer(pre_seal_manifest) {
        Ok(finalizer) => finalizer,
        Err(error) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    let hardlink_build = sidecars.build_sorted_hardlink_scratch_from_manifest(
        wal,
        transaction,
        &mut pre_seal_scratch,
        pre_seal_manifest,
        pre_seal_finalizer,
        |finalizer, record, emit_hardlink| finalizer.observe(record, emit_hardlink),
    );
    let (pre_seal_hardlink_scratch, pre_seal_finalizer) = match hardlink_build {
        Ok(result) => result,
        Err(error) => {
            // A complete scratch integrity pass wins over a tree/fold failure;
            // no directory mutation has occurred yet.
            let authenticated = sidecars.fingerprint_sorted_manifest_scratch(
                wal,
                transaction,
                &mut pre_seal_scratch,
            );
            let primary = match error {
                TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Tree(error)) => {
                    StagingRenameError::HeldTree(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Codec(error)) => {
                    StagingRenameError::ManifestCodec(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Emit(error)) => {
                    StagingRenameError::Sidecar(error)
                }
            };
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated.map_err(StagingRenameError::Sidecar)?;
            return Err(primary);
        }
    };
    let pre_seal_hardlinks = sidecars.fold_sorted_hardlink_scratch_preserving_manifest(
        wal,
        transaction,
        pre_seal_hardlink_scratch,
        HardlinkTopologyFold::new(),
        |groups, record| {
            let record = decode_hardlink_scratch_record(record)
                .map_err(HeldTreeV3CollectError::<std::convert::Infallible>::Codec)?
                .ok_or(HeldTreeV3CollectError::Codec(
                    ManifestV3CodecError::InvalidTag,
                ))?;
            groups.observe(record).map_err(HeldTreeV3CollectError::Tree)
        },
    );
    let pre_seal_hardlinks = match pre_seal_hardlinks {
        Ok(fold) => match fold.finish() {
            Ok(topology) => topology,
            Err(error) => {
                let authenticated = sidecars.fingerprint_sorted_manifest_scratch(
                    wal,
                    transaction,
                    &mut pre_seal_scratch,
                );
                let _ = sidecars.cleanup_unpublished(wal);
                authenticated.map_err(StagingRenameError::Sidecar)?;
                return Err(StagingRenameError::HeldTree(error));
            }
        },
        Err(error) => {
            let primary = match error {
                TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Tree(error)) => {
                    StagingRenameError::HeldTree(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Codec(_)) => {
                    StagingRenameError::Sidecar(TreeSidecarError::InvalidScratch(
                        "hardlink scratch record validation failed",
                    ))
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Emit(never)) => match never {},
            };
            let authenticated = sidecars.fingerprint_sorted_manifest_scratch(
                wal,
                transaction,
                &mut pre_seal_scratch,
            );
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated.map_err(StagingRenameError::Sidecar)?;
            return Err(primary);
        }
    };
    let mut tree = match pre_seal_finalizer.finish(pre_seal_hardlinks) {
        Ok(tree) => tree,
        Err(error) => {
            let authenticated = sidecars.fingerprint_sorted_manifest_scratch(
                wal,
                transaction,
                &mut pre_seal_scratch,
            );
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated.map_err(StagingRenameError::Sidecar)?;
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    #[cfg(test)]
    AFTER_PRE_SEAL_SCRATCH_READY.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let mut plan_records = 0_u64;
    let plan_validation = directory_plan.for_each_forward(|record| {
        let record = decode_pre_seal_directory_plan_record(record)
            .map_err(HeldTreeV3CollectError::<std::convert::Infallible>::Codec)?;
        tree.validate_directory_plan_record(&record, plan_records)
            .map_err(HeldTreeV3CollectError::Tree)?;
        plan_records = plan_records
            .checked_add(1)
            .ok_or(HeldTreeV3CollectError::Tree(HeldTreeError::PostChanged(
                PathBuf::new(),
            )))?;
        Ok(())
    });
    if let Err(error) = plan_validation {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(match error {
            TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
            TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Tree(error)) => {
                StagingRenameError::HeldTree(error)
            }
            TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Codec(error)) => {
                StagingRenameError::ManifestCodec(error)
            }
            TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Emit(never)) => match never {},
        });
    }
    if plan_records != tree.directory_count() || plan_records != directory_plan.record_count() {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::HeldTree(HeldTreeError::PostChanged(
            PathBuf::new(),
        )));
    }
    if tree.root_strong_identity() != binding.metadata.root_identity() {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::Binding(
            PreparedRootError::BackendOrMountChanged,
        ));
    }
    if let Err(error) =
        wal.transition_staging_foundation(transaction, TransactionState::TreeSealIntent)
    {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::Wal(error));
    }
    #[cfg(test)]
    AFTER_PRE_SEAL_DIRECTORY_PLAN_PREFLIGHT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook(&directory_plan);
        }
    });
    let source_root = binding
        .metadata
        .source_parent()
        .relative_path()
        .join(binding.metadata.source_basename());
    let mut mutation_id = 1_u64;
    loop {
        let encoded = match directory_plan.next_reverse() {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::Sidecar(error));
            }
        };
        let target = match decode_pre_seal_directory_plan_record(&encoded) {
            Ok(record) => record,
            Err(error) => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::ManifestCodec(error));
            }
        };
        let mut chain = Vec::new();
        let chain_result = directory_plan.for_each_forward(|encoded| {
            let candidate = decode_pre_seal_directory_plan_record(encoded)
                .map_err(HeldTreeV3CollectError::<std::convert::Infallible>::Codec)?;
            tree.consider_directory_plan_ancestor(&target, candidate, &mut chain)
                .map_err(HeldTreeV3CollectError::Tree)
        });
        if let Err(error) = chain_result {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(match error {
                TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Tree(error)) => {
                    StagingRenameError::HeldTree(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Codec(error)) => {
                    StagingRenameError::ManifestCodec(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Emit(never)) => match never {},
            });
        }
        if let Err(error) = tree.seal_directory_for_staging(
            wal,
            transaction,
            &source_root,
            binding.metadata.filesystem_id(),
            mutation_id,
            &target,
            &chain,
        ) {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::TreeSeal(error));
        }
        mutation_id = match mutation_id.checked_add(1) {
            Some(next) => next,
            None => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::TreeSeal(
                    HeldTreeSealError::MutationIdExhausted,
                ));
            }
        };
    }
    if let Err(error) = directory_plan.finish() {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::Sidecar(error));
    }
    #[cfg(test)]
    AFTER_PRE_SEAL_DIRECTORY_SEALS.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });

    let mut expectation_builder = tree.post_seal_expectation_builder();
    let expectation_fold = sidecars.read_sorted_manifest_scratch(
        wal,
        transaction,
        pre_seal_manifest,
        &mut pre_seal_scratch,
        (),
        |(), record, wal_view| {
            expectation_builder.observe(&tree, record, |path, device, inode, incarnation| {
                wal_view.applied_tree_seal_mode(
                    transaction,
                    &source_root.join(path),
                    device,
                    inode,
                    incarnation,
                    record.mode,
                )
            })?;
            Ok(())
        },
    );
    if let Err(error) = expectation_fold {
        let primary = match error {
            TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
            TreeSidecarFoldError::Fold(error) => StagingRenameError::HeldTree(error),
        };
        let authenticated =
            sidecars.fingerprint_sorted_manifest_scratch(wal, transaction, &mut pre_seal_scratch);
        let _ = sidecars.cleanup_unpublished(wal);
        authenticated.map_err(StagingRenameError::Sidecar)?;
        return Err(primary);
    }
    let post_seal_expectation = match tree.finish_post_seal_expectation(expectation_builder) {
        Ok(expectation) => expectation,
        Err(error) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    if let Err(error) = sidecars.discard_sorted_manifest_scratch(
        wal,
        transaction,
        pre_seal_manifest,
        pre_seal_scratch,
    ) {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(StagingRenameError::Sidecar(error));
    }
    #[cfg(test)]
    AFTER_PRE_SEAL_INVENTORY_DROPPED.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let produced =
        sidecars.build_sorted_manifest_scratch_with_output(wal, transaction, |emit_record| {
            let parent = certify_duplicate(&binding.source_parent)
                .map_err(PostSealProducerError::Binding)?;
            PendingV3Inventory::collect(
                parent,
                binding.metadata.source_basename(),
                crate::backend::held_tree_protected_names(),
                HeldTreeLimits::default(),
                emit_record,
            )
            .map_err(PostSealProducerError::Collect)
        });
    let (mut scratch, pending) = match produced {
        Ok(produced) => produced,
        Err(TreeManifestScratchBuildError::Sidecar(error)) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::Sidecar(error));
        }
        Err(TreeManifestScratchBuildError::Produce(PostSealProducerError::Binding(error))) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::Binding(error));
        }
        Err(TreeManifestScratchBuildError::Produce(PostSealProducerError::Collect(error))) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(match error {
                HeldTreeV3CollectError::Tree(error) => StagingRenameError::HeldTree(error),
                HeldTreeV3CollectError::Codec(error) => StagingRenameError::ManifestCodec(error),
                HeldTreeV3CollectError::Emit(error) => StagingRenameError::Sidecar(error),
            });
        }
    };
    let pending_manifest =
        match sidecars.fingerprint_sorted_manifest_scratch(wal, transaction, &mut scratch) {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::Sidecar(error));
            }
        };
    let finalizer = match pending.into_finalizer(pending_manifest) {
        Ok(finalizer) => finalizer,
        Err(error) => {
            let _ = sidecars.cleanup_unpublished(wal);
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    // The exact scratch is completely merged, decoded, fingerprint-matched,
    // synced, and published before any record drives held-tree reobservation.
    // Failure below leaves only a self-authenticating unreferenced final orphan;
    // it still cannot authorize recovery because the WAL reference is written last.
    let commitment =
        match sidecars.publish_sorted_manifest_scratch(wal, transaction, pending_manifest, scratch)
        {
            Ok(commitment) => commitment,
            Err(error) => {
                let _ = sidecars.cleanup_unpublished(wal);
                return Err(StagingRenameError::Sidecar(error));
            }
        };
    let hardlink_build =
        sidecars.build_sorted_hardlink_scratch_with_output(wal, transaction, |emit_hardlink| {
            emit_hardlink(hardlink_scratch_sentinel_record()).map_err(|error| {
                TreeManifestFoldError::Fold(HeldTreeV3CollectError::Emit(error))
            })?;
            sidecars.read_manifest_v3_fold(
                commitment,
                pending_manifest,
                finalizer,
                |finalizer, record| finalizer.observe(record, emit_hardlink),
            )
        });
    let (hardlink_scratch, (finalizer, authenticated_manifest)) = match hardlink_build {
        Ok(result) => result,
        Err(error) => {
            let primary = match error {
                TreeManifestScratchBuildError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Sidecar(error)) => {
                    StagingRenameError::Sidecar(error)
                }
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Codec(error)) => {
                    StagingRenameError::ManifestCodec(error)
                }
                TreeManifestScratchBuildError::Produce(
                    TreeManifestFoldError::FingerprintMismatch,
                ) => StagingRenameError::ManifestMismatch,
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Fold(
                    HeldTreeV3CollectError::Tree(error),
                )) => StagingRenameError::HeldTree(error),
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Fold(
                    HeldTreeV3CollectError::Codec(error),
                )) => StagingRenameError::ManifestCodec(error),
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Fold(
                    HeldTreeV3CollectError::Emit(error),
                )) => StagingRenameError::Sidecar(error),
            };
            let authenticated =
                authenticate_streamed_v3_manifest(sidecars, commitment, pending_manifest);
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated?;
            return Err(primary);
        }
    };
    let hardlink_fold = sidecars.fold_sorted_hardlink_scratch(
        wal,
        transaction,
        hardlink_scratch,
        HardlinkTopologyFold::new(),
        |groups, record| {
            let record = decode_hardlink_scratch_record(record)
                .map_err(HeldTreeV3CollectError::<std::convert::Infallible>::Codec)?
                .ok_or(HeldTreeV3CollectError::Codec(
                    ManifestV3CodecError::InvalidTag,
                ))?;
            groups.observe(record).map_err(HeldTreeV3CollectError::Tree)
        },
    );
    let hardlink_fold = match hardlink_fold {
        Ok(fold) => fold,
        Err(error) => {
            let primary = match error {
                TreeSidecarFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Tree(error)) => {
                    StagingRenameError::HeldTree(error)
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Codec(_)) => {
                    StagingRenameError::Sidecar(TreeSidecarError::InvalidScratch(
                        "hardlink scratch record validation failed",
                    ))
                }
                TreeSidecarFoldError::Fold(HeldTreeV3CollectError::Emit(never)) => match never {},
            };
            authenticate_streamed_v3_manifest(sidecars, commitment, pending_manifest)?;
            return Err(primary);
        }
    };
    let hardlinks = match hardlink_fold.finish() {
        Ok(topology) => topology,
        Err(error) => {
            authenticate_streamed_v3_manifest(sidecars, commitment, pending_manifest)?;
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    let post_seal = match finalizer.finish(authenticated_manifest, hardlinks) {
        Ok(post_seal) => post_seal,
        Err(error) => {
            authenticate_streamed_v3_manifest(sidecars, commitment, pending_manifest)?;
            return Err(StagingRenameError::HeldTree(error));
        }
    };
    let fingerprint = post_seal_expectation.verify(&post_seal)?;
    let manifest = DurableTreeManifest {
        schema_version: fingerprint.schema_version,
        entry_count: fingerprint.entry_count,
        sha256: fingerprint.sha256,
    };
    if manifest != pending_manifest {
        return Err(StagingRenameError::ManifestMismatch);
    }
    rewalk_streamed_v3_structure(
        wal,
        sidecars,
        transaction,
        commitment,
        pending_manifest,
        &post_seal,
    )?;
    #[cfg(test)]
    if FAIL_WAL_STEP.with(|failure| failure.get() == Some("manifest-reference")) {
        wal.poison_for_test();
    }
    wal.complete_tree_manifest_with_sidecar(transaction, manifest, commitment)?;
    wal.transition_staging_foundation(transaction, TransactionState::TreeSealed)?;

    rewalk_streamed_v3_structure(
        wal,
        sidecars,
        transaction,
        commitment,
        pending_manifest,
        &post_seal,
    )?;
    binding.verify_before_rename()?;
    wal.record_rename_intent(transaction)?;
    #[cfg(test)]
    BEFORE_RENAME.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });

    if let Err(syscall) = rename_noreplace(&binding) {
        // Only atomic no-replace collision is classified as definitely not
        // applied. Unsupported flags, I/O errors, interrupts, and every other
        // result remain ambiguous even if a best-effort source probe succeeds.
        if syscall.raw_os_error() == Some(libc::EEXIST)
            && binding.verify_confirmed_collision().is_ok()
        {
            wal.record_confirmed_not_applied_rename(
                transaction,
                FreshlyConfirmedSourceResident {
                    identity: binding.metadata.root_identity(),
                },
            )?;
            return Err(StagingRenameError::ConfirmedNotApplied(syscall));
        }
        return Err(StagingRenameError::RenameOutcomeUnknown(syscall));
    }

    #[cfg(test)]
    AFTER_RENAME.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    verify_post_rename(&binding).map_err(StagingRenameError::AppliedButUnverified)?;
    sync_parent(&binding.source_parent, "source").map_err(|source| {
        StagingRenameError::ParentSync {
            which: "source",
            source,
        }
    })?;
    sync_parent(&binding.destination_parent, "destination").map_err(|source| {
        StagingRenameError::ParentSync {
            which: "destination",
            source,
        }
    })?;
    // The durable applied proof binds not only the held objects and fsyncs, but
    // also the current authenticated locator attachments after both syncs.
    verify_post_rename(&binding).map_err(StagingRenameError::AppliedButUnverified)?;
    #[cfg(test)]
    if FAIL_WAL_STEP.with(|failure| failure.get() == Some("applied-outcome")) {
        return Err(StagingRenameError::AppliedOutcomeNotDurable(
            AppendError::Io(io::Error::from_raw_os_error(libc::EIO)),
        ));
    }
    wal.record_applied_synced_rename(
        transaction,
        ParentsSyncedAppliedRename {
            identity: binding.metadata.root_identity(),
        },
    )
    .map_err(StagingRenameError::AppliedOutcomeNotDurable)?;
    #[cfg(test)]
    if FAIL_WAL_STEP.with(|failure| failure.get() == Some("staged-state")) {
        return Err(StagingRenameError::StagedStateNotDurable(AppendError::Io(
            io::Error::from_raw_os_error(libc::EIO),
        )));
    }
    wal.transition_staging_foundation(transaction, TransactionState::StagedUnverified)
        .map_err(StagingRenameError::StagedStateNotDurable)?;

    Ok(StagedUnverifiedTree {
        wal,
        startup_blocked,
        transaction,
        _source_parent: binding.source_parent,
        _destination_parent: binding.destination_parent,
        _staged_root: binding.root_check_fd,
        _source_parent_seal: binding.source_parent_held,
        _destination_parent_evidence: binding.destination_parent_held,
        _sealed_tree: post_seal,
    })
}

fn authenticate_streamed_v3_manifest(
    sidecars: &TreeSidecarStore,
    commitment: TreeSidecarCommitment,
    manifest: DurableTreeManifest,
) -> Result<(), StagingRenameError> {
    sidecars
        .read_manifest_v3_fold(commitment, manifest, (), |(), _| {
            Ok::<(), std::convert::Infallible>(())
        })
        .map(|_| ())
        .map_err(|error| match error {
            TreeManifestFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
            TreeManifestFoldError::Codec(error) => StagingRenameError::ManifestCodec(error),
            TreeManifestFoldError::FingerprintMismatch => StagingRenameError::ManifestMismatch,
            TreeManifestFoldError::Fold(never) => match never {},
        })
}

struct StreamedStructureComparison {
    actual: Option<StructureEvidence>,
    scratch_error: Option<TreeSidecarError>,
    first_tree_error: Option<HeldTreeError>,
}

impl StreamedStructureComparison {
    fn observe(
        &mut self,
        cursor: &mut TreeStructureScratchCursor,
        expected: crate::backend::held::ManifestV3Record<'_>,
    ) {
        let expected = structure_evidence_from_v3_record(expected);
        loop {
            if self.actual.is_none() && self.scratch_error.is_none() {
                match cursor.next() {
                    Ok(actual) => self.actual = actual,
                    Err(error) => self.scratch_error = Some(error),
                }
            }
            if self.scratch_error.is_some() {
                return;
            }
            let Some(actual) = self.actual.as_ref() else {
                self.record_tree_error(HeldTreeError::PostRemoved(expected.path().to_path_buf()));
                return;
            };
            match expected.path().cmp(actual.path()) {
                std::cmp::Ordering::Less => {
                    self.record_tree_error(HeldTreeError::PostRemoved(
                        expected.path().to_path_buf(),
                    ));
                    return;
                }
                std::cmp::Ordering::Greater => {
                    let path = actual.path().to_path_buf();
                    self.actual = None;
                    self.record_tree_error(HeldTreeError::PostAdded(path));
                }
                std::cmp::Ordering::Equal => {
                    if expected != *actual {
                        self.record_tree_error(HeldTreeError::PostChanged(
                            expected.path().to_path_buf(),
                        ));
                    }
                    self.actual = None;
                    return;
                }
            }
        }
    }

    fn record_tree_error(&mut self, error: HeldTreeError) {
        if self.first_tree_error.is_none() {
            self.first_tree_error = Some(error);
        }
    }
}

fn rewalk_streamed_v3_structure(
    wal: &mut SealWal<RecoverySession>,
    sidecars: &TreeSidecarStore,
    transaction: TransactionId,
    commitment: TreeSidecarCommitment,
    manifest: DurableTreeManifest,
    tree: &StreamedV3Inventory,
) -> Result<(), StagingRenameError> {
    // A corrupt published baseline must win over a traversal/scratch producer
    // error. Recheck it again on every early exit before the authenticated fold.
    sidecars.verify(commitment)?;
    #[cfg(test)]
    AFTER_STRUCTURE_SIDECAR_PREFLIGHT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let produced =
        sidecars.build_sorted_structure_scratch_with_output(wal, transaction, |emit_record| {
            tree.stream_structure_records(emit_record)
        });
    let (scratch, ()) = match produced {
        Ok(produced) => produced,
        Err(error) => {
            let authenticated = authenticate_streamed_v3_manifest(sidecars, commitment, manifest);
            let primary = match error {
                TreeManifestScratchBuildError::Sidecar(error) => StagingRenameError::Sidecar(error),
                TreeManifestScratchBuildError::Produce(HeldTreeV3CollectError::Tree(error)) => {
                    StagingRenameError::HeldTree(error)
                }
                TreeManifestScratchBuildError::Produce(HeldTreeV3CollectError::Codec(error)) => {
                    StagingRenameError::ManifestCodec(error)
                }
                TreeManifestScratchBuildError::Produce(HeldTreeV3CollectError::Emit(error)) => {
                    StagingRenameError::Sidecar(error)
                }
            };
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated?;
            return Err(primary);
        }
    };
    let cursor = match sidecars.open_sorted_structure_scratch_cursor(wal, transaction, scratch) {
        Ok(cursor) => cursor,
        Err(error) => {
            let authenticated = authenticate_streamed_v3_manifest(sidecars, commitment, manifest);
            let _ = sidecars.cleanup_unpublished(wal);
            authenticated?;
            return Err(StagingRenameError::Sidecar(error));
        }
    };
    let mut cursor = cursor;
    let comparison = StreamedStructureComparison {
        actual: None,
        scratch_error: None,
        first_tree_error: None,
    };
    let mut comparison = comparison;
    let sidecar_result =
        sidecars.read_manifest_v3_fold(commitment, manifest, (), |(), expected| {
            comparison.observe(&mut cursor, expected);
            Ok::<(), std::convert::Infallible>(())
        });
    if let Err(error) = sidecar_result {
        let primary = match error {
            TreeManifestFoldError::Sidecar(error) => StagingRenameError::Sidecar(error),
            TreeManifestFoldError::Codec(error) => StagingRenameError::ManifestCodec(error),
            TreeManifestFoldError::FingerprintMismatch => StagingRenameError::ManifestMismatch,
            TreeManifestFoldError::Fold(never) => match never {},
        };
        let _ = sidecars.finish_sorted_structure_scratch_cursor(wal, cursor);
        return Err(primary);
    }

    while comparison.actual.is_some()
        || (comparison.scratch_error.is_none()
            && cursor
                .next()
                .map(|actual| {
                    comparison.actual = actual;
                    comparison.actual.is_some()
                })
                .unwrap_or_else(|error| {
                    comparison.scratch_error = Some(error);
                    false
                }))
    {
        if let Some(actual) = comparison.actual.take() {
            comparison.record_tree_error(HeldTreeError::PostAdded(actual.path().to_path_buf()));
        }
    }

    if let Err(error) = sidecars.finish_sorted_structure_scratch_cursor(wal, cursor) {
        return Err(StagingRenameError::Sidecar(error));
    }
    if let Some(error) = comparison.scratch_error {
        return Err(StagingRenameError::Sidecar(error));
    }
    if let Some(error) = comparison.first_tree_error {
        return Err(StagingRenameError::HeldTree(error));
    }
    tree.finish_streamed_structure_rewalk()?;
    Ok(())
}

fn verify_post_rename(binding: &PreparedRootBinding) -> Result<(), PreparedRootError> {
    binding.source_anchor.verify_locator_binding(
        binding.metadata.source_parent(),
        &binding.source_parent,
        binding.metadata.source_parent_identity(),
    )?;
    binding.destination_anchor.verify_locator_binding(
        binding.metadata.destination_parent(),
        &binding.destination_parent,
        binding.metadata.destination_parent_identity(),
    )?;
    require_absent(&binding.source_parent, binding.metadata.source_basename())?;
    verify_named_identity(
        &binding.destination_parent,
        binding.metadata.destination_basename(),
        binding.metadata.root_identity(),
    )?;
    verify_identity(&binding.root_check_fd, binding.metadata.root_identity())?;
    verify_identity(
        &binding.source_parent,
        binding.metadata.source_parent_identity(),
    )?;
    verify_identity(
        &binding.destination_parent,
        binding.metadata.destination_parent_identity(),
    )
}

fn classify_source_parent(error: LocalModeRevalidationFailure) -> PreparedRootError {
    if error == LocalModeRevalidationFailure::NamespaceWritersPresent {
        PreparedRootError::SourceParentNotExclusive
    } else {
        PreparedRootError::SourceParentChanged(error)
    }
}

fn classify_destination_parent(error: LocalModeRevalidationFailure) -> PreparedRootError {
    if error == LocalModeRevalidationFailure::NamespaceWritersPresent {
        PreparedRootError::DestinationParentNotExclusive
    } else {
        PreparedRootError::DestinationParentChanged(error)
    }
}

fn rename_noreplace(binding: &PreparedRootBinding) -> io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = RENAME_ERROR.with(|error| error.get()) {
        return Err(io::Error::from_raw_os_error(errno));
    }
    rustix::fs::renameat_with(
        &binding.source_parent,
        binding.metadata.source_basename(),
        &binding.destination_parent,
        binding.metadata.destination_basename(),
        RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

fn sync_parent(fd: &OwnedFd, _which: &'static str) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_PARENT_SYNC.with(|failure| failure.get() == Some(_which)) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    rustix::fs::fsync(fd).map_err(io::Error::from)
}

fn certify_duplicate(fd: &OwnedFd) -> Result<HeldLocalBackendEvidence, PreparedRootError> {
    let duplicate = rustix::io::dup(fd)
        .map_err(io::Error::from)
        .map_err(PreparedRootError::Io)?;
    certify_held_fd(duplicate).map_err(PreparedRootError::Certification)
}

fn open_directory_at(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, PreparedRootError> {
    rustix::fs::openat(parent, name, OPEN_DIRECTORY, Mode::empty())
        .map_err(io::Error::from)
        .map_err(PreparedRootError::Io)
}

fn verify_named_identity(
    parent: &OwnedFd,
    name: &OsStr,
    expected: StrongObjectIdentity,
) -> Result<(), PreparedRootError> {
    let current = open_directory_at(parent, name)?;
    verify_identity(&current, expected)
}

fn verify_identity(fd: &OwnedFd, expected: StrongObjectIdentity) -> Result<(), PreparedRootError> {
    if strong_identity_fd(fd)? == expected {
        Ok(())
    } else {
        Err(PreparedRootError::BackendOrMountChanged)
    }
}

fn require_absent(parent: &OwnedFd, name: &OsStr) -> Result<(), PreparedRootError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(PreparedRootError::Io(io::Error::from(error))),
        Ok(_) => Err(PreparedRootError::DestinationOccupied),
    }
}

fn require_occupied(parent: &OwnedFd, name: &OsStr) -> Result<(), PreparedRootError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::NOENT => {
            Err(PreparedRootError::DestinationOccupied)
        }
        Err(error) => Err(PreparedRootError::Io(io::Error::from(error))),
    }
}

fn normal_basename(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(test)]
mod tests;
