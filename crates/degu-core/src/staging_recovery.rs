//! Crash-recovery rebind and execution boundary for sealed staging.
//!
//! Durable paths and inode numbers are never promoted to authority. A recovery
//! capability owns freshly opened parent/object descriptors, re-certifies the
//! exact binding against backend, mount, filesystem-id, dev/inode and birth-time,
//! and rechecks that binding immediately before any held-FD mode restoration.

use crate::authority::TransactionState;
use crate::local_backend::{
    CertificationError, CertifiedLocalBackend, HeldLocalBackendEvidence, certify_held_fd,
    certify_held_fd_backend,
};
use crate::seal_executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeTransform, RecoveryLocator,
    execute_staging_local_mode_mutation,
};
use crate::seal_wal::{
    AppendError, DurablePermission, PermissionResolution, RecoverySession, RecoveryWork,
    ResolveError, SealWal, StagingLocator, StagingTransactionMetadata, StrongObjectIdentity,
    TransactionId,
};
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
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
}

#[derive(Debug)]
pub(crate) struct RecoveryAnchors {
    pub(crate) source: RecoveryFilesystemAnchor,
    pub(crate) destination: RecoveryFilesystemAnchor,
}

/// One exact, freshly rebound object. The parent and object descriptors are
/// retained together; the value is neither Clone nor Copy and is consumed by
/// restoration.
#[derive(Debug)]
struct ReboundObject {
    parent: OwnedFd,
    object_check_fd: OwnedFd,
    basename: OsString,
    relative_path: PathBuf,
    identity: StrongObjectIdentity,
    held: HeldLocalBackendEvidence,
}

impl ReboundObject {
    fn verify_fresh_binding(&self) -> Result<(), RecoveryRebindError> {
        let current = open_directory_at(&self.parent, &self.basename)?;
        if strong_identity_fd(&current)? != self.identity
            || strong_identity_fd(&self.object_check_fd)? != self.identity
            || !self.held.is_live()
        {
            return Err(RecoveryRebindError::BindingChanged);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ReboundRestore {
    transaction: TransactionId,
    source_parent_last: PathBuf,
    entries: Vec<(DurablePermission, ReboundObject)>,
    completion: TransactionState,
}

/// Capability returned for post-rename verification. It keeps the exact
/// destination parent/name and staged root descriptors live but exposes no
/// chmod, unlink, rename, or purge operation.
pub(crate) struct CertifiedStagedRecovery<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    root: ReboundObject,
}

impl CertifiedStagedRecovery<'_> {
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
}

pub(crate) enum StartupRecoveryCapability<'a> {
    Restore(RecoveryRestoreSession<'a>),
    /// Nonforgeable continuation for a future staged-tree verifier. Merely
    /// checking liveness never clears the startup mutation block.
    PendingVerification(CertifiedStagedRecovery<'a>),
}

/// Owns all rebound FDs and borrows the exact leased WAL until ordered restore
/// completes or the session is dropped.
pub(crate) struct RecoveryRestoreSession<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    restore: ReboundRestore,
}

impl RecoveryRestoreSession<'_> {
    pub(crate) fn execute(mut self) -> Result<(), RecoveryRebindError> {
        let transaction = self.restore.transaction;
        let current = self.wal.transaction_state(transaction);
        if self.restore.completion == TransactionState::Restored
            && current != Some(TransactionState::RestoreIntent)
        {
            self.wal
                .transition_staging(transaction, TransactionState::RestoreIntent)?;
        }

        // Sorting is repeated here rather than trusting serialized/report order.
        // The exact source parent is forced after every descendant and sibling.
        sort_restore_entries(&mut self.restore.entries, &self.restore.source_parent_last);

        for (original, mut rebound) in self.restore.entries {
            rebound.verify_fresh_binding()?;
            rebound
                .held
                .bind_recovered_seal_lineage(
                    transaction,
                    original.mutation_id,
                    original.pre_mode,
                    original.expected_mode,
                    self.wal
                        .staging_metadata(transaction)
                        .ok_or(RecoveryRebindError::TransactionMismatch)?
                        .backend(),
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
                    locator: RecoveryLocator {
                        relative_path: rebound.relative_path,
                        filesystem_id: original.evidence.filesystem_id().map(str::to_owned),
                    },
                    transform: LocalModeTransform::Restore { original },
                },
            )?;
        }
        if self.wal.transaction_state(transaction) != Some(self.restore.completion) {
            self.wal
                .transition_staging(transaction, self.restore.completion)?;
        }
        *self.startup_blocked = !self.wal.can_begin_staging_transaction();
        Ok(())
    }
}

fn sort_restore_entries<T>(entries: &mut [(DurablePermission, T)], source_parent: &Path) {
    entries.sort_by(|(left, _), (right, _)| {
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
    });
}

/// Rebind startup work under fresh authenticated anchors. On any inability to
/// establish strong authority, no path is mutated and the transaction is moved
/// to durable `RecoveryRequired` when that transition can be recorded.
pub(crate) fn prepare_startup_recovery<'a>(
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    anchors: RecoveryAnchors,
) -> Result<StartupRecoveryCapability<'a>, RecoveryRebindError> {
    // Recompute from the exact leased WAL after every durable uncertainty
    // resolution. No caller can supply/omit a permission or choose a rename side.
    let (metadata, work) = loop {
        let snapshot = wal
            .recovery_snapshot(transaction)
            .ok_or(RecoveryRebindError::TransactionMismatch)?;
        let work = crate::seal_wal::decide_recovery(&snapshot, |_| {
            crate::seal_wal::RecoveryIdentity::Reestablished
        });
        // Preserve the typed RenameIntent+missing-outcome ambiguity. Repeated
        // attempts must never turn it into a generic state that permits lookup.
        if recovery_lookup_is_forbidden(&work) {
            return Err(RecoveryRebindError::RenameOutcomeUnknown);
        }
        if let RecoveryWork::RecoveryRequired { reason, .. } = &work {
            return match reason {
                crate::seal_wal::RecoveryRequiredReason::LegacySchemaMissingMountIdentity {
                    version,
                } => Err(RecoveryRebindError::LegacySchemaMissingMountIdentity(
                    *version,
                )),
                crate::seal_wal::RecoveryRequiredReason::RecordedRecoveryRequired => {
                    Err(RecoveryRebindError::RecordedRecoveryRequired)
                }
                crate::seal_wal::RecoveryRequiredReason::InsufficientPersistentIdentity => {
                    fail_closed(
                        wal,
                        transaction,
                        RecoveryRebindError::StrongIdentityUnavailable,
                    )
                }
                crate::seal_wal::RecoveryRequiredReason::RenameOutcomeUnknown => {
                    unreachable!("rename ambiguity handled before recovery-required dispatch")
                }
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
        break (metadata, work);
    };

    match rebind_work(&metadata, work, &anchors) {
        Ok(ReboundWork::Restore(restore)) => {
            Ok(StartupRecoveryCapability::Restore(RecoveryRestoreSession {
                wal,
                startup_blocked,
                restore,
            }))
        }
        Ok(ReboundWork::VerifyStaged(root)) => Ok(StartupRecoveryCapability::PendingVerification(
            CertifiedStagedRecovery {
                wal,
                startup_blocked,
                transaction,
                root,
            },
        )),
        Err(error) => fail_closed(wal, transaction, error),
    }
}

fn fail_closed<T>(
    wal: &mut SealWal<RecoverySession>,
    transaction: TransactionId,
    error: RecoveryRebindError,
) -> Result<T, RecoveryRebindError> {
    if wal.transaction_state(transaction) != Some(TransactionState::RecoveryRequired) {
        wal.transition_staging(transaction, TransactionState::RecoveryRequired)?;
    }
    Err(error)
}

enum ReboundWork {
    Restore(ReboundRestore),
    VerifyStaged(ReboundObject),
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
            crate::seal_wal::ObjectIncarnation::new(
                permission
                    .evidence
                    .generation_or_btime()
                    .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
            ),
            anchor.mount_key,
        );
        let (parent, basename) = open_confined_parent(&anchor.fd, &path, anchor.mount_key)?;
        let rebound = rebind_named_child(parent, &basename, expected, path, metadata, None)?;
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
    if original.application != crate::seal_wal::ApplicationStatus::Applied
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
        _ => return Err(RecoveryRebindError::TransactionMismatch),
    };
    if permission.evidence.relative_path() != expected_path {
        return Err(RecoveryRebindError::TransactionMismatch);
    }
    Ok((anchor, expected_path))
}

fn rebind_work(
    metadata: &StagingTransactionMetadata,
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
            Ok(ReboundWork::Restore(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                entries,
                completion: TransactionState::Restored,
            }))
        }
        RecoveryWork::RestoreSourceParentAfterRename {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let staged = rebind_named_child(
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
            Ok(ReboundWork::Restore(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                entries,
                completion: TransactionState::SourceParentRestored,
            }))
        }
        RecoveryWork::RestoreQuarantinedSeals {
            transaction: work_transaction,
            permissions,
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            let staged = rebind_named_child(
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
            Ok(ReboundWork::Restore(ReboundRestore {
                transaction,
                source_parent_last: metadata.source_parent().relative_path().to_path_buf(),
                entries,
                completion: TransactionState::Quarantined,
            }))
        }
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: work_transaction,
            ..
        } => {
            if work_transaction != transaction {
                return Err(RecoveryRebindError::TransactionMismatch);
            }
            drop(source_parent);
            let root = rebind_named_child(
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
            Ok(ReboundWork::VerifyStaged(root))
        }
        RecoveryWork::RecoveryRequired { .. }
        | RecoveryWork::ResolveUncertainPermissions { .. }
        | RecoveryWork::PreserveCommittedSeal { .. }
        | RecoveryWork::PreserveQuarantine { .. }
        | RecoveryWork::Nothing => Err(RecoveryRebindError::TransactionMismatch),
    }
}

fn recovery_lookup_is_forbidden(work: &RecoveryWork) -> bool {
    matches!(
        work,
        RecoveryWork::RecoveryRequired {
            reason: crate::seal_wal::RecoveryRequiredReason::RenameOutcomeUnknown,
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

fn rebind_permissions(
    anchor: &RecoveryFilesystemAnchor,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<(DurablePermission, ReboundObject)>, RecoveryRebindError> {
    permissions
        .into_iter()
        .map(|permission| {
            let path = permission.evidence.relative_path().to_path_buf();
            let expected = StrongObjectIdentity::new_with_mount(
                permission.evidence.device(),
                permission.evidence.inode(),
                crate::seal_wal::ObjectIncarnation::new(
                    permission
                        .evidence
                        .generation_or_btime()
                        .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
                ),
                anchor.mount_key,
            );
            let (parent, basename) = open_confined_parent(&anchor.fd, &path, anchor.mount_key)?;
            let rebound = rebind_named_child(
                parent,
                &basename,
                expected,
                path,
                metadata,
                Some(permission.expected_mode),
            )?;
            Ok((permission, rebound))
        })
        .collect()
}

fn rebind_quarantined_permissions(
    anchors: &RecoveryAnchors,
    metadata: &StagingTransactionMetadata,
    permissions: Vec<DurablePermission>,
) -> Result<Vec<(DurablePermission, ReboundObject)>, RecoveryRebindError> {
    let source_root = metadata
        .source_parent()
        .relative_path()
        .join(metadata.source_basename());
    let destination_root = metadata
        .destination_parent()
        .relative_path()
        .join(metadata.destination_basename());
    permissions
        .into_iter()
        .map(|permission| {
            let (anchor, path) = if permission.phase == TransactionState::ParentSealIntent {
                (
                    &anchors.source,
                    permission.evidence.relative_path().to_path_buf(),
                )
            } else if permission.phase == TransactionState::TreeSealIntent {
                let suffix = permission
                    .evidence
                    .relative_path()
                    .strip_prefix(&source_root)
                    .map_err(|_| RecoveryRebindError::InvalidLocator)?;
                (&anchors.destination, destination_root.join(suffix))
            } else {
                return Err(RecoveryRebindError::TransactionMismatch);
            };
            let expected = StrongObjectIdentity::new_with_mount(
                permission.evidence.device(),
                permission.evidence.inode(),
                crate::seal_wal::ObjectIncarnation::new(
                    permission
                        .evidence
                        .generation_or_btime()
                        .ok_or(RecoveryRebindError::StrongIdentityUnavailable)?,
                ),
                anchor.mount_key,
            );
            let (parent, basename) = open_confined_parent(&anchor.fd, &path, anchor.mount_key)?;
            let rebound = rebind_named_child(
                parent,
                &basename,
                expected,
                path,
                metadata,
                Some(permission.expected_mode),
            )?;
            Ok((permission, rebound))
        })
        .collect()
}

fn rebind_named_child(
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
        parent,
        object_check_fd,
        basename: basename.to_os_string(),
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

fn open_confined_directory(
    anchor: &OwnedFd,
    path: &Path,
    expected_mount: u64,
) -> Result<OwnedFd, RecoveryRebindError> {
    let mut current = rustix::io::dup(anchor)
        .map_err(io::Error::from)
        .map_err(RecoveryRebindError::Io)?;
    let mut saw_component = false;
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(RecoveryRebindError::InvalidLocator);
        };
        saw_component = true;
        current = open_directory_at(&current, name)?;
        if held_mount_key(&current)? != expected_mount {
            return Err(RecoveryRebindError::MountChanged);
        }
    }
    saw_component
        .then_some(current)
        .ok_or(RecoveryRebindError::InvalidLocator)
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
fn strong_identity_fd(fd: &OwnedFd) -> Result<StrongObjectIdentity, RecoveryRebindError> {
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
        crate::seal_wal::ObjectIncarnation::new(incarnation),
        statx.stx_mnt_id,
    ))
}

#[cfg(target_os = "macos")]
fn strong_identity_fd(fd: &OwnedFd) -> Result<StrongObjectIdentity, RecoveryRebindError> {
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
        crate::seal_wal::ObjectIncarnation::new(incarnation),
        mount_id,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn strong_identity_fd(_fd: &OwnedFd) -> Result<StrongObjectIdentity, RecoveryRebindError> {
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
