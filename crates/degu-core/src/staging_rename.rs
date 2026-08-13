//! Lease-bound held-FD staging rename foundation.
//!
//! This module is deliberately unwired from the CLI and lifecycle. It may move
//! one exact, fully sealed local tree from an authenticated source parent to an
//! authenticated destination parent. It cannot restore, commit, purge, unlink,
//! or delete, and its only success state is `StagedUnverified`.

use crate::authority::TransactionState;
use crate::local_backend::held_tree::{
    HeldTreeError, HeldTreeInventory, HeldTreeLimits, HeldTreeSealError,
};
use crate::local_backend::{
    CertificationError, HeldLocalBackendEvidence, LocalModeRevalidationFailure, certify_held_fd,
};
use crate::seal_executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeMutationResult, LocalModeTransform,
    RecoveryLocator, execute_staging_local_mode_mutation,
};
use crate::seal_wal::{
    AppendError, DurableSourceParentStrategy, DurableTreeManifest, RecoverySession, SealWal,
    StagingLocator, StagingTransactionMetadata, StrongObjectIdentity, TransactionId,
};
use crate::staging_recovery::{
    RecoveryFilesystemAnchor, RecoveryRebindError, held_filesystem_id, strong_identity_fd,
};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path};

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
        production_association: Option<crate::seal_wal::ProductionAssociation>,
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

/// Nonforgeable live result of A3c2. It retains the exact leased WAL, both
/// parents, staged root, and sealed directory descriptors, but exposes no
/// namespace, restore, commit, purge, unlink, or deletion operation.
pub(crate) struct StagedUnverifiedTree<'a> {
    wal: &'a mut SealWal<RecoverySession>,
    startup_blocked: &'a mut bool,
    transaction: TransactionId,
    _source_parent: OwnedFd,
    _destination_parent: OwnedFd,
    _staged_root: OwnedFd,
    _source_parent_seal: HeldLocalBackendEvidence,
    _destination_parent_evidence: HeldLocalBackendEvidence,
    _sealed_tree: HeldTreeInventory,
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

    let mut tree = collect_source_tree(&binding)?;
    if tree.root_strong_identity() != binding.metadata.root_identity() {
        return Err(StagingRenameError::Binding(
            PreparedRootError::BackendOrMountChanged,
        ));
    }
    wal.transition_staging_foundation(transaction, TransactionState::TreeSealIntent)?;
    let source_root = binding
        .metadata
        .source_parent()
        .relative_path()
        .join(binding.metadata.source_basename());
    tree.seal_directories_for_staging(
        wal,
        transaction,
        &source_root,
        binding.metadata.filesystem_id(),
        1,
    )?;

    let post_seal = collect_source_tree(&binding)?;
    tree.verify_post_seal_snapshot(&post_seal)?;
    post_seal.rewalk_exact()?;
    let fingerprint = post_seal.fingerprint();
    wal.complete_tree_manifest(
        transaction,
        DurableTreeManifest {
            schema_version: fingerprint.schema_version,
            entry_count: fingerprint.entry_count,
            sha256: fingerprint.sha256,
        },
    )?;
    wal.transition_staging_foundation(transaction, TransactionState::TreeSealed)?;

    post_seal.rewalk_exact()?;
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
        _sealed_tree: tree,
    })
}

fn collect_source_tree(
    binding: &PreparedRootBinding,
) -> Result<HeldTreeInventory, StagingRenameError> {
    let parent = certify_duplicate(&binding.source_parent)?;
    let protected_names = crate::safety::PROTECTED_DESCENDANT_DIR_NAMES
        .iter()
        .map(OsString::from)
        .collect();
    Ok(HeldTreeInventory::collect(
        parent,
        binding.metadata.source_basename(),
        protected_names,
        HeldTreeLimits::default(),
    )?)
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
