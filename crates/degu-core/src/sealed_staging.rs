//! High-level boundary for the sealed-staging transaction stack.
//!
//! A3c3 owns the exact WAL lease, exhausts startup recovery through freshly
//! certified filesystem anchors, and mints readiness only after every recovery
//! candidate reaches a safe durable terminal state. A3c4 adds one narrow forward
//! coordinator on that readiness capability. It consumes raw held descriptors,
//! completes seal/rename/verification/source-parent restoration under the same
//! lease, and returns only after `VerifiedCommitted`. No purge, unlink, deletion,
//! or committed-tree mode-restoration authority is exported.

use crate::authority::TransactionState;
use crate::seal_store::{SealWalStore, StoreError};
use crate::seal_wal::{
    AppendError, ProductionAssociation, RecoveryIdentity, RecoverySession, RecoveryWork,
    ReplayError, ReplayedTransaction, SealWal, StagingTransactionMetadata, StrongObjectIdentity,
    TransactionId, decide_recovery, quarantined_transaction_retains_active_permission_seals,
};
use crate::staging_recovery::{
    RecoveryAnchors, RecoveryFilesystemAnchor, RecoveryRebindError, StagedVerificationFailure,
    StagedVerificationOutcome, StartupRecoveryCapability, certify_verified_commit,
    prepare_startup_recovery, recovery_transaction, strong_identity_fd,
};
use crate::staging_rename::{
    PreparedRootBinding, StagedUnverifiedTree, StagingRenameError, execute_prepared_rename,
};
use rustix::fd::OwnedFd;
use std::error::Error;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_RECOVERY_GENERATION: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
std::thread_local! {
    pub(crate) static AFTER_FORWARD_QUARANTINE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}
const MAX_RECOVERY_STEPS_PER_TRANSACTION: usize = 4;
const MAX_RECOVERY_TRANSACTIONS: usize = 64;
const MAX_RECOVERY_PERMISSION_RECORDS: usize = 4096;
const MAX_RECOVERY_PERMISSION_OPERATIONS: usize = 1024;
const MAX_RECOVERY_PATH_COMPONENTS: usize = 128;
const MAX_RECOVERY_PATH_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StagingEngineError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Wal(#[from] AppendError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("staging recovery metadata is incomplete or inconsistent: {0}")]
    InsufficientRecoveryIdentity(&'static str),
}

/// Owns the exact WAL lease. Low-level mode and namespace mutations remain
/// crate-private and cannot be reached through this boundary.
pub struct SealedStagingEngine {
    wal: SealWal<RecoverySession>,
    startup_blocked: bool,
    recovery_generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StartupRecoveryCandidate {
    transaction: TransactionId,
    generation: u64,
}

impl StartupRecoveryCandidate {
    pub fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StartupRecoveryReport {
    candidates: Vec<StartupRecoveryCandidate>,
    generation: u64,
}

impl StartupRecoveryReport {
    pub fn candidates(&self) -> &[StartupRecoveryCandidate] {
        &self.candidates
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn into_candidates(self) -> Vec<StartupRecoveryCandidate> {
        self.candidates
    }
}

/// Raw descriptors supplied by the lifecycle for one durable transaction.
/// Construction grants no authority: the coordinator independently certifies
/// filesystem identity, backend, mount, and every locator/object binding.
#[derive(Debug)]
pub struct StartupRecoveryAnchors {
    source: OwnedFd,
    destination: OwnedFd,
}

impl StartupRecoveryAnchors {
    pub fn new(source: OwnedFd, destination: OwnedFd) -> Self {
        Self {
            source,
            destination,
        }
    }

    fn certify(
        self,
        metadata: &StagingTransactionMetadata,
    ) -> Result<RecoveryAnchors, RecoveryRebindError> {
        Ok(RecoveryAnchors {
            source: RecoveryFilesystemAnchor::certify(
                self.source,
                metadata.filesystem_id().to_owned(),
            )?,
            destination: RecoveryFilesystemAnchor::certify(
                self.destination,
                metadata.filesystem_id().to_owned(),
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredStartupTransaction {
    pub transaction: TransactionId,
    pub terminal_state: TransactionState,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct StartupRecoverySummary {
    pub recovered: Vec<RecoveredStartupTransaction>,
}

struct RecoveryTerminalOutcome {
    state: TransactionState,
    verification_failure: Option<StagedVerificationFailure>,
}

/// Derives the kernel filesystem identifier required by forward locators from
/// a held descriptor. Callers cannot supply pathname-derived identity.
pub fn forward_filesystem_id(fd: &OwnedFd) -> io::Result<String> {
    crate::staging_recovery::held_filesystem_id(fd)
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Result of comparing a named directory with WAL-held strong identity.
///
/// `Mismatch` is positive evidence that the name is absent, is not a directory,
/// or names another incarnation. `Uncertain` is deliberately distinct: callers
/// must not weaken authority when the namespace could not be inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDirectoryIdentityProbe {
    Match,
    Mismatch,
    Uncertain(String),
}

/// Strongly probes a directory for lifecycle conflict detection. On Linux an
/// `O_PATH` descriptor avoids requiring read permission; every platform keeps a
/// descriptor held while deriving strong identity. The result is evidence only
/// and grants no namespace mutation authority.
pub fn probe_forward_directory_identity(
    path: &Path,
    expected: StrongObjectIdentity,
) -> ForwardDirectoryIdentityProbe {
    #[cfg(target_os = "linux")]
    let flags = rustix::fs::OFlags::PATH
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;

    let fd = match rustix::fs::open(path, flags, rustix::fs::Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
            return ForwardDirectoryIdentityProbe::Mismatch;
        }
        Err(error) => {
            return ForwardDirectoryIdentityProbe::Uncertain(io::Error::from(error).to_string());
        }
    };
    match strong_identity_fd(&fd) {
        Ok(actual) if actual == expected => ForwardDirectoryIdentityProbe::Match,
        Ok(_) => ForwardDirectoryIdentityProbe::Mismatch,
        Err(error) => ForwardDirectoryIdentityProbe::Uncertain(error.to_string()),
    }
}

/// Raw held inputs for one forward sealed-staging transaction.
///
/// Construction grants no authority. The coordinator independently certifies
/// both anchors, binds each locator to its held parent, authenticates the source
/// root and destination absence, and requires one certified local mount before
/// the first WAL frame is written.
#[derive(Debug)]
pub struct ForwardStagingRequest {
    source_anchor: OwnedFd,
    source_parent: OwnedFd,
    source_parent_locator: crate::seal_wal::StagingLocator,
    source_basename: std::ffi::OsString,
    destination_anchor: OwnedFd,
    destination_parent: OwnedFd,
    destination_parent_locator: crate::seal_wal::StagingLocator,
    destination_basename: std::ffi::OsString,
    production_association: Option<ProductionAssociation>,
}

impl ForwardStagingRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_anchor: OwnedFd,
        source_parent: OwnedFd,
        source_parent_locator: crate::seal_wal::StagingLocator,
        source_basename: std::ffi::OsString,
        destination_anchor: OwnedFd,
        destination_parent: OwnedFd,
        destination_parent_locator: crate::seal_wal::StagingLocator,
        destination_basename: std::ffi::OsString,
    ) -> Self {
        Self {
            source_anchor,
            source_parent,
            source_parent_locator,
            source_basename,
            destination_anchor,
            destination_parent,
            destination_parent_locator,
            destination_basename,
            production_association: None,
        }
    }

    /// Attaches the lifecycle grouping to the same first durable frame that
    /// binds the exact source, destination, and object identity.
    pub fn with_production_association(mut self, association: ProductionAssociation) -> Self {
        self.production_association = Some(association);
        self
    }

    fn prepare(self) -> Result<(PreparedRootBinding, ForwardRecoveryAnchors), BoxError> {
        let recovery = ForwardRecoveryAnchors {
            source: duplicate_fd(&self.source_anchor)?,
            destination: duplicate_fd(&self.destination_anchor)?,
        };
        let filesystem_id = self.source_parent_locator.filesystem_id().to_owned();
        let source_anchor =
            RecoveryFilesystemAnchor::certify(self.source_anchor, filesystem_id.clone())?;
        let destination_anchor =
            RecoveryFilesystemAnchor::certify(self.destination_anchor, filesystem_id)?;
        let binding = PreparedRootBinding::prepare_with_association(
            source_anchor,
            self.source_parent,
            self.source_parent_locator,
            self.source_basename,
            destination_anchor,
            self.destination_parent,
            self.destination_parent_locator,
            self.destination_basename,
            self.production_association,
        )?;
        Ok((binding, recovery))
    }
}

type BoxError = Box<dyn Error + Send + Sync>;

struct ForwardRecoveryAnchors {
    source: OwnedFd,
    destination: OwnedFd,
}

impl ForwardRecoveryAnchors {
    fn duplicate(&self) -> io::Result<StartupRecoveryAnchors> {
        Ok(StartupRecoveryAnchors::new(
            duplicate_fd(&self.source)?,
            duplicate_fd(&self.destination)?,
        ))
    }
}

fn duplicate_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    rustix::io::dup(fd).map_err(io::Error::from)
}

/// Authority-neutral receipt proving that the exact leased WAL reached only
/// `VerifiedCommitted`. It is not undo, purge, unlink, or deletion authority.
#[derive(Debug)]
pub struct ForwardStagingCommit {
    transaction: TransactionId,
}

impl ForwardStagingCommit {
    pub fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardFailureDisposition {
    /// The request wrote no transaction frame and performed no permission or
    /// namespace mutation. A different request may be attempted on this engine.
    NotStarted,
    /// The request started and was durably driven to this safe terminal state.
    Terminal(TransactionState),
    /// Recovery did not reach a safe terminal state. No later transaction may
    /// be attempted until a reopened coordinator completes or manually resolves it.
    RecoveryBlocked,
}

#[derive(Debug, thiserror::Error)]
enum ForwardRecoveryError {
    #[error(transparent)]
    Recovery(#[from] StartupRecoveryError),
    #[error(
        "staged verification failed ({verification}); subsequent recovery also failed: {recovery}"
    )]
    VerificationThenRecovery {
        verification: StagedVerificationFailure,
        #[source]
        recovery: StartupRecoveryError,
    },
}

#[derive(Debug, thiserror::Error)]
#[error(
    "forward operation failed: {forward}; recovery did not reach a safe terminal state: {recovery}"
)]
struct FailedForwardRecovery {
    forward: StagingRenameError,
    #[source]
    recovery: ForwardRecoveryError,
}

#[derive(Debug, thiserror::Error)]
#[error("forward sealed staging for {transaction:?} failed during {stage}: {source}")]
pub struct ForwardStagingError {
    transaction: TransactionId,
    stage: &'static str,
    disposition: ForwardFailureDisposition,
    #[source]
    source: BoxError,
}

impl ForwardStagingError {
    fn new<E>(
        transaction: TransactionId,
        stage: &'static str,
        disposition: ForwardFailureDisposition,
        source: E,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::from_box(transaction, stage, disposition, Box::new(source))
    }

    fn from_box(
        transaction: TransactionId,
        stage: &'static str,
        disposition: ForwardFailureDisposition,
        source: BoxError,
    ) -> Self {
        Self {
            transaction,
            stage,
            disposition,
            source,
        }
    }

    pub fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub fn stage(&self) -> &'static str {
        self.stage
    }

    pub fn disposition(&self) -> ForwardFailureDisposition {
        self.disposition
    }

    /// Convenience projection for callers that only need a safe terminal state.
    pub fn terminal_state(&self) -> Option<TransactionState> {
        match self.disposition {
            ForwardFailureDisposition::Terminal(state) => Some(state),
            ForwardFailureDisposition::NotStarted | ForwardFailureDisposition::RecoveryBlocked => {
                None
            }
        }
    }
}

/// WAL-authoritative association for one production staging transaction.
/// Locators remain evidence relative to separately authenticated anchors.
#[derive(Debug, Clone)]
pub struct ProductionStagingEntry {
    transaction: TransactionId,
    state: TransactionState,
    destination_parent: crate::seal_wal::StagingLocator,
    destination_basename: std::ffi::OsString,
    root_identity: StrongObjectIdentity,
    reclamation_id: String,
}

impl ProductionStagingEntry {
    pub fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub fn state(&self) -> TransactionState {
        self.state
    }

    pub fn destination_parent(&self) -> &crate::seal_wal::StagingLocator {
        &self.destination_parent
    }

    pub fn destination_basename(&self) -> &std::ffi::OsStr {
        &self.destination_basename
    }

    pub fn root_identity(&self) -> StrongObjectIdentity {
        self.root_identity
    }

    pub fn reclamation_id(&self) -> &str {
        &self.reclamation_id
    }
}

/// The only engine form that may be retained by a production mutation session.
pub struct ReadyStagingEngine {
    engine: SealedStagingEngine,
}

impl ReadyStagingEngine {
    pub fn state(&self, transaction: TransactionId) -> Option<TransactionState> {
        self.engine.state(transaction)
    }

    /// Complete WAL-authoritative production bindings, independent of JSONL.
    pub fn production_entries(&self) -> Vec<ProductionStagingEntry> {
        self.engine
            .wal
            .recovery_snapshots()
            .into_iter()
            .filter_map(|snapshot| {
                let metadata = snapshot.staging?;
                let association = metadata.production_association()?.clone();
                Some(ProductionStagingEntry {
                    transaction: snapshot.id,
                    state: snapshot.state,
                    destination_parent: metadata.destination_parent().clone(),
                    destination_basename: metadata.destination_basename().to_os_string(),
                    root_identity: metadata.root_identity(),
                    reclamation_id: association.reclamation_id().to_owned(),
                })
            })
            .collect()
    }

    /// Executes one complete forward transaction under this engine's exact WAL
    /// lease. Success is returned only after exact staged-tree verification,
    /// source-parent restoration, and a durable `VerifiedCommitted` record.
    ///
    /// A failed rename is synchronously driven toward a safe terminal state when
    /// the WAL and namespace evidence permit it. Callers must inspect
    /// [`ForwardStagingError::disposition`] to distinguish a preflight rejection
    /// that may be retried from a recovery block that must stop the mutation run.
    pub fn stage_to_verified_commit(
        &mut self,
        transaction: TransactionId,
        request: ForwardStagingRequest,
    ) -> Result<ForwardStagingCommit, ForwardStagingError> {
        if !self.engine.can_begin_staging_transaction() {
            return Err(ForwardStagingError::new(
                transaction,
                "transaction admission",
                ForwardFailureDisposition::RecoveryBlocked,
                io::Error::other("existing transaction blocks new sealed staging"),
            ));
        }
        if self.engine.state(transaction).is_some() {
            return Err(ForwardStagingError::new(
                transaction,
                "transaction admission",
                ForwardFailureDisposition::NotStarted,
                io::Error::other("transaction ID already exists in the exact leased WAL"),
            ));
        }
        let (binding, recovery_anchors) = request.prepare().map_err(|source| {
            ForwardStagingError::from_box(
                transaction,
                "prepared root binding",
                ForwardFailureDisposition::NotStarted,
                source,
            )
        })?;

        let forward = self.engine.stage_prepared_root(transaction, binding);
        match forward {
            Ok(staged) => {
                debug_assert_eq!(staged.transaction(), transaction);
                debug_assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
                drop(staged);
            }
            Err(source) => {
                if self.engine.state(transaction).is_none() {
                    let disposition = if self.engine.can_begin_staging_transaction() {
                        ForwardFailureDisposition::NotStarted
                    } else {
                        // A failed first-frame write/sync poisons the exact WAL
                        // before its in-memory state can be updated. Absence from
                        // the map therefore cannot alone prove "not started".
                        ForwardFailureDisposition::RecoveryBlocked
                    };
                    return Err(ForwardStagingError::new(
                        transaction,
                        "seal and no-replace rename",
                        disposition,
                        source,
                    ));
                }
                return match self.recover_forward_transaction(transaction, &recovery_anchors) {
                    Ok(terminal) => Err(ForwardStagingError::new(
                        transaction,
                        "seal and no-replace rename",
                        ForwardFailureDisposition::Terminal(terminal.state),
                        source,
                    )),
                    Err(recovery) => Err(ForwardStagingError::new(
                        transaction,
                        "failed-forward recovery",
                        ForwardFailureDisposition::RecoveryBlocked,
                        FailedForwardRecovery {
                            forward: source,
                            recovery,
                        },
                    )),
                };
            }
        }

        let terminal = self
            .recover_forward_transaction(transaction, &recovery_anchors)
            .map_err(|source| {
                ForwardStagingError::new(
                    transaction,
                    "forward commit recovery",
                    ForwardFailureDisposition::RecoveryBlocked,
                    source,
                )
            })?;
        if terminal.state != TransactionState::VerifiedCommitted {
            let disposition = ForwardFailureDisposition::Terminal(terminal.state);
            return match terminal.verification_failure {
                Some(source) => Err(ForwardStagingError::new(
                    transaction,
                    "staged-tree verification",
                    disposition,
                    source,
                )),
                None => Err(ForwardStagingError::new(
                    transaction,
                    "forward terminal state",
                    disposition,
                    io::Error::other(format!(
                        "forward transaction reached {:?} instead of VerifiedCommitted",
                        terminal.state
                    )),
                )),
            };
        }
        Ok(ForwardStagingCommit { transaction })
    }

    fn recover_forward_transaction(
        &mut self,
        transaction: TransactionId,
        anchors: &ForwardRecoveryAnchors,
    ) -> Result<RecoveryTerminalOutcome, ForwardRecoveryError> {
        let mut verification_failure = None;
        self.engine
            .recover_transaction_to_terminal(
                transaction,
                &mut |_, _| anchors.duplicate(),
                MAX_RECOVERY_STEPS_PER_TRANSACTION,
                &mut verification_failure,
            )
            .map_err(|recovery| match verification_failure {
                Some(verification) => ForwardRecoveryError::VerificationThenRecovery {
                    verification,
                    recovery,
                },
                None => ForwardRecoveryError::Recovery(recovery),
            })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("startup recovery for {transaction:?} failed during {stage}: {source}")]
pub struct StartupRecoveryError {
    transaction: Option<TransactionId>,
    stage: &'static str,
    #[source]
    source: Box<dyn Error + Send + Sync>,
}

impl StartupRecoveryError {
    fn new<E>(transaction: Option<TransactionId>, stage: &'static str, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            transaction,
            stage,
            source: Box::new(source),
        }
    }

    pub fn transaction(&self) -> Option<TransactionId> {
        self.transaction
    }

    pub fn stage(&self) -> &'static str {
        self.stage
    }
}

fn recovery_work_requires_candidate(work: &RecoveryWork) -> bool {
    matches!(
        work,
        RecoveryWork::RestoreBeforeRename { .. }
            | RecoveryWork::VerifyOrQuarantineAfterRename { .. }
            | RecoveryWork::RestoreSourceParentAfterRename { .. }
            | RecoveryWork::RestoreQuarantinedSeals { .. }
            | RecoveryWork::ResolveUncertainPermissions { .. }
            | RecoveryWork::FinalizeVerifiedCommit { .. }
            | RecoveryWork::RecoveryRequired { .. }
    )
}

fn validate_recovery_workload(snapshot: &ReplayedTransaction) -> io::Result<()> {
    if snapshot.permissions.len() > MAX_RECOVERY_PERMISSION_RECORDS {
        return Err(io::Error::other(format!(
            "transaction contains {} permission records, above the limit of {MAX_RECOVERY_PERMISSION_RECORDS}",
            snapshot.permissions.len()
        )));
    }
    let unresolved = snapshot
        .permissions
        .iter()
        .filter(|permission| {
            permission.application
                == crate::seal_wal::ApplicationStatus::IntentDurableApplicationUnknown
        })
        .count();
    let active = snapshot
        .permissions
        .iter()
        .filter(|permission| {
            permission.application == crate::seal_wal::ApplicationStatus::Applied
                && permission.reverses_mutation_id.is_none()
                && !snapshot.permissions.iter().any(|inverse| {
                    inverse.application == crate::seal_wal::ApplicationStatus::Applied
                        && inverse.reverses_mutation_id == Some(permission.mutation_id)
                })
        })
        .count();
    if unresolved > MAX_RECOVERY_PERMISSION_OPERATIONS
        || active > MAX_RECOVERY_PERMISSION_OPERATIONS
    {
        return Err(io::Error::other(format!(
            "transaction exceeds the {MAX_RECOVERY_PERMISSION_OPERATIONS}-operation permission recovery limit"
        )));
    }
    let validate_path = |path: &Path| -> io::Result<()> {
        if path.components().count() > MAX_RECOVERY_PATH_COMPONENTS {
            return Err(io::Error::other(format!(
                "recovery path exceeds the {MAX_RECOVERY_PATH_COMPONENTS}-component limit"
            )));
        }
        if path.as_os_str().as_bytes().len() > MAX_RECOVERY_PATH_BYTES {
            return Err(io::Error::other(format!(
                "recovery path exceeds the {MAX_RECOVERY_PATH_BYTES}-byte limit"
            )));
        }
        Ok(())
    };
    if let Some(metadata) = &snapshot.staging {
        validate_path(metadata.source_parent().relative_path())?;
        validate_path(metadata.destination_parent().relative_path())?;
        if metadata.source_basename().as_bytes().len() > MAX_RECOVERY_PATH_BYTES
            || metadata.destination_basename().as_bytes().len() > MAX_RECOVERY_PATH_BYTES
        {
            return Err(io::Error::other(
                "recovery basename exceeds the path-byte limit",
            ));
        }
    }
    for permission in &snapshot.permissions {
        validate_path(permission.evidence.relative_path())?;
    }
    Ok(())
}

impl SealedStagingEngine {
    /// Opens the store once per mutation session, replays even an empty WAL, and
    /// resumes append on that same locked descriptor. Any legacy bare transaction
    /// fails closed rather than being promoted into sealed staging.
    pub fn open(store: &SealWalStore) -> Result<(Self, StartupRecoveryReport), StagingEngineError> {
        let mut recovery = store.try_lease()?;
        let replay = recovery.replay_and_repair()?.clone();
        if replay
            .transactions
            .values()
            .any(|transaction| transaction.staging.is_none())
        {
            return Err(StagingEngineError::InsufficientRecoveryIdentity(
                "transaction has no atomic staging metadata",
            ));
        }
        // Enumerate candidate recovery ordering without granting authority. Every
        // item is subsequently required to pass staging_recovery's fresh held-FD
        // rebind; this callback cannot itself authorize chmod or namespace work.
        let recovery_generation = NEXT_RECOVERY_GENERATION.fetch_add(1, Ordering::Relaxed);
        let mut work = replay
            .transactions
            .values()
            .map(|transaction| decide_recovery(transaction, |_| RecoveryIdentity::Reestablished))
            .filter(recovery_work_requires_candidate)
            .collect::<Vec<_>>();
        work.sort_by_key(recovery_transaction);
        let candidates = work
            .iter()
            .map(|work| StartupRecoveryCandidate {
                transaction: recovery_transaction(work),
                generation: recovery_generation,
            })
            .collect();
        let startup_blocked = replay
            .transactions
            .values()
            .any(quarantined_transaction_retains_active_permission_seals)
            || !work.is_empty();
        let wal = recovery.resume()?;
        Ok((
            Self {
                wal,
                startup_blocked,
                recovery_generation,
            },
            StartupRecoveryReport {
                candidates,
                generation: recovery_generation,
            },
        ))
    }

    /// Exhausts the exact report from [`Self::open`]. The provider is invoked
    /// only for work that may safely inspect a known side of the namespace; a
    /// rename-unknown or already-`RecoveryRequired` transaction is blocked and
    /// recorded without requesting anchors.
    pub fn recover_startup<F>(
        mut self,
        report: StartupRecoveryReport,
        mut provide_anchors: F,
    ) -> Result<(ReadyStagingEngine, StartupRecoverySummary), StartupRecoveryError>
    where
        F: FnMut(TransactionId, &StagingTransactionMetadata) -> io::Result<StartupRecoveryAnchors>,
    {
        let reported_transactions = report
            .candidates
            .iter()
            .map(|candidate| candidate.transaction)
            .collect::<Vec<_>>();
        let canonical_transactions = self.current_recovery_transactions();
        if report.generation != self.recovery_generation
            || report
                .candidates
                .iter()
                .any(|candidate| candidate.generation != self.recovery_generation)
            || reported_transactions != canonical_transactions
        {
            return Err(StartupRecoveryError::new(
                None,
                "report validation",
                io::Error::other(
                    "startup report does not exactly match the leased WAL recovery set",
                ),
            ));
        }

        let mut summary = StartupRecoverySummary::default();
        let candidates = report.candidates;
        if candidates.len() > MAX_RECOVERY_TRANSACTIONS {
            return Err(StartupRecoveryError::new(
                None,
                "recovery workload budget",
                io::Error::other(format!(
                    "startup report exceeds the {MAX_RECOVERY_TRANSACTIONS}-transaction limit"
                )),
            ));
        }
        for candidate in candidates {
            let transaction = self
                .validate_recovery_candidate(&candidate)
                .map_err(|error| {
                    StartupRecoveryError::new(
                        Some(candidate.transaction),
                        "candidate validation",
                        error,
                    )
                })?;
            let mut verification_failure = None;
            let terminal = self.recover_transaction_to_terminal(
                transaction,
                &mut provide_anchors,
                MAX_RECOVERY_STEPS_PER_TRANSACTION,
                &mut verification_failure,
            )?;
            summary.recovered.push(RecoveredStartupTransaction {
                transaction,
                terminal_state: terminal.state,
            });
        }

        self.startup_blocked = !self.wal.can_begin_staging_transaction();
        if self.startup_blocked {
            return Err(StartupRecoveryError::new(
                None,
                "terminal readiness check",
                io::Error::other("leased WAL still contains nonterminal recovery work"),
            ));
        }
        Ok((ReadyStagingEngine { engine: self }, summary))
    }

    fn current_recovery_transactions(&self) -> Vec<TransactionId> {
        self.wal
            .recovery_snapshots()
            .iter()
            .map(|transaction| decide_recovery(transaction, |_| RecoveryIdentity::Reestablished))
            .filter(recovery_work_requires_candidate)
            .map(|work| recovery_transaction(&work))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn recover_transaction_with_step_limit_for_test<F>(
        &mut self,
        transaction: TransactionId,
        provide_anchors: &mut F,
        step_limit: usize,
    ) -> Result<TransactionState, StartupRecoveryError>
    where
        F: FnMut(TransactionId, &StagingTransactionMetadata) -> io::Result<StartupRecoveryAnchors>,
    {
        let mut verification_failure = None;
        self.recover_transaction_to_terminal(
            transaction,
            provide_anchors,
            step_limit,
            &mut verification_failure,
        )
        .map(|terminal| terminal.state)
    }

    fn recover_transaction_to_terminal<F>(
        &mut self,
        transaction: TransactionId,
        provide_anchors: &mut F,
        step_limit: usize,
        verification_failure: &mut Option<StagedVerificationFailure>,
    ) -> Result<RecoveryTerminalOutcome, StartupRecoveryError>
    where
        F: FnMut(TransactionId, &StagingTransactionMetadata) -> io::Result<StartupRecoveryAnchors>,
    {
        for _ in 0..step_limit {
            if let Some(state) = self.safe_terminal_state(transaction) {
                return Ok(RecoveryTerminalOutcome {
                    state,
                    verification_failure: verification_failure.take(),
                });
            }

            let snapshot = self.wal.recovery_snapshot(transaction).ok_or_else(|| {
                StartupRecoveryError::new(
                    Some(transaction),
                    "snapshot",
                    io::Error::other("candidate transaction disappeared from the leased WAL"),
                )
            })?;
            if let Err(error) = validate_recovery_workload(&snapshot) {
                if snapshot.state != TransactionState::RecoveryRequired {
                    self.wal
                        .transition_staging_foundation(
                            transaction,
                            TransactionState::RecoveryRequired,
                        )
                        .map_err(|source| {
                            StartupRecoveryError::new(
                                Some(transaction),
                                "durable workload block",
                                source,
                            )
                        })?;
                }
                return Err(StartupRecoveryError::new(
                    Some(transaction),
                    "recovery workload budget",
                    error,
                ));
            }
            let work = decide_recovery(&snapshot, |_| RecoveryIdentity::Reestablished);
            if let RecoveryWork::RecoveryRequired { reason, .. } = work {
                if snapshot.state != TransactionState::RecoveryRequired {
                    self.wal
                        .transition_staging_foundation(
                            transaction,
                            TransactionState::RecoveryRequired,
                        )
                        .map_err(|error| {
                            StartupRecoveryError::new(
                                Some(transaction),
                                "durable recovery block",
                                error,
                            )
                        })?;
                }
                return Err(StartupRecoveryError::new(
                    Some(transaction),
                    "manual recovery block",
                    io::Error::other(format!("automatic recovery is forbidden: {reason:?}")),
                ));
            }

            if matches!(work, RecoveryWork::FinalizeVerifiedCommit { .. }) {
                let proof = certify_verified_commit(&self.wal, transaction).map_err(|error| {
                    StartupRecoveryError::new(
                        Some(transaction),
                        "verified commit certification",
                        error,
                    )
                })?;
                self.wal.record_verified_committed(proof).map_err(|error| {
                    StartupRecoveryError::new(Some(transaction), "verified commit", error)
                })?;
                self.startup_blocked = !self.wal.can_begin_staging_transaction();
                continue;
            }

            let metadata = snapshot.staging.clone().ok_or_else(|| {
                StartupRecoveryError::new(
                    Some(transaction),
                    "anchor request",
                    io::Error::other("candidate has no atomic staging metadata"),
                )
            })?;
            let supplied = provide_anchors(transaction, &metadata).map_err(|error| {
                StartupRecoveryError::new(Some(transaction), "anchor acquisition", error)
            })?;
            let anchors = supplied.certify(&metadata).map_err(|error| {
                StartupRecoveryError::new(Some(transaction), "anchor certification", error)
            })?;

            let before = snapshot.state;
            let capability = self
                .prepare_startup_recovery(
                    StartupRecoveryCandidate {
                        transaction,
                        generation: self.recovery_generation,
                    },
                    anchors,
                )
                .map_err(|error| {
                    StartupRecoveryError::new(Some(transaction), "fresh recovery rebind", error)
                })?;
            match capability {
                StartupRecoveryCapability::Restore(restore) => {
                    restore.execute().map_err(|error| {
                        StartupRecoveryError::new(
                            Some(transaction),
                            "held-descriptor restore",
                            error,
                        )
                    })?;
                }
                StartupRecoveryCapability::PendingVerification(pending) => {
                    match pending.verify_or_quarantine().map_err(|error| {
                        StartupRecoveryError::new(
                            Some(transaction),
                            "staged-tree verification",
                            error,
                        )
                    })? {
                        StagedVerificationOutcome::StagedSealed(verified) => {
                            debug_assert_eq!(verified.transaction(), transaction);
                            debug_assert_eq!(
                                verified.wal_state(),
                                Some(TransactionState::StagedSealed)
                            );
                            debug_assert!(verified.startup_is_blocked());
                        }
                        StagedVerificationOutcome::Quarantined(failure) => {
                            *verification_failure = Some(failure);
                            #[cfg(test)]
                            AFTER_FORWARD_QUARANTINE.with(|hook| {
                                if let Some(hook) = hook.borrow_mut().take() {
                                    hook();
                                }
                            });
                        }
                    }
                }
            }

            if let Some(state) = self.safe_terminal_state(transaction) {
                return Ok(RecoveryTerminalOutcome {
                    state,
                    verification_failure: verification_failure.take(),
                });
            }
            let after = self.wal.transaction_state(transaction).ok_or_else(|| {
                StartupRecoveryError::new(
                    Some(transaction),
                    "progress check",
                    io::Error::other("recovered transaction disappeared from the leased WAL"),
                )
            })?;
            if after == before {
                return Err(StartupRecoveryError::new(
                    Some(transaction),
                    "progress check",
                    io::Error::other("recovery step made no durable state progress"),
                ));
            }
        }

        Err(StartupRecoveryError::new(
            Some(transaction),
            "step exhaustion",
            io::Error::other(format!(
                "recovery exceeded {step_limit} durable state advances"
            )),
        ))
    }

    fn safe_terminal_state(&self, transaction: TransactionId) -> Option<TransactionState> {
        let snapshot = self.wal.recovery_snapshot(transaction)?;
        match snapshot.state {
            state @ (TransactionState::VerifiedCommitted
            | TransactionState::Purgeable
            | TransactionState::Purged
            | TransactionState::Restored
            | TransactionState::RolledBack) => Some(state),
            TransactionState::Quarantined
                if !quarantined_transaction_retains_active_permission_seals(&snapshot) =>
            {
                Some(TransactionState::Quarantined)
            }
            _ => None,
        }
    }

    fn can_begin_staging_transaction(&self) -> bool {
        !self.startup_blocked && self.wal.can_begin_staging_transaction()
    }

    /// Appends an atomic begin-with-metadata frame; multiple transactions may be
    /// started sequentially in one store and one mutation session.
    pub fn begin_transaction(
        &mut self,
        transaction: TransactionId,
        metadata: StagingTransactionMetadata,
    ) -> Result<(), StagingEngineError> {
        if self.startup_blocked || !self.wal.can_begin_staging_transaction() {
            return Err(StagingEngineError::InsufficientRecoveryIdentity(
                "existing transaction requires terminal recovery before new mutation",
            ));
        }
        self.wal.begin_staging(transaction, metadata)?;
        Ok(())
    }

    pub fn metadata(&self, transaction: TransactionId) -> Option<&StagingTransactionMetadata> {
        self.wal.staging_metadata(transaction)
    }

    pub fn state(&self, transaction: TransactionId) -> Option<TransactionState> {
        self.wal.transaction_state(transaction)
    }

    /// Rebinds one startup item while retaining this engine's exact WAL lease.
    /// The returned capability borrows the engine, so another transaction cannot
    /// reuse the lease while recovery FDs authorize work.
    pub(crate) fn prepare_startup_recovery(
        &mut self,
        candidate: StartupRecoveryCandidate,
        anchors: RecoveryAnchors,
    ) -> Result<StartupRecoveryCapability<'_>, RecoveryRebindError> {
        let transaction = self.validate_recovery_candidate(&candidate)?;
        prepare_startup_recovery(
            &mut self.wal,
            &mut self.startup_blocked,
            transaction,
            anchors,
        )
    }

    fn validate_recovery_candidate(
        &self,
        candidate: &StartupRecoveryCandidate,
    ) -> Result<TransactionId, RecoveryRebindError> {
        if candidate.generation != self.recovery_generation {
            return Err(RecoveryRebindError::CandidateFromAnotherEngine);
        }
        Ok(candidate.transaction)
    }

    /// Consumes one descriptor-derived root binding and performs the complete
    /// A3c2 seal/rename sequence. Success reaches only `StagedUnverified` and
    /// retains this engine's exact WAL lease for the A3c4 coordinator.
    pub(crate) fn stage_prepared_root(
        &mut self,
        transaction: TransactionId,
        binding: PreparedRootBinding,
    ) -> Result<StagedUnverifiedTree<'_>, StagingRenameError> {
        if self.startup_blocked || !self.wal.can_begin_staging_transaction() {
            return Err(StagingRenameError::StartupBlocked);
        }
        execute_prepared_rename(
            &mut self.wal,
            &mut self.startup_blocked,
            transaction,
            binding,
        )
    }
}

// Purge, unlink, and deletion authorization deliberately have no callable
// engine seam. A3c3 can finish only restore, quarantine-without-active-seals,
// or VerifiedCommitted; `Purgeable` still requires a future independent proof.

#[cfg(test)]
mod tests;
