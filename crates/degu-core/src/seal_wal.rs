//! Durable, authority-neutral WAL for future seal transactions.
//!
//! This module is intentionally not connected to clean, stage, undo, or purge.
//! It records recovery evidence and emits typed recovery work; neither a path nor
//! `(device, inode)` evidence is an authority token and this module performs no
//! permission or namespace mutation.

use crate::authority::{PersistentRecoveryEvidence, TransactionState};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"DSWL";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 20;
const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
const MAX_WAL_LEN: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(pub [u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRecord {
    State {
        transaction: TransactionId,
        state: TransactionState,
    },
    PermissionIntent {
        transaction: TransactionId,
        mutation_id: u64,
        evidence: PersistentRecoveryEvidence,
        pre_mode: u32,
        expected_mode: u32,
        reverses_mutation_id: Option<u64>,
    },
    PermissionApplied {
        transaction: TransactionId,
        mutation_id: u64,
    },
    PermissionNotApplied {
        transaction: TransactionId,
        mutation_id: u64,
    },
}

impl SealRecord {
    fn transaction(&self) -> TransactionId {
        match self {
            Self::State { transaction, .. }
            | Self::PermissionIntent { transaction, .. }
            | Self::PermissionApplied { transaction, .. }
            | Self::PermissionNotApplied { transaction, .. } => *transaction,
        }
    }
}

/// The durability surface needed by [`SealWal`]. Tests can inject short writes
/// and sync failures without making filesystem mutations.
pub trait DurableWrite: Write {
    fn sync_record(&mut self) -> io::Result<()>;
    /// Positions this writer at its physical EOF and returns that length.
    fn prepare_append(&mut self) -> io::Result<u64>;
}

impl DurableWrite for File {
    fn sync_record(&mut self) -> io::Result<()> {
        self.sync_all()
    }

    fn prepare_append(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::End(0))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error("WAL append failed: {0}")]
    Io(#[source] io::Error),
    #[error("WAL cannot be reused after a failed append or sync")]
    Poisoned,
    #[error("invalid WAL transaction operation: {0}")]
    InvalidState(&'static str),
    #[error("WAL record cannot be framed: {0}")]
    Frame(#[from] FrameError),
    #[error("WAL would exceed its {limit} byte limit")]
    TotalSize { limit: u64 },
}

/// Append-only writer. Every successful append includes a durability sync.
/// Any write/sync error poisons the handle so bytes after an uncertain tail are
/// never appended in the same session.
pub struct SealWal<W> {
    writer: W,
    poisoned: bool,
    states: HashMap<TransactionId, TransactionState>,
    used_mutations: HashSet<(TransactionId, u64)>,
    permissions: HashMap<(TransactionId, u64), DurablePermission>,
    unresolved_mutations: HashMap<(TransactionId, u64), DurablePermission>,
    committed_len: u64,
    max_wal_len: u64,
}

impl<W: DurableWrite> SealWal<W> {
    pub(crate) fn new(mut writer: W) -> Result<Self, AppendError> {
        let committed_len = writer.prepare_append().map_err(AppendError::Io)?;
        if committed_len != 0 {
            return Err(AppendError::InvalidState(
                "new WAL writer is not empty; use resume with validated replay",
            ));
        }
        Ok(Self::from_validated(writer, 0, MAX_WAL_LEN))
    }

    fn from_validated(writer: W, committed_len: u64, max_wal_len: u64) -> Self {
        Self {
            writer,
            poisoned: false,
            states: HashMap::new(),
            used_mutations: HashSet::new(),
            permissions: HashMap::new(),
            unresolved_mutations: HashMap::new(),
            committed_len,
            max_wal_len,
        }
    }

    #[cfg(test)]
    fn new_with_limit(mut writer: W, max_wal_len: u64) -> Result<Self, AppendError> {
        if writer.prepare_append().map_err(AppendError::Io)? != 0 {
            return Err(AppendError::InvalidState("test WAL writer is not empty"));
        }
        Ok(Self::from_validated(writer, 0, max_wal_len))
    }

    fn append_synced(&mut self, record: &SealRecord) -> Result<(), AppendError> {
        if self.poisoned {
            return Err(AppendError::Poisoned);
        }
        let frame = encode_frame(record)?;
        let next_len =
            self.committed_len
                .checked_add(frame.len() as u64)
                .ok_or(AppendError::TotalSize {
                    limit: self.max_wal_len,
                })?;
        if next_len > self.max_wal_len {
            return Err(AppendError::TotalSize {
                limit: self.max_wal_len,
            });
        }
        let result = self
            .writer
            .write_all(&frame)
            .and_then(|()| self.writer.sync_record());
        if let Err(error) = result {
            self.poisoned = true;
            return Err(AppendError::Io(error));
        }
        self.committed_len = next_len;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Hydrates append-side validation from a fail-closed replay. The caller
    /// must supply a writer positioned for append to the same validated WAL.
    pub(crate) fn resume(mut writer: W, replay: &Replay) -> Result<Self, AppendError> {
        let actual_len = writer.prepare_append().map_err(AppendError::Io)?;
        if actual_len != replay.committed_len || actual_len > MAX_WAL_LEN {
            return Err(AppendError::InvalidState(
                "writer length does not match validated replay",
            ));
        }
        let mut wal = Self::from_validated(writer, actual_len, MAX_WAL_LEN);
        for transaction in replay.transactions.values() {
            wal.states.insert(transaction.id, transaction.state);
            for permission in &transaction.permissions {
                let key = (transaction.id, permission.mutation_id);
                wal.used_mutations.insert(key);
                wal.permissions.insert(key, permission.clone());
                if permission.application == ApplicationStatus::IntentDurableApplicationUnknown {
                    wal.unresolved_mutations.insert(key, permission.clone());
                }
            }
        }
        Ok(wal)
    }

    pub fn begin(&mut self, transaction: TransactionId) -> Result<(), AppendError> {
        if self.states.contains_key(&transaction) {
            return Err(AppendError::InvalidState("transaction already exists"));
        }
        self.append_synced(&SealRecord::State {
            transaction,
            state: TransactionState::Prepared,
        })?;
        self.states.insert(transaction, TransactionState::Prepared);
        Ok(())
    }

    pub fn transition(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        let Some(current) = self.states.get(&transaction).copied() else {
            return Err(AppendError::InvalidState("transaction has not begun"));
        };
        if next != TransactionState::RecoveryRequired
            && self
                .unresolved_mutations
                .keys()
                .any(|(owner, _)| *owner == transaction)
        {
            return Err(AppendError::InvalidState(
                "transaction has an unresolved permission intent",
            ));
        }
        if !phase_completion_is_valid(
            self.permissions
                .iter()
                .filter(|((owner, _), _)| *owner == transaction)
                .map(|(_, permission)| permission),
            current,
            next,
        ) {
            return Err(AppendError::InvalidState(
                "seal phase contains a permission intent not durably applied",
            ));
        }
        if matches!(
            next,
            TransactionState::Restored | TransactionState::RolledBack
        ) && !all_applied_seals_have_applied_inverse(
            self.permissions
                .iter()
                .filter(|((owner, _), _)| *owner == transaction)
                .map(|(_, permission)| permission),
        ) {
            return Err(AppendError::InvalidState(
                "terminal restore requires an applied inverse for every applied seal",
            ));
        }
        if !valid_transition(current, next) {
            return Err(AppendError::InvalidState("invalid transaction transition"));
        }
        self.append_synced(&SealRecord::State {
            transaction,
            state: next,
        })?;
        self.states.insert(transaction, next);
        Ok(())
    }

    /// Durably records intent before invoking `mutate`, then durably records
    /// applied only after the mutation reports success.
    pub fn apply_permission_mutation<F>(
        &mut self,
        intent: PermissionIntent,
        mutate: F,
    ) -> Result<(), MutationAppendError>
    where
        F: FnOnce() -> io::Result<()>,
    {
        let transaction = intent.transaction;
        let mutation_id = intent.mutation_id;
        let phase = self.states.get(&transaction).copied();
        if !matches!(
            phase,
            Some(
                TransactionState::ParentSealIntent
                    | TransactionState::TreeSealIntent
                    | TransactionState::RestoreIntent
                    | TransactionState::RollbackIntent
            )
        ) {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "permission mutation is outside an intent phase",
            )));
        }
        if intent.expected_mode != intent.evidence.expected_mode()
            || intent.pre_mode & !0o7777 != 0
            || intent.expected_mode & !0o7777 != 0
        {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "permission modes are invalid or inconsistent with recovery evidence",
            )));
        }
        let reverse = intent.reverses_mutation_id;
        match (phase.unwrap(), reverse) {
            (TransactionState::ParentSealIntent | TransactionState::TreeSealIntent, None) => {}
            (
                TransactionState::RestoreIntent | TransactionState::RollbackIntent,
                Some(original),
            ) => {
                let Some(original) = self.permissions.get(&(transaction, original)) else {
                    return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                        "permission inverse references no durable mutation",
                    )));
                };
                if original.application != ApplicationStatus::Applied
                    || !matches!(
                        original.phase,
                        TransactionState::ParentSealIntent | TransactionState::TreeSealIntent
                    )
                    || !same_recovery_object(&original.evidence, &intent.evidence)
                    || intent.pre_mode != original.expected_mode
                    || intent.expected_mode != original.pre_mode
                    || self.permissions.iter().any(|((owner, _), permission)| {
                        *owner == transaction
                            && permission.reverses_mutation_id == Some(original.mutation_id)
                            && matches!(
                                permission.application,
                                ApplicationStatus::Applied
                                    | ApplicationStatus::IntentDurableApplicationUnknown
                            )
                    })
                {
                    return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                        "permission inverse does not match its applied seal mutation",
                    )));
                }
            }
            _ => {
                return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                    "seal and inverse permission intents are inconsistent with their phase",
                )));
            }
        }
        if !self.used_mutations.insert((transaction, mutation_id)) {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "duplicate permission mutation id",
            )));
        }
        if let Err(error) = self.append_synced(&intent.clone().into_record()) {
            self.used_mutations.remove(&(transaction, mutation_id));
            return Err(MutationAppendError::IntentWal(error));
        }
        self.unresolved_mutations.insert(
            (transaction, mutation_id),
            DurablePermission {
                mutation_id,
                phase: phase.unwrap(),
                evidence: intent.evidence,
                pre_mode: intent.pre_mode,
                expected_mode: intent.expected_mode,
                reverses_mutation_id: intent.reverses_mutation_id,
                application: ApplicationStatus::IntentDurableApplicationUnknown,
            },
        );
        let durable = self.unresolved_mutations[&(transaction, mutation_id)].clone();
        self.permissions.insert((transaction, mutation_id), durable);
        mutate().map_err(MutationAppendError::Mutation)?;
        self.append_synced(&SealRecord::PermissionApplied {
            transaction,
            mutation_id,
        })
        .map_err(|source| MutationAppendError::AppliedWal {
            source,
            mutation_applied: true,
        })?;
        self.unresolved_mutations
            .remove(&(transaction, mutation_id));
        self.permissions
            .get_mut(&(transaction, mutation_id))
            .unwrap()
            .application = ApplicationStatus::Applied;
        Ok(())
    }

    /// Resolves a durable intent only after caller-supplied, live-authorized
    /// recovery establishes whether the mutation is applied. This method does
    /// not perform chmod or infer identity from the recorded evidence.
    pub fn resolve_unresolved_permission<F>(
        &mut self,
        transaction: TransactionId,
        mutation_id: u64,
        resolve: F,
    ) -> Result<PermissionResolution, ResolveError>
    where
        F: FnOnce(&DurablePermission) -> io::Result<PermissionResolution>,
    {
        let key = (transaction, mutation_id);
        let permission = self
            .unresolved_mutations
            .get(&key)
            .ok_or(ResolveError::NotUnresolved)?;
        if self.states.get(&transaction).copied() != Some(permission.phase) {
            return Err(ResolveError::WrongPhase);
        }
        let resolution = resolve(permission).map_err(ResolveError::Recovery)?;
        let record = match resolution {
            PermissionResolution::Applied => SealRecord::PermissionApplied {
                transaction,
                mutation_id,
            },
            PermissionResolution::ConfirmedNotApplied => SealRecord::PermissionNotApplied {
                transaction,
                mutation_id,
            },
        };
        self.append_synced(&record).map_err(ResolveError::Wal)?;
        self.unresolved_mutations.remove(&key);
        self.permissions.get_mut(&key).unwrap().application = match resolution {
            PermissionResolution::Applied => ApplicationStatus::Applied,
            PermissionResolution::ConfirmedNotApplied => ApplicationStatus::ConfirmedNotApplied,
        };
        Ok(resolution)
    }
}

#[derive(Debug, Clone)]
pub struct PermissionIntent {
    pub transaction: TransactionId,
    pub mutation_id: u64,
    pub evidence: PersistentRecoveryEvidence,
    pub pre_mode: u32,
    pub expected_mode: u32,
    pub reverses_mutation_id: Option<u64>,
}

impl PermissionIntent {
    fn into_record(self) -> SealRecord {
        SealRecord::PermissionIntent {
            transaction: self.transaction,
            mutation_id: self.mutation_id,
            evidence: self.evidence,
            pre_mode: self.pre_mode,
            expected_mode: self.expected_mode,
            reverses_mutation_id: self.reverses_mutation_id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MutationAppendError {
    #[error("permission intent was not durably recorded: {0}")]
    IntentWal(#[source] AppendError),
    #[error("permission mutation failed after durable intent: {0}")]
    Mutation(#[source] io::Error),
    #[error("mutation succeeded but its applied record was not durable: {source}")]
    AppliedWal {
        #[source]
        source: AppendError,
        mutation_applied: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationStatus {
    Applied,
    ConfirmedNotApplied,
    IntentDurableApplicationUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionResolution {
    Applied,
    ConfirmedNotApplied,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("permission intent is not unresolved")]
    NotUnresolved,
    #[error("permission intent cannot be resolved outside its recorded phase")]
    WrongPhase,
    #[error("authorized recovery probe or mutation failed: {0}")]
    Recovery(#[source] io::Error),
    #[error("permission resolution record was not durable: {0}")]
    Wal(#[source] AppendError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePermission {
    pub mutation_id: u64,
    pub phase: TransactionState,
    pub evidence: PersistentRecoveryEvidence,
    pub pre_mode: u32,
    pub expected_mode: u32,
    pub reverses_mutation_id: Option<u64>,
    pub application: ApplicationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedTransaction {
    pub id: TransactionId,
    pub state: TransactionState,
    pub permissions: Vec<DurablePermission>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Replay {
    pub transactions: BTreeMap<TransactionId, ReplayedTransaction>,
    pub tail_repair: Option<TailRepair>,
    pub committed_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailRepair {
    pub truncated_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("failed to access seal WAL: {0}")]
    Io(#[from] io::Error),
    #[error("malformed committed WAL frame at byte {offset}: {reason}")]
    Malformed { offset: u64, reason: &'static str },
    #[error("unsupported WAL version {version} at byte {offset}")]
    UnknownVersion { offset: u64, version: u16 },
    #[error("WAL header checksum mismatch at byte {offset}")]
    HeaderChecksum { offset: u64 },
    #[error("WAL payload checksum mismatch at byte {offset}")]
    Checksum { offset: u64 },
    #[error("invalid transaction history: {0}")]
    InvalidHistory(&'static str),
    #[error("seal WAL exceeds the {limit} byte startup-recovery limit")]
    TooLarge { limit: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryLockError {
    #[error("another startup recovery process holds the WAL recovery lock")]
    Busy,
    #[error("failed to acquire WAL recovery lock: {0}")]
    Io(#[source] io::Error),
}

/// Exclusive, nonblocking `flock` guard that explicitly unlocks on drop.
///
/// Explicit unlock makes the logical guard lifetime authoritative even when an
/// unrelated concurrent `fork` briefly inherits the close-on-exec descriptor.
pub(crate) struct ExclusiveFileLock {
    file: File,
}

impl ExclusiveFileLock {
    pub(crate) fn try_acquire(file: File) -> Result<Self, RecoveryLockError> {
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(RecoveryLockError::Busy),
            Err(std::fs::TryLockError::Error(error)) => Err(RecoveryLockError::Io(error)),
        }
    }

    pub(crate) fn as_file(&self) -> &File {
        &self.file
    }

    fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        // Closing alone does not release `flock` while a fork-inherited duplicate
        // still exists. The descriptor is private, so no duplicate is a legitimate
        // co-owner of this logical lease.
        let _ = self.file.unlock();
    }
}

/// Exclusive, nonblocking lease on the exact WAL descriptor.
///
/// The descriptor is intentionally private: replay, tail repair, and append can
/// only operate on the file that carries this lease. Moving the session into a
/// [`SealWal`] keeps the lock held for the complete writer lifetime.
pub struct RecoverySession {
    lock: ExclusiveFileLock,
    replay: Option<Replay>,
}

impl RecoverySession {
    /// The caller must securely open and validate the WAL and its private parent
    /// directory. [`crate::seal_store::SealWalStore`] is the supported path-based
    /// constructor.
    pub(crate) fn try_acquire(file: File) -> Result<Self, RecoveryLockError> {
        Ok(Self {
            lock: ExclusiveFileLock::try_acquire(file)?,
            replay: None,
        })
    }

    pub(crate) fn as_file(&self) -> &File {
        self.lock.as_file()
    }

    /// Reads committed frames and repairs only a physically partial final frame.
    /// Fully present bad checksums, unknown versions, and malformed interior
    /// records fail closed without truncation.
    pub fn replay_and_repair(&mut self) -> Result<&Replay, ReplayError> {
        let file = self.lock.as_file_mut();
        if file.metadata()?.len() > MAX_WAL_LEN {
            return Err(ReplayError::TooLarge { limit: MAX_WAL_LEN });
        }
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.take(MAX_WAL_LEN + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_WAL_LEN {
            return Err(ReplayError::TooLarge { limit: MAX_WAL_LEN });
        }
        let parsed = parse_frames(&bytes)?;
        let mut replay = replay_records(parsed.records)?;
        if parsed.committed_len < bytes.len() {
            file.set_len(parsed.committed_len as u64)?;
            file.sync_all()?;
            replay.tail_repair = Some(TailRepair {
                truncated_bytes: (bytes.len() - parsed.committed_len) as u64,
            });
        }
        replay.committed_len = parsed.committed_len as u64;
        file.seek(SeekFrom::Start(parsed.committed_len as u64))?;
        self.replay = Some(replay);
        Ok(self.replay.as_ref().unwrap())
    }

    /// Starts a writer for a newly created, empty WAL while retaining this lease.
    pub fn into_new_wal(self) -> Result<SealWal<Self>, AppendError> {
        SealWal::new(self)
    }

    /// Resumes the replayed WAL on this exact descriptor while retaining the
    /// exclusive lease for the writer's complete lifetime. Replay evidence is
    /// stored inside the session, so evidence from another WAL cannot be passed.
    pub fn resume(mut self) -> Result<SealWal<Self>, AppendError> {
        let replay = self.replay.take().ok_or(AppendError::InvalidState(
            "WAL lease has not completed validated replay",
        ))?;
        SealWal::resume(self, &replay)
    }
}

impl Write for RecoverySession {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.lock.as_file_mut().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lock.as_file_mut().flush()
    }
}

impl DurableWrite for RecoverySession {
    fn sync_record(&mut self) -> io::Result<()> {
        self.lock.as_file().sync_all()
    }

    fn prepare_append(&mut self) -> io::Result<u64> {
        self.lock.as_file_mut().seek(SeekFrom::End(0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryIdentity {
    Reestablished,
    Insufficient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryWork {
    Nothing,
    RestoreBeforeRename {
        transaction: TransactionId,
        permissions: Vec<DurablePermission>,
    },
    VerifyOrQuarantineAfterRename {
        transaction: TransactionId,
        permissions: Vec<DurablePermission>,
    },
    ResolveUncertainPermissions {
        transaction: TransactionId,
        permissions: Vec<DurablePermission>,
    },
    PreserveCommittedSeal {
        transaction: TransactionId,
        state: TransactionState,
    },
    PreserveQuarantine {
        transaction: TransactionId,
    },
    RecoveryRequired {
        transaction: TransactionId,
        reason: RecoveryRequiredReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRequiredReason {
    InsufficientPersistentIdentity,
    RenameOutcomeUnknown,
    RecordedRecoveryRequired,
}

/// Converts durable state into work only. The caller must independently obtain
/// live, authority-bearing handles before any chmod/rename/quarantine action.
pub fn decide_recovery<F>(transaction: &ReplayedTransaction, identity: F) -> RecoveryWork
where
    F: Fn(&PersistentRecoveryEvidence) -> RecoveryIdentity,
{
    if transaction.state == TransactionState::RecoveryRequired {
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::RecordedRecoveryRequired,
        };
    }
    if transaction.state == TransactionState::Quarantined {
        return RecoveryWork::PreserveQuarantine {
            transaction: transaction.id,
        };
    }
    if matches!(
        transaction.state,
        TransactionState::VerifiedCommitted
            | TransactionState::Purgeable
            | TransactionState::Purged
    ) {
        return RecoveryWork::PreserveCommittedSeal {
            transaction: transaction.id,
            state: transaction.state,
        };
    }
    if matches!(
        transaction.state,
        TransactionState::Restored | TransactionState::RolledBack
    ) {
        return RecoveryWork::Nothing;
    }
    if transaction.state == TransactionState::RenameIntent {
        // The rename may have completed before a StagedUnverified record became
        // durable. This WAL deliberately has no filesystem authority with which
        // to infer the location, so startup must stop for an authorized probe.
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::RenameOutcomeUnknown,
        };
    }
    let uncertain = transaction
        .permissions
        .iter()
        .filter(|permission| {
            permission.application == ApplicationStatus::IntentDurableApplicationUnknown
        })
        .cloned()
        .collect::<Vec<_>>();
    if !uncertain.is_empty() {
        return RecoveryWork::ResolveUncertainPermissions {
            transaction: transaction.id,
            permissions: uncertain,
        };
    }
    let active_permissions = || {
        transaction
            .permissions
            .iter()
            .filter(|permission| {
                permission.application == ApplicationStatus::Applied
                    && permission.reverses_mutation_id.is_none()
                    && !transaction.permissions.iter().any(|inverse| {
                        inverse.application == ApplicationStatus::Applied
                            && inverse.reverses_mutation_id == Some(permission.mutation_id)
                    })
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    if transaction
        .permissions
        .iter()
        .filter(|permission| {
            permission.application == ApplicationStatus::Applied
                && permission.reverses_mutation_id.is_none()
                && !transaction.permissions.iter().any(|inverse| {
                    inverse.application == ApplicationStatus::Applied
                        && inverse.reverses_mutation_id == Some(permission.mutation_id)
                })
        })
        .any(|permission| identity(&permission.evidence) == RecoveryIdentity::Insufficient)
    {
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::InsufficientPersistentIdentity,
        };
    }
    if matches!(
        transaction.state,
        TransactionState::StagedUnverified
            | TransactionState::StagedSealed
            | TransactionState::RollbackIntent
    ) {
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: transaction.id,
            permissions: active_permissions(),
        }
    } else {
        let mut permissions = active_permissions();
        // Evidence paths are confined beneath one recovery anchor. Restoring
        // deepest objects first keeps every recorded source parent after its
        // descendants; ties retain deterministic mutation-id order.
        permissions.sort_by(|left, right| {
            right
                .evidence
                .relative_path()
                .components()
                .count()
                .cmp(&left.evidence.relative_path().components().count())
                .then_with(|| left.mutation_id.cmp(&right.mutation_id))
        });
        RecoveryWork::RestoreBeforeRename {
            transaction: transaction.id,
            permissions,
        }
    }
}

struct ParsedFrames {
    records: Vec<SealRecord>,
    committed_len: usize,
}

fn parse_frames(bytes: &[u8]) -> Result<ParsedFrames, ReplayError> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            break;
        }
        let header = &bytes[offset..offset + HEADER_LEN];
        if &header[..4] != MAGIC {
            return Err(ReplayError::Malformed {
                offset: offset as u64,
                reason: "bad frame magic",
            });
        }
        let expected_header_crc = u32::from_le_bytes(header[12..16].try_into().unwrap());
        if crc32(&header[4..12]) != expected_header_crc {
            return Err(ReplayError::HeaderChecksum {
                offset: offset as u64,
            });
        }
        let version = u16::from_le_bytes([header[4], header[5]]);
        if version != VERSION {
            return Err(ReplayError::UnknownVersion {
                offset: offset as u64,
                version,
            });
        }
        if header[6] != 0 || header[7] != 0 {
            return Err(ReplayError::Malformed {
                offset: offset as u64,
                reason: "nonzero reserved header bits",
            });
        }
        let payload_len = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(ReplayError::Malformed {
                offset: offset as u64,
                reason: "frame exceeds maximum size",
            });
        }
        let frame_len = HEADER_LEN + payload_len;
        if bytes.len() - offset < frame_len {
            break;
        }
        let expected = u32::from_le_bytes(header[16..20].try_into().unwrap());
        let payload = &bytes[offset + HEADER_LEN..offset + frame_len];
        if crc32(payload) != expected {
            return Err(ReplayError::Checksum {
                offset: offset as u64,
            });
        }
        records.push(decode_record(payload, offset as u64)?);
        offset += frame_len;
    }
    Ok(ParsedFrames {
        records,
        committed_len: offset,
    })
}

#[derive(Default)]
struct ReplayBuilding {
    state: Option<TransactionState>,
    permissions: Vec<DurablePermission>,
    indices: HashMap<u64, (usize, TransactionState)>,
}

fn replay_records(records: Vec<SealRecord>) -> Result<Replay, ReplayError> {
    let mut transactions: BTreeMap<TransactionId, ReplayBuilding> = BTreeMap::new();
    for record in records {
        let id = record.transaction();
        let tx = transactions.entry(id).or_default();
        match record {
            SealRecord::State { state, .. } => {
                if let Some(previous) = tx.state {
                    if state != TransactionState::RecoveryRequired
                        && tx.permissions.iter().any(|permission| {
                            permission.application
                                == ApplicationStatus::IntentDurableApplicationUnknown
                        })
                    {
                        return Err(ReplayError::InvalidHistory(
                            "state advanced with an unresolved permission intent",
                        ));
                    }
                    if !phase_completion_is_valid(tx.permissions.iter(), previous, state) {
                        return Err(ReplayError::InvalidHistory(
                            "seal phase contains a permission intent not durably applied",
                        ));
                    }
                    if matches!(
                        state,
                        TransactionState::Restored | TransactionState::RolledBack
                    ) && !all_applied_seals_have_applied_inverse(tx.permissions.iter())
                    {
                        return Err(ReplayError::InvalidHistory(
                            "terminal restore lacks an applied inverse for an applied seal",
                        ));
                    }
                    if !valid_transition(previous, state) {
                        return Err(ReplayError::InvalidHistory(
                            "invalid transaction transition",
                        ));
                    }
                } else if state != TransactionState::Prepared {
                    return Err(ReplayError::InvalidHistory(
                        "transaction does not start prepared",
                    ));
                }
                tx.state = Some(state);
            }
            SealRecord::PermissionIntent {
                mutation_id,
                evidence,
                pre_mode,
                expected_mode,
                reverses_mutation_id,
                ..
            } => {
                let Some(phase) = tx.state else {
                    return Err(ReplayError::InvalidHistory(
                        "intent precedes prepared state",
                    ));
                };
                if !matches!(
                    phase,
                    TransactionState::ParentSealIntent
                        | TransactionState::TreeSealIntent
                        | TransactionState::RestoreIntent
                        | TransactionState::RollbackIntent
                ) {
                    return Err(ReplayError::InvalidHistory(
                        "permission intent is outside a permission-intent phase",
                    ));
                }
                if tx.indices.contains_key(&mutation_id) {
                    return Err(ReplayError::InvalidHistory("duplicate permission intent"));
                }
                tx.indices
                    .insert(mutation_id, (tx.permissions.len(), phase));
                validate_replayed_inverse(
                    &tx.permissions,
                    phase,
                    mutation_id,
                    &evidence,
                    pre_mode,
                    expected_mode,
                    reverses_mutation_id,
                )?;
                tx.permissions.push(DurablePermission {
                    mutation_id,
                    phase,
                    evidence,
                    pre_mode,
                    expected_mode,
                    reverses_mutation_id,
                    application: ApplicationStatus::IntentDurableApplicationUnknown,
                });
            }
            SealRecord::PermissionApplied { mutation_id, .. } => {
                resolve_replayed_permission(tx, mutation_id, ApplicationStatus::Applied)?
            }
            SealRecord::PermissionNotApplied { mutation_id, .. } => resolve_replayed_permission(
                tx,
                mutation_id,
                ApplicationStatus::ConfirmedNotApplied,
            )?,
        }
    }
    let transactions = transactions
        .into_iter()
        .map(|(id, tx)| {
            let state = tx
                .state
                .ok_or(ReplayError::InvalidHistory("transaction has no state"))?;
            Ok((
                id,
                ReplayedTransaction {
                    id,
                    state,
                    permissions: tx.permissions,
                },
            ))
        })
        .collect::<Result<_, ReplayError>>()?;
    Ok(Replay {
        transactions,
        tail_repair: None,
        committed_len: 0,
    })
}

fn validate_replayed_inverse(
    permissions: &[DurablePermission],
    phase: TransactionState,
    mutation_id: u64,
    evidence: &PersistentRecoveryEvidence,
    pre_mode: u32,
    expected_mode: u32,
    reverses_mutation_id: Option<u64>,
) -> Result<(), ReplayError> {
    match (phase, reverses_mutation_id) {
        (TransactionState::ParentSealIntent | TransactionState::TreeSealIntent, None) => Ok(()),
        (TransactionState::RestoreIntent | TransactionState::RollbackIntent, Some(original_id)) => {
            let original = permissions
                .iter()
                .find(|permission| permission.mutation_id == original_id)
                .ok_or(ReplayError::InvalidHistory(
                    "permission inverse references no mutation in its transaction",
                ))?;
            if original.application != ApplicationStatus::Applied
                || original.reverses_mutation_id.is_some()
                || !same_recovery_object(&original.evidence, evidence)
                || pre_mode != original.expected_mode
                || expected_mode != original.pre_mode
                || permissions.iter().any(|permission| {
                    permission.reverses_mutation_id == Some(original_id)
                        && permission.mutation_id != mutation_id
                        && matches!(
                            permission.application,
                            ApplicationStatus::Applied
                                | ApplicationStatus::IntentDurableApplicationUnknown
                        )
                })
            {
                return Err(ReplayError::InvalidHistory(
                    "permission inverse does not match its applied seal mutation",
                ));
            }
            Ok(())
        }
        _ => Err(ReplayError::InvalidHistory(
            "seal and inverse permission intents are inconsistent with their phase",
        )),
    }
}

fn resolve_replayed_permission(
    transaction: &mut ReplayBuilding,
    mutation_id: u64,
    resolution: ApplicationStatus,
) -> Result<(), ReplayError> {
    let Some((index, intent_phase)) = transaction.indices.get(&mutation_id).copied() else {
        return Err(ReplayError::InvalidHistory(
            "permission resolution has no intent",
        ));
    };
    if transaction.state != Some(intent_phase) {
        return Err(ReplayError::InvalidHistory(
            "permission resolution is outside its intent phase",
        ));
    }
    if transaction.permissions[index].application
        != ApplicationStatus::IntentDurableApplicationUnknown
    {
        return Err(ReplayError::InvalidHistory(
            "duplicate permission resolution",
        ));
    }
    transaction.permissions[index].application = resolution;
    Ok(())
}

fn same_recovery_object(
    left: &PersistentRecoveryEvidence,
    right: &PersistentRecoveryEvidence,
) -> bool {
    left.filesystem_id() == right.filesystem_id()
        && left.device() == right.device()
        && left.inode() == right.inode()
        && left.generation_or_btime() == right.generation_or_btime()
}

fn phase_completion_is_valid<'a>(
    permissions: impl Iterator<Item = &'a DurablePermission>,
    from: TransactionState,
    to: TransactionState,
) -> bool {
    let completed_phase = match (from, to) {
        (TransactionState::ParentSealIntent, TransactionState::ParentSealed) => {
            Some(TransactionState::ParentSealIntent)
        }
        (TransactionState::TreeSealIntent, TransactionState::TreeSealed) => {
            Some(TransactionState::TreeSealIntent)
        }
        _ => None,
    };
    completed_phase.is_none_or(|phase| {
        permissions
            .filter(|permission| permission.phase == phase)
            .all(|permission| permission.application == ApplicationStatus::Applied)
    })
}

fn all_applied_seals_have_applied_inverse<'a>(
    permissions: impl Iterator<Item = &'a DurablePermission>,
) -> bool {
    let permissions = permissions.collect::<Vec<_>>();
    permissions.iter().all(|seal| {
        seal.application != ApplicationStatus::Applied
            || !matches!(
                seal.phase,
                TransactionState::ParentSealIntent | TransactionState::TreeSealIntent
            )
            || permissions.iter().any(|inverse| {
                inverse.application == ApplicationStatus::Applied
                    && inverse.reverses_mutation_id == Some(seal.mutation_id)
            })
    })
}

fn valid_transition(from: TransactionState, to: TransactionState) -> bool {
    use TransactionState as S;
    matches!(
        (from, to),
        // Happy path.
        (S::Prepared, S::ParentSealIntent)
            | (S::ParentSealIntent, S::ParentSealed)
            | (S::ParentSealed, S::TreeSealIntent)
            | (S::TreeSealIntent, S::TreeSealed)
            | (S::TreeSealed, S::RenameIntent)
            | (S::RenameIntent, S::StagedUnverified)
            | (S::StagedUnverified, S::StagedSealed)
            | (S::StagedSealed, S::VerifiedCommitted)
            | (S::VerifiedCommitted, S::Purgeable)
            | (S::Purgeable, S::Purged)
            // Rollback is meaningful only after rename may have happened.
            | (S::StagedUnverified | S::StagedSealed, S::RollbackIntent)
            | (S::RollbackIntent, S::RolledBack)
            // Restore addresses pre-rename seals. RolledBack is terminal.
            | (
                S::Prepared
                    | S::ParentSealIntent
                    | S::ParentSealed
                    | S::TreeSealIntent
                    | S::TreeSealed
                    | S::RenameIntent,
                S::RestoreIntent
            )
            | (S::RestoreIntent, S::Restored)
            // Quarantine is confined to an unverified staged object.
            | (
                S::StagedUnverified | S::StagedSealed | S::RollbackIntent,
                S::Quarantined
            )
            // Any nonterminal state that may still require recovery may stop
            // fail-closed. Terminal outcomes have no outgoing exception edge.
            | (
                S::Prepared
                    | S::ParentSealIntent
                    | S::ParentSealed
                    | S::TreeSealIntent
                    | S::TreeSealed
                    | S::RenameIntent
                    | S::StagedUnverified
                    | S::StagedSealed
                    | S::RollbackIntent
                    | S::RestoreIntent,
                S::RecoveryRequired
            )
    )
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("record field exceeds framing limit")]
    FieldTooLarge,
    #[error("record payload exceeds {limit} bytes")]
    PayloadTooLarge { limit: usize },
}

fn encode_frame(record: &SealRecord) -> Result<Vec<u8>, FrameError> {
    let payload = encode_record(record)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge {
        limit: MAX_PAYLOAD_LEN,
    })?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    let header_checksum = crc32(&frame[4..12]);
    frame.extend_from_slice(&header_checksum.to_le_bytes());
    frame.extend_from_slice(&crc32(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn encode_record(record: &SealRecord) -> Result<Vec<u8>, FrameError> {
    let mut bytes = Vec::new();
    match record {
        SealRecord::State { transaction, state } => {
            bytes.push(1);
            bytes.extend_from_slice(&transaction.0);
            bytes.push(encode_state(*state));
        }
        SealRecord::PermissionIntent {
            transaction,
            mutation_id,
            evidence,
            pre_mode,
            expected_mode,
            reverses_mutation_id,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&transaction.0);
            bytes.extend_from_slice(&mutation_id.to_le_bytes());
            put_bytes(&mut bytes, evidence.relative_path().as_os_str().as_bytes())?;
            put_optional_bytes(&mut bytes, evidence.filesystem_id().map(str::as_bytes))?;
            bytes.extend_from_slice(&evidence.device().to_le_bytes());
            bytes.extend_from_slice(&evidence.inode().to_le_bytes());
            put_optional_u64(&mut bytes, evidence.generation_or_btime());
            bytes.extend_from_slice(&evidence.expected_mode().to_le_bytes());
            bytes.extend_from_slice(&pre_mode.to_le_bytes());
            bytes.extend_from_slice(&expected_mode.to_le_bytes());
            put_optional_u64(&mut bytes, *reverses_mutation_id);
        }
        SealRecord::PermissionApplied {
            transaction,
            mutation_id,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(&transaction.0);
            bytes.extend_from_slice(&mutation_id.to_le_bytes());
        }
        SealRecord::PermissionNotApplied {
            transaction,
            mutation_id,
        } => {
            bytes.push(4);
            bytes.extend_from_slice(&transaction.0);
            bytes.extend_from_slice(&mutation_id.to_le_bytes());
        }
    }
    if bytes.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge {
            limit: MAX_PAYLOAD_LEN,
        });
    }
    Ok(bytes)
}

fn decode_record(payload: &[u8], offset: u64) -> Result<SealRecord, ReplayError> {
    let mut cursor = Cursor::new(payload, offset);
    let tag = cursor.u8()?;
    let transaction = TransactionId(cursor.array_16()?);
    let record = match tag {
        1 => SealRecord::State {
            transaction,
            state: decode_state(cursor.u8()?, offset)?,
        },
        2 => {
            let mutation_id = cursor.u64()?;
            let relative_path = PathBuf::from(std::ffi::OsString::from_vec(cursor.bytes()?));
            let filesystem_id = cursor
                .optional_bytes()?
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| ReplayError::Malformed {
                    offset,
                    reason: "filesystem id is not UTF-8",
                })?;
            let device = cursor.u64()?;
            let inode = cursor.u64()?;
            let generation_or_btime = cursor.optional_u64()?;
            let evidence_mode = cursor.u32()?;
            let pre_mode = cursor.u32()?;
            let expected_mode = cursor.u32()?;
            let reverses_mutation_id = cursor.optional_u64()?;
            if evidence_mode != expected_mode {
                return Err(ReplayError::Malformed {
                    offset,
                    reason: "evidence and intent modes disagree",
                });
            }
            if pre_mode & !0o7777 != 0 || expected_mode & !0o7777 != 0 {
                return Err(ReplayError::Malformed {
                    offset,
                    reason: "permission mode exceeds the supported mode-bit schema",
                });
            }
            let evidence = PersistentRecoveryEvidence::new(
                relative_path,
                filesystem_id,
                device,
                inode,
                generation_or_btime,
                evidence_mode,
            )
            .ok_or(ReplayError::Malformed {
                offset,
                reason: "recovery path is not confined",
            })?;
            SealRecord::PermissionIntent {
                transaction,
                mutation_id,
                evidence,
                pre_mode,
                expected_mode,
                reverses_mutation_id,
            }
        }
        3 => SealRecord::PermissionApplied {
            transaction,
            mutation_id: cursor.u64()?,
        },
        4 => SealRecord::PermissionNotApplied {
            transaction,
            mutation_id: cursor.u64()?,
        },
        _ => {
            return Err(ReplayError::Malformed {
                offset,
                reason: "unknown record kind",
            });
        }
    };
    if !cursor.is_empty() {
        return Err(ReplayError::Malformed {
            offset,
            reason: "trailing record bytes",
        });
    }
    Ok(record)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FrameError::FieldTooLarge)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_optional_bytes(output: &mut Vec<u8>, bytes: Option<&[u8]>) -> Result<(), FrameError> {
    match bytes {
        Some(bytes) => {
            output.push(1);
            put_bytes(output, bytes)?;
        }
        None => output.push(0),
    }
    Ok(())
}

fn put_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_le_bytes());
        }
        None => output.push(0),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: u64,
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], offset: u64) -> Self {
        Self {
            bytes,
            offset,
            position: 0,
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ReplayError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ReplayError::Malformed {
                offset: self.offset,
                reason: "record length overflow",
            })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ReplayError::Malformed {
                offset: self.offset,
                reason: "record payload is truncated",
            })?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ReplayError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ReplayError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array_16(&mut self) -> Result<[u8; 16], ReplayError> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, ReplayError> {
        let len = self.u32()? as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(ReplayError::Malformed {
                offset: self.offset,
                reason: "field exceeds maximum size",
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    fn optional_bytes(&mut self) -> Result<Option<Vec<u8>>, ReplayError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.bytes().map(Some),
            _ => Err(ReplayError::Malformed {
                offset: self.offset,
                reason: "invalid optional field tag",
            }),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, ReplayError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(ReplayError::Malformed {
                offset: self.offset,
                reason: "invalid optional integer tag",
            }),
        }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn encode_state(state: TransactionState) -> u8 {
    use TransactionState as S;
    match state {
        S::Prepared => 0,
        S::ParentSealIntent => 1,
        S::ParentSealed => 2,
        S::TreeSealIntent => 3,
        S::TreeSealed => 4,
        S::RenameIntent => 5,
        S::StagedUnverified => 6,
        S::StagedSealed => 7,
        S::VerifiedCommitted => 8,
        S::Purgeable => 9,
        S::Purged => 10,
        S::RollbackIntent => 11,
        S::RolledBack => 12,
        S::RestoreIntent => 13,
        S::Restored => 14,
        S::Quarantined => 15,
        S::RecoveryRequired => 16,
    }
}

fn decode_state(value: u8, offset: u64) -> Result<TransactionState, ReplayError> {
    use TransactionState as S;
    match value {
        0 => Ok(S::Prepared),
        1 => Ok(S::ParentSealIntent),
        2 => Ok(S::ParentSealed),
        3 => Ok(S::TreeSealIntent),
        4 => Ok(S::TreeSealed),
        5 => Ok(S::RenameIntent),
        6 => Ok(S::StagedUnverified),
        7 => Ok(S::StagedSealed),
        8 => Ok(S::VerifiedCommitted),
        9 => Ok(S::Purgeable),
        10 => Ok(S::Purged),
        11 => Ok(S::RollbackIntent),
        12 => Ok(S::RolledBack),
        13 => Ok(S::RestoreIntent),
        14 => Ok(S::Restored),
        15 => Ok(S::Quarantined),
        16 => Ok(S::RecoveryRequired),
        _ => Err(ReplayError::Malformed {
            offset,
            reason: "unknown transaction state",
        }),
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320_u32 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests;
