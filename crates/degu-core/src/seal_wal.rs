//! Durable, authority-neutral WAL for future seal transactions.
//!
//! This module is intentionally not connected to clean, stage, undo, or purge.
//! It records recovery evidence and emits typed recovery work; neither a path nor
//! `(device, inode)` evidence is an authority token and this module performs no
//! permission or namespace mutation.

use crate::authority::{PersistentRecoveryEvidence, TransactionState};
use crate::local_backend::CertifiedLocalBackend;
use crate::staging_recovery::{
    ExactSourceParentRestoreIntent, ExactSourceParentRestored, ExactStagedVerification,
    ExactVerifiedCommit,
};
use crate::staging_rename::{FreshlyConfirmedSourceResident, ParentsSyncedAppliedRename};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"DSWL";
const VERSION: u16 = 4;
const HEADER_LEN: usize = 20;
const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
const MAX_WAL_LEN: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(pub [u8; 16]);

/// Mandatory strong incarnation component used to reject inode reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIncarnation(u64);

impl ObjectIncarnation {
    pub fn new(generation_or_btime: u64) -> Self {
        Self(generation_or_btime)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrongObjectIdentity {
    device: u64,
    inode: u64,
    incarnation: ObjectIncarnation,
    mount_id: u64,
}

impl StrongObjectIdentity {
    /// A zero mount id is insufficient for live startup recovery.
    pub fn new(device: u64, inode: u64, incarnation: ObjectIncarnation) -> Self {
        Self::new_with_mount(device, inode, incarnation, 0)
    }

    pub fn new_with_mount(
        device: u64,
        inode: u64,
        incarnation: ObjectIncarnation,
        mount_id: u64,
    ) -> Self {
        Self {
            device,
            inode,
            incarnation,
            mount_id,
        }
    }

    pub fn device(self) -> u64 {
        self.device
    }

    pub fn inode(self) -> u64 {
        self.inode
    }

    pub fn incarnation(self) -> ObjectIncarnation {
        self.incarnation
    }

    pub fn mount_id(self) -> u64 {
        self.mount_id
    }
}

/// Confined path evidence beneath a separately authenticated filesystem anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingLocator {
    relative_path: PathBuf,
    filesystem_id: String,
}

impl StagingLocator {
    pub fn new(relative_path: PathBuf, filesystem_id: String) -> Option<Self> {
        (staging_path_is_confined(&relative_path) && !filesystem_id.is_empty()).then_some(Self {
            relative_path,
            filesystem_id,
        })
    }

    pub fn relative_path(&self) -> &std::path::Path {
        &self.relative_path
    }

    pub fn filesystem_id(&self) -> &str {
        &self.filesystem_id
    }
}

fn staging_path_is_confined(path: &std::path::Path) -> bool {
    let mut components = path.components();
    let Some(std::path::Component::Normal(_)) = components.next() else {
        return false;
    };
    components.all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Immutable evidence for an already-exclusive source parent. There is no
/// public constructor: the future held-parent executor must mint this only from
/// an authenticated live parent capability. Replay can decode the durable proof,
/// but durable evidence never recreates execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAlreadyExclusiveParent {
    source_parent: StagingLocator,
    source_parent_identity: StrongObjectIdentity,
    observed_mode: u32,
}

/// Immutable source-parent strategy selected before staging begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableSourceParentStrategy {
    /// The exact metadata-bound source parent must have an applied permission
    /// seal and a matching applied inverse before source-parent restoration.
    PermissionSeal,
    /// Zero parent mutation is permitted only with a non-vacuous, exact-parent
    /// proof minted by the future held-parent executor.
    AlreadyExclusive(DurableAlreadyExclusiveParent),
}

/// Immutable namespace, object, and source-parent strategy binding written in
/// the transaction's first durable frame. Locators are relative to separately
/// authenticated anchors; basenames are single normal components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingTransactionMetadata {
    source_parent: StagingLocator,
    source_parent_identity: StrongObjectIdentity,
    source_basename: std::ffi::OsString,
    root_identity: StrongObjectIdentity,
    destination_parent: StagingLocator,
    destination_parent_identity: StrongObjectIdentity,
    destination_basename: std::ffi::OsString,
    backend: CertifiedLocalBackend,
    source_parent_strategy: DurableSourceParentStrategy,
}

impl StagingTransactionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_parent: StagingLocator,
        source_parent_identity: StrongObjectIdentity,
        source_basename: std::ffi::OsString,
        root_identity: StrongObjectIdentity,
        destination_parent: StagingLocator,
        destination_parent_identity: StrongObjectIdentity,
        destination_basename: std::ffi::OsString,
        backend: CertifiedLocalBackend,
        source_parent_strategy: DurableSourceParentStrategy,
    ) -> Option<Self> {
        let metadata = Self {
            source_parent,
            source_parent_identity,
            source_basename,
            root_identity,
            destination_parent,
            destination_parent_identity,
            destination_basename,
            backend,
            source_parent_strategy,
        };
        metadata.invariants_hold().then_some(metadata)
    }

    pub fn source_parent(&self) -> &StagingLocator {
        &self.source_parent
    }

    pub fn source_parent_identity(&self) -> StrongObjectIdentity {
        self.source_parent_identity
    }

    pub fn source_basename(&self) -> &std::ffi::OsStr {
        &self.source_basename
    }

    pub fn root_identity(&self) -> StrongObjectIdentity {
        self.root_identity
    }

    pub fn destination_parent(&self) -> &StagingLocator {
        &self.destination_parent
    }

    pub fn destination_parent_identity(&self) -> StrongObjectIdentity {
        self.destination_parent_identity
    }

    pub fn destination_basename(&self) -> &std::ffi::OsStr {
        &self.destination_basename
    }

    pub fn backend(&self) -> CertifiedLocalBackend {
        self.backend
    }

    pub fn source_parent_strategy(&self) -> &DurableSourceParentStrategy {
        &self.source_parent_strategy
    }

    pub fn filesystem_id(&self) -> &str {
        self.source_parent.filesystem_id()
    }

    fn invariants_hold(&self) -> bool {
        let normal_name = |name: &std::ffi::OsStr| {
            let path = std::path::Path::new(name);
            let mut components = path.components();
            matches!(components.next(), Some(std::path::Component::Normal(_)))
                && components.next().is_none()
        };
        let locator_is_valid = |locator: &StagingLocator| {
            staging_path_is_confined(&locator.relative_path) && !locator.filesystem_id.is_empty()
        };
        let strategy_is_bound = match &self.source_parent_strategy {
            DurableSourceParentStrategy::PermissionSeal => true,
            DurableSourceParentStrategy::AlreadyExclusive(proof) => {
                proof.source_parent == self.source_parent
                    && proof.source_parent_identity == self.source_parent_identity
                    && mode_is_exclusive_parent(proof.observed_mode)
            }
        };
        locator_is_valid(&self.source_parent)
            && locator_is_valid(&self.destination_parent)
            && self.source_parent.filesystem_id == self.destination_parent.filesystem_id
            && self.source_parent_identity.mount_id != 0
            && self.source_parent_identity.mount_id == self.root_identity.mount_id
            && self.root_identity.mount_id == self.destination_parent_identity.mount_id
            && normal_name(&self.source_basename)
            && normal_name(&self.destination_basename)
            && (self.source_parent.relative_path != self.destination_parent.relative_path
                || self.source_basename != self.destination_basename)
            && strategy_is_bound
    }

    #[cfg(test)]
    pub(crate) fn invalidate_for_test(&mut self) {
        self.source_basename = std::ffi::OsString::from("../invalid");
    }
}

fn mode_is_exclusive_parent(mode: u32) -> bool {
    mode & !0o7777 == 0 && mode & 0o300 == 0o300 && mode & 0o030 != 0o030 && mode & 0o003 != 0o003
}

/// Completion marker for the exact sealed tree selected by the future held-tree
/// engine. The digest algorithm is fixed by this schema to SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableTreeManifest {
    pub entry_count: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRenameOutcome {
    /// The root is at the destination and both source and destination parent
    /// directory fsyncs completed successfully.
    AppliedAndParentsSynced(StrongObjectIdentity),
    /// The root remains at the source; no namespace mutation was applied.
    ConfirmedNotAppliedAtSource(StrongObjectIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // durable schema favors explicit, allocation-free records
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
    StagingBegin {
        transaction: TransactionId,
        metadata: StagingTransactionMetadata,
    },
    TreeManifestComplete {
        transaction: TransactionId,
        manifest: DurableTreeManifest,
    },
    RenameIntent {
        transaction: TransactionId,
    },
    RenameOutcome {
        transaction: TransactionId,
        outcome: DurableRenameOutcome,
    },
}

impl SealRecord {
    fn transaction(&self) -> TransactionId {
        match self {
            Self::State { transaction, .. }
            | Self::PermissionIntent { transaction, .. }
            | Self::PermissionApplied { transaction, .. }
            | Self::PermissionNotApplied { transaction, .. }
            | Self::StagingBegin { transaction, .. }
            | Self::TreeManifestComplete { transaction, .. }
            | Self::RenameIntent { transaction }
            | Self::RenameOutcome { transaction, .. } => *transaction,
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
    staging_schema_versions: HashMap<TransactionId, u16>,
    used_mutations: HashSet<(TransactionId, u64)>,
    permissions: HashMap<(TransactionId, u64), DurablePermission>,
    unresolved_mutations: HashMap<(TransactionId, u64), DurablePermission>,
    staging: HashMap<TransactionId, StagingTransactionMetadata>,
    manifests: HashMap<TransactionId, DurableTreeManifest>,
    rename_outcomes: HashMap<TransactionId, DurableRenameOutcome>,
    committed_len: u64,
    max_wal_len: u64,
}

impl<W: DurableWrite> SealWal<W> {
    #[allow(dead_code)] // authority-neutral A1 constructor retained for future coordinator
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
            staging_schema_versions: HashMap::new(),
            used_mutations: HashSet::new(),
            permissions: HashMap::new(),
            unresolved_mutations: HashMap::new(),
            staging: HashMap::new(),
            manifests: HashMap::new(),
            rename_outcomes: HashMap::new(),
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
            if let Some(version) = transaction.staging_schema_version {
                wal.staging_schema_versions.insert(transaction.id, version);
            }
            if let Some(metadata) = &transaction.staging {
                wal.staging.insert(transaction.id, metadata.clone());
            }
            if let Some(manifest) = transaction.tree_manifest {
                wal.manifests.insert(transaction.id, manifest);
            }
            if let Some(outcome) = transaction.rename_outcome {
                wal.rename_outcomes.insert(transaction.id, outcome);
            }
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

    /// Atomically begins a staging transaction with its immutable namespace and
    /// strong source-identity binding in the first durable frame.
    pub(crate) fn begin_staging(
        &mut self,
        transaction: TransactionId,
        metadata: StagingTransactionMetadata,
    ) -> Result<(), AppendError> {
        if self.states.contains_key(&transaction) {
            return Err(AppendError::InvalidState("transaction already exists"));
        }
        if !metadata.invariants_hold() {
            return Err(AppendError::InvalidState(
                "staging metadata invariants are invalid",
            ));
        }
        self.append_synced(&SealRecord::StagingBegin {
            transaction,
            metadata: metadata.clone(),
        })?;
        self.states.insert(transaction, TransactionState::Prepared);
        self.staging.insert(transaction, metadata);
        self.staging_schema_versions.insert(transaction, VERSION);
        Ok(())
    }

    pub(crate) fn staging_metadata(
        &self,
        transaction: TransactionId,
    ) -> Option<&StagingTransactionMetadata> {
        self.staging.get(&transaction)
    }

    pub(crate) fn transaction_state(&self, transaction: TransactionId) -> Option<TransactionState> {
        self.states.get(&transaction).copied()
    }

    /// Exact in-memory projection of the transaction held by this leased WAL.
    /// Recovery must derive work from this snapshot rather than caller-provided
    /// permission subsets or durable-path guesses.
    pub(crate) fn recovery_snapshots(&self) -> Vec<ReplayedTransaction> {
        let mut transactions = self.states.keys().copied().collect::<Vec<_>>();
        transactions.sort();
        transactions
            .into_iter()
            .filter_map(|transaction| self.recovery_snapshot(transaction))
            .collect()
    }

    pub(crate) fn recovery_snapshot(
        &self,
        transaction: TransactionId,
    ) -> Option<ReplayedTransaction> {
        let state = self.states.get(&transaction).copied()?;
        let mut permissions = self
            .permissions
            .iter()
            .filter_map(|((owner, _), permission)| {
                (*owner == transaction).then_some(permission.clone())
            })
            .collect::<Vec<_>>();
        permissions.sort_by_key(|permission| permission.mutation_id);
        Some(ReplayedTransaction {
            id: transaction,
            state,
            staging_schema_version: self.staging_schema_versions.get(&transaction).copied(),
            permissions,
            staging: self.staging.get(&transaction).cloned(),
            tree_manifest: self.manifests.get(&transaction).copied(),
            rename_outcome: self.rename_outcomes.get(&transaction).copied(),
        })
    }

    /// Allocates the next transaction-local mutation id for startup recovery.
    /// IDs are never reused across original seals, failed intents, or inverses.
    #[allow(dead_code)] // consumed by the startup recovery execution seam
    pub(crate) fn next_recovery_mutation_id(&self, transaction: TransactionId) -> Option<u64> {
        self.used_mutations
            .iter()
            .filter_map(|(owner, id)| (*owner == transaction).then_some(*id))
            .max()
            .map_or(Some(0), |id| id.checked_add(1))
    }

    #[cfg(test)]
    pub(crate) fn poison_for_test(&mut self) {
        self.poisoned = true;
    }

    pub(crate) fn can_begin_staging_transaction(&self) -> bool {
        !self.poisoned
            && self.states.iter().all(|(transaction, state)| {
                matches!(
                    state,
                    TransactionState::VerifiedCommitted
                        | TransactionState::Purgeable
                        | TransactionState::Purged
                        | TransactionState::Restored
                        | TransactionState::RolledBack
                ) || (*state == TransactionState::Quarantined
                    && !retains_active_permission_seals(
                        self.permissions
                            .iter()
                            .filter(|((owner, _), _)| owner == transaction)
                            .map(|(_, permission)| permission),
                    ))
            })
    }

    /// Authority-neutral A1 transition. Staging transactions are deliberately
    /// excluded and can be advanced only by the crate-private high-level engine.
    pub fn transition(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        if self.staging.contains_key(&transaction) {
            return Err(AppendError::InvalidState(
                "staging transitions require the high-level engine",
            ));
        }
        self.transition_inner(transaction, next)
    }

    fn transition_staging(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        if !self.staging.contains_key(&transaction) {
            return Err(AppendError::InvalidState("transaction is not staged"));
        }
        self.transition_inner(transaction, next)
    }

    /// Narrow A3 foundation transitions. Verification, source-parent commit,
    /// verified commit, and purge states require separate unforgeable proofs.
    pub(crate) fn transition_staging_foundation(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        if !matches!(
            next,
            TransactionState::ParentSealIntent
                | TransactionState::ParentSealed
                | TransactionState::TreeSealIntent
                | TransactionState::TreeSealed
                | TransactionState::StagedUnverified
                | TransactionState::RestoreIntent
                | TransactionState::Restored
                | TransactionState::Quarantined
                | TransactionState::RecoveryRequired
        ) {
            return Err(AppendError::InvalidState(
                "staging state requires an unavailable authority proof",
            ));
        }
        self.transition_staging(transaction, next)
    }

    pub(crate) fn record_staged_sealed(
        &mut self,
        proof: ExactStagedVerification,
    ) -> Result<(), AppendError> {
        self.transition_staging(proof.transaction(), TransactionState::StagedSealed)
    }

    pub(crate) fn record_source_parent_restore_intent(
        &mut self,
        proof: ExactSourceParentRestoreIntent,
    ) -> Result<(), AppendError> {
        self.transition_staging(
            proof.transaction(),
            TransactionState::SourceParentRestoreIntent,
        )
    }

    pub(crate) fn record_source_parent_restored(
        &mut self,
        proof: ExactSourceParentRestored,
    ) -> Result<(), AppendError> {
        self.transition_staging(proof.transaction(), TransactionState::SourceParentRestored)
    }

    pub(crate) fn record_verified_committed(
        &mut self,
        proof: ExactVerifiedCommit,
    ) -> Result<(), AppendError> {
        self.transition_staging(proof.transaction(), TransactionState::VerifiedCommitted)
    }

    #[cfg(test)]
    pub(crate) fn transition_staging_for_test(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        self.transition_staging(transaction, next)
    }

    /// Fail-closed transition shared by authority-neutral and staging executors.
    pub(crate) fn transition_recovery_required(
        &mut self,
        transaction: TransactionId,
    ) -> Result<(), AppendError> {
        self.transition_inner(transaction, TransactionState::RecoveryRequired)
    }

    fn transition_inner(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), AppendError> {
        let Some(current) = self.states.get(&transaction).copied() else {
            return Err(AppendError::InvalidState("transaction has not begun"));
        };
        if next == TransactionState::RenameIntent {
            return Err(AppendError::InvalidState(
                "rename intent requires its explicit durable record",
            ));
        }
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
        if current == TransactionState::ParentSealIntent
            && next == TransactionState::ParentSealed
            && !staging_parent_strategy_is_complete(
                self.staging.get(&transaction),
                self.permissions
                    .iter()
                    .filter(|((owner, _), _)| *owner == transaction)
                    .map(|(_, permission)| permission),
            )
        {
            return Err(AppendError::InvalidState(
                "source-parent strategy lacks its required durable proof",
            ));
        }
        if next == TransactionState::SourceParentRestored
            && !all_applied_parent_seals_have_applied_inverse(
                self.permissions
                    .iter()
                    .filter(|((owner, _), _)| *owner == transaction)
                    .map(|(_, permission)| permission),
            )
        {
            return Err(AppendError::InvalidState(
                "source-parent restoration requires applied inverses",
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
        if current == TransactionState::TreeSealIntent
            && next == TransactionState::TreeSealed
            && !self.manifests.contains_key(&transaction)
        {
            return Err(AppendError::InvalidState(
                "tree seal completion requires a durable manifest digest",
            ));
        }
        if current == TransactionState::RenameIntent {
            match (self.rename_outcomes.get(&transaction), next) {
                (
                    Some(DurableRenameOutcome::AppliedAndParentsSynced(_)),
                    TransactionState::StagedUnverified,
                )
                | (
                    Some(DurableRenameOutcome::ConfirmedNotAppliedAtSource(_)),
                    TransactionState::RestoreIntent,
                )
                | (_, TransactionState::RecoveryRequired) => {}
                _ => {
                    return Err(AppendError::InvalidState(
                        "rename transition lacks a matching durable outcome",
                    ));
                }
            }
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

    /// Durably completes the exact tree manifest after all tree seal intents
    /// have resolved Applied. The future held-tree implementation computes the
    /// digest; this WAL method only enforces ordering and uniqueness.
    #[allow(dead_code)] // consumed by the held-tree coordinator seam
    pub(crate) fn complete_tree_manifest(
        &mut self,
        transaction: TransactionId,
        manifest: DurableTreeManifest,
    ) -> Result<(), AppendError> {
        if self.states.get(&transaction).copied() != Some(TransactionState::TreeSealIntent) {
            return Err(AppendError::InvalidState(
                "tree manifest is outside tree seal intent",
            ));
        }
        if self.manifests.contains_key(&transaction)
            || self
                .unresolved_mutations
                .keys()
                .any(|(owner, _)| *owner == transaction)
            || self.permissions.iter().any(|((owner, _), permission)| {
                *owner == transaction
                    && permission.phase == TransactionState::TreeSealIntent
                    && permission.application != ApplicationStatus::Applied
            })
        {
            return Err(AppendError::InvalidState(
                "tree manifest is duplicate or permission work is unresolved",
            ));
        }
        self.append_synced(&SealRecord::TreeManifestComplete {
            transaction,
            manifest,
        })?;
        self.manifests.insert(transaction, manifest);
        Ok(())
    }

    /// Atomically transitions TreeSealed to RenameIntent using an explicit WAL
    /// record. Actual namespace authority remains outside this module.
    #[allow(dead_code)] // consumed by the held-tree coordinator seam
    pub(crate) fn record_rename_intent(
        &mut self,
        transaction: TransactionId,
    ) -> Result<(), AppendError> {
        if self.states.get(&transaction).copied() != Some(TransactionState::TreeSealed)
            || !self.staging.contains_key(&transaction)
            || !self.manifests.contains_key(&transaction)
        {
            return Err(AppendError::InvalidState(
                "rename intent requires staging metadata and a complete sealed tree",
            ));
        }
        self.append_synced(&SealRecord::RenameIntent { transaction })?;
        self.states
            .insert(transaction, TransactionState::RenameIntent);
        Ok(())
    }

    pub(crate) fn record_applied_synced_rename(
        &mut self,
        transaction: TransactionId,
        proof: ParentsSyncedAppliedRename,
    ) -> Result<(), AppendError> {
        self.record_rename_outcome(
            transaction,
            DurableRenameOutcome::AppliedAndParentsSynced(proof.identity()),
        )
    }

    pub(crate) fn record_confirmed_not_applied_rename(
        &mut self,
        transaction: TransactionId,
        proof: FreshlyConfirmedSourceResident,
    ) -> Result<(), AppendError> {
        self.record_rename_outcome(
            transaction,
            DurableRenameOutcome::ConfirmedNotAppliedAtSource(proof.identity()),
        )
    }

    /// Private codec/state validation behind the two proof-consuming writers.
    fn record_rename_outcome(
        &mut self,
        transaction: TransactionId,
        outcome: DurableRenameOutcome,
    ) -> Result<(), AppendError> {
        if self.states.get(&transaction).copied() != Some(TransactionState::RenameIntent)
            || self.rename_outcomes.contains_key(&transaction)
        {
            return Err(AppendError::InvalidState(
                "rename outcome is outside a unique rename intent",
            ));
        }
        let identity = self
            .staging
            .get(&transaction)
            .ok_or(AppendError::InvalidState("transaction is not staged"))?
            .root_identity;
        let outcome_identity = match outcome {
            DurableRenameOutcome::AppliedAndParentsSynced(identity)
            | DurableRenameOutcome::ConfirmedNotAppliedAtSource(identity) => identity,
        };
        if outcome_identity != identity {
            return Err(AppendError::InvalidState(
                "rename outcome does not bind the staged root identity",
            ));
        }
        self.append_synced(&SealRecord::RenameOutcome {
            transaction,
            outcome,
        })?;
        self.rename_outcomes.insert(transaction, outcome);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_applied_rename_for_test(
        &mut self,
        transaction: TransactionId,
    ) -> Result<(), AppendError> {
        let identity = self
            .staging
            .get(&transaction)
            .ok_or(AppendError::InvalidState("transaction is not staged"))?
            .root_identity;
        self.record_rename_outcome(
            transaction,
            DurableRenameOutcome::AppliedAndParentsSynced(identity),
        )
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
        if self.staging.contains_key(&intent.transaction) {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "staging permission mutation requires the high-level engine",
            )));
        }
        self.apply_permission_mutation_inner(intent, mutate)
    }

    #[allow(dead_code)] // future held-tree coordinator only
    pub(crate) fn apply_staging_permission_mutation<F>(
        &mut self,
        intent: PermissionIntent,
        mutate: F,
    ) -> Result<(), MutationAppendError>
    where
        F: FnOnce() -> io::Result<()>,
    {
        if !self.staging.contains_key(&intent.transaction) {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "transaction is not staged",
            )));
        }
        self.apply_permission_mutation_inner(intent, mutate)
    }

    fn apply_permission_mutation_inner<F>(
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
                    | TransactionState::SourceParentRestoreIntent
                    | TransactionState::RollbackIntent
                    | TransactionState::Quarantined
            )
        ) {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "permission mutation is outside an intent phase",
            )));
        }
        if phase == Some(TransactionState::TreeSealIntent)
            && self.manifests.contains_key(&transaction)
        {
            return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                "tree permission membership is frozen by the manifest",
            )));
        }
        if let Some(metadata) = self.staging.get(&transaction) {
            if intent.evidence.filesystem_id() != Some(metadata.filesystem_id())
                || intent.evidence.generation_or_btime().is_none()
            {
                return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                    "staging permission evidence lacks the bound filesystem or strong incarnation",
                )));
            }
            if phase == Some(TransactionState::ParentSealIntent)
                && (!matches!(
                    metadata.source_parent_strategy,
                    DurableSourceParentStrategy::PermissionSeal
                ) || !evidence_is_exact_source_parent(&intent.evidence, metadata))
            {
                return Err(MutationAppendError::IntentWal(AppendError::InvalidState(
                    "parent seal evidence is not the exact metadata-bound source parent",
                )));
            }
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
                TransactionState::RestoreIntent
                | TransactionState::SourceParentRestoreIntent
                | TransactionState::RollbackIntent
                | TransactionState::Quarantined,
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
                    || (phase == Some(TransactionState::SourceParentRestoreIntent)
                        && original.phase != TransactionState::ParentSealIntent)
                    || !same_recovery_object(&original.evidence, &intent.evidence)
                    || (original.phase == TransactionState::ParentSealIntent
                        && self.staging.get(&transaction).is_some_and(|metadata| {
                            !evidence_is_exact_source_parent(&intent.evidence, metadata)
                        }))
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
        if self.staging.contains_key(&transaction) {
            return Err(ResolveError::WrongPhase);
        }
        self.resolve_unresolved_permission_inner(transaction, mutation_id, resolve)
    }

    #[allow(dead_code)] // future authorized staging recovery only
    pub(crate) fn resolve_staging_permission<F>(
        &mut self,
        transaction: TransactionId,
        mutation_id: u64,
        resolve: F,
    ) -> Result<PermissionResolution, ResolveError>
    where
        F: FnOnce(&DurablePermission) -> io::Result<PermissionResolution>,
    {
        if !self.staging.contains_key(&transaction) {
            return Err(ResolveError::WrongPhase);
        }
        self.resolve_unresolved_permission_inner(transaction, mutation_id, resolve)
    }

    fn resolve_unresolved_permission_inner<F>(
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
    /// Schema version of the transaction's atomic `StagingBegin` frame.
    /// Later legacy-version state fixtures do not weaken v4 staging metadata.
    pub staging_schema_version: Option<u16>,
    pub permissions: Vec<DurablePermission>,
    pub staging: Option<StagingTransactionMetadata>,
    pub tree_manifest: Option<DurableTreeManifest>,
    pub rename_outcome: Option<DurableRenameOutcome>,
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
    #[error(
        "unsupported legacy WAL version {version} at byte {offset}; supported legacy versions are 1 and 3"
    )]
    UnsupportedLegacyVersion { offset: u64, version: u16 },
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
    #[allow(dead_code)] // authority-neutral A1 constructor retained for future coordinator
    pub(crate) fn into_new_wal(self) -> Result<SealWal<Self>, AppendError> {
        SealWal::new(self)
    }

    /// Resumes the replayed WAL on this exact descriptor while retaining the
    /// exclusive lease for the writer's complete lifetime. Replay evidence is
    /// stored inside the session, so evidence from another WAL cannot be passed.
    pub(crate) fn resume(mut self) -> Result<SealWal<Self>, AppendError> {
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
    RestoreSourceParentAfterRename {
        transaction: TransactionId,
        permissions: Vec<DurablePermission>,
    },
    RestoreQuarantinedSeals {
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
    FinalizeVerifiedCommit {
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
    LegacySchemaMissingMountIdentity { version: u16 },
}

pub(crate) fn quarantined_transaction_retains_active_permission_seals(
    transaction: &ReplayedTransaction,
) -> bool {
    transaction.state == TransactionState::Quarantined
        && retains_active_permission_seals(transaction.permissions.iter())
}

fn staging_recovery_needs_mount_authority(transaction: &ReplayedTransaction) -> bool {
    match transaction.state {
        TransactionState::VerifiedCommitted
        | TransactionState::Restored
        | TransactionState::RolledBack
        | TransactionState::Purged
        | TransactionState::Purgeable
        | TransactionState::RecoveryRequired => false,
        TransactionState::Quarantined => {
            quarantined_transaction_retains_active_permission_seals(transaction)
        }
        _ => true,
    }
}

/// Converts durable state into work only. The caller must independently obtain
/// live, authority-bearing handles before any chmod/rename/quarantine action.
pub fn decide_recovery<F>(transaction: &ReplayedTransaction, identity: F) -> RecoveryWork
where
    F: Fn(&PersistentRecoveryEvidence) -> RecoveryIdentity,
{
    if let Some(version @ 0..=3) = transaction.staging_schema_version
        && staging_recovery_needs_mount_authority(transaction)
    {
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::LegacySchemaMissingMountIdentity { version },
        };
    }
    if transaction.state == TransactionState::RecoveryRequired {
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::RecordedRecoveryRequired,
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
    if transaction.state == TransactionState::Quarantined {
        let mut permissions = active_permissions();
        if permissions.is_empty() {
            return RecoveryWork::PreserveQuarantine {
                transaction: transaction.id,
            };
        }
        sort_permissions_deepest_first(&mut permissions);
        return RecoveryWork::RestoreQuarantinedSeals {
            transaction: transaction.id,
            permissions,
        };
    }
    if transaction.state == TransactionState::RenameIntent && transaction.rename_outcome.is_none() {
        // No durable outcome exists from which to choose a side of the rename.
        // The WAL has no filesystem authority with which to infer the location.
        return RecoveryWork::RecoveryRequired {
            transaction: transaction.id,
            reason: RecoveryRequiredReason::RenameOutcomeUnknown,
        };
    }
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
    if transaction.state == TransactionState::RenameIntent {
        return match transaction.rename_outcome {
            Some(DurableRenameOutcome::AppliedAndParentsSynced(_)) => {
                RecoveryWork::VerifyOrQuarantineAfterRename {
                    transaction: transaction.id,
                    permissions: active_permissions(),
                }
            }
            Some(DurableRenameOutcome::ConfirmedNotAppliedAtSource(_)) => {
                let mut permissions = active_permissions();
                sort_permissions_deepest_first(&mut permissions);
                RecoveryWork::RestoreBeforeRename {
                    transaction: transaction.id,
                    permissions,
                }
            }
            None => unreachable!("missing rename outcome handled before identity gating"),
        };
    }
    if matches!(
        transaction.state,
        TransactionState::StagedSealed | TransactionState::SourceParentRestoreIntent
    ) {
        return RecoveryWork::RestoreSourceParentAfterRename {
            transaction: transaction.id,
            permissions: active_permissions()
                .into_iter()
                .filter(|permission| permission.phase == TransactionState::ParentSealIntent)
                .collect(),
        };
    }
    if transaction.state == TransactionState::SourceParentRestored {
        return RecoveryWork::FinalizeVerifiedCommit {
            transaction: transaction.id,
        };
    }
    if matches!(
        transaction.state,
        TransactionState::StagedUnverified | TransactionState::RollbackIntent
    ) {
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: transaction.id,
            permissions: active_permissions(),
        }
    } else {
        let mut permissions = active_permissions();
        sort_permissions_deepest_first(&mut permissions);
        RecoveryWork::RestoreBeforeRename {
            transaction: transaction.id,
            permissions,
        }
    }
}

fn sort_permissions_deepest_first(permissions: &mut [DurablePermission]) {
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
}

#[derive(Debug)]
struct VersionedRecord {
    version: u16,
    record: SealRecord,
}

trait IntoVersionedRecord {
    fn into_versioned(self) -> VersionedRecord;
}

impl IntoVersionedRecord for VersionedRecord {
    fn into_versioned(self) -> VersionedRecord {
        self
    }
}

impl IntoVersionedRecord for SealRecord {
    fn into_versioned(self) -> VersionedRecord {
        VersionedRecord {
            version: VERSION,
            record: self,
        }
    }
}

struct ParsedFrames {
    records: Vec<VersionedRecord>,
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
        if !matches!(version, 1 | 3 | VERSION) {
            return Err(ReplayError::UnsupportedLegacyVersion {
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
        records.push(VersionedRecord {
            version,
            record: decode_record(payload, offset as u64, version)?,
        });
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
    staging_schema_version: Option<u16>,
    permissions: Vec<DurablePermission>,
    indices: HashMap<u64, (usize, TransactionState)>,
    staging: Option<StagingTransactionMetadata>,
    tree_manifest: Option<DurableTreeManifest>,
    rename_outcome: Option<DurableRenameOutcome>,
}

fn replay_records<R: IntoVersionedRecord>(records: Vec<R>) -> Result<Replay, ReplayError> {
    let mut transactions: BTreeMap<TransactionId, ReplayBuilding> = BTreeMap::new();
    for record in records {
        let versioned = record.into_versioned();
        let record = versioned.record;
        let id = record.transaction();
        let tx = transactions.entry(id).or_default();
        match record {
            SealRecord::StagingBegin { metadata, .. } => {
                tx.staging_schema_version = Some(versioned.version);
                if tx.state.is_some() || tx.staging.is_some() {
                    return Err(ReplayError::InvalidHistory(
                        "staging transaction has a duplicate or noninitial begin",
                    ));
                }
                tx.state = Some(TransactionState::Prepared);
                tx.staging = Some(metadata);
            }
            SealRecord::TreeManifestComplete { manifest, .. } => {
                if tx.state != Some(TransactionState::TreeSealIntent)
                    || tx.tree_manifest.is_some()
                    || tx.permissions.iter().any(|permission| {
                        permission.application == ApplicationStatus::IntentDurableApplicationUnknown
                            || (permission.phase == TransactionState::TreeSealIntent
                                && permission.application != ApplicationStatus::Applied)
                    })
                {
                    return Err(ReplayError::InvalidHistory(
                        "tree manifest is duplicate, unordered, or has unresolved permissions",
                    ));
                }
                tx.tree_manifest = Some(manifest);
            }
            SealRecord::RenameIntent { .. } => {
                if tx.state != Some(TransactionState::TreeSealed)
                    || tx.staging.is_none()
                    || tx.tree_manifest.is_none()
                {
                    return Err(ReplayError::InvalidHistory(
                        "rename intent lacks staging metadata or a completed tree manifest",
                    ));
                }
                tx.state = Some(TransactionState::RenameIntent);
            }
            SealRecord::RenameOutcome { outcome, .. } => {
                if tx.state != Some(TransactionState::RenameIntent) || tx.rename_outcome.is_some() {
                    return Err(ReplayError::InvalidHistory(
                        "rename outcome is duplicate or outside rename intent",
                    ));
                }
                let expected = tx
                    .staging
                    .as_ref()
                    .ok_or(ReplayError::InvalidHistory(
                        "rename outcome has no staging metadata",
                    ))?
                    .root_identity;
                let actual = match outcome {
                    DurableRenameOutcome::AppliedAndParentsSynced(identity)
                    | DurableRenameOutcome::ConfirmedNotAppliedAtSource(identity) => identity,
                };
                if actual != expected {
                    return Err(ReplayError::InvalidHistory(
                        "rename outcome identity differs from the bound root",
                    ));
                }
                tx.rename_outcome = Some(outcome);
            }
            SealRecord::State { state, .. } => {
                if let Some(previous) = tx.state {
                    if state == TransactionState::RenameIntent {
                        return Err(ReplayError::InvalidHistory(
                            "rename intent must use its explicit record",
                        ));
                    }
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
                    if previous == TransactionState::ParentSealIntent
                        && state == TransactionState::ParentSealed
                        && !staging_parent_strategy_is_complete(
                            tx.staging.as_ref(),
                            tx.permissions.iter(),
                        )
                    {
                        return Err(ReplayError::InvalidHistory(
                            "source-parent strategy lacks its required durable proof",
                        ));
                    }
                    if state == TransactionState::SourceParentRestored
                        && !all_applied_parent_seals_have_applied_inverse(tx.permissions.iter())
                    {
                        return Err(ReplayError::InvalidHistory(
                            "source-parent restoration lacks applied inverses",
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
                    if previous == TransactionState::TreeSealIntent
                        && state == TransactionState::TreeSealed
                        && tx.tree_manifest.is_none()
                    {
                        return Err(ReplayError::InvalidHistory(
                            "tree seal completed without a manifest digest",
                        ));
                    }
                    if previous == TransactionState::RenameIntent {
                        match (tx.rename_outcome, state) {
                            (
                                Some(DurableRenameOutcome::AppliedAndParentsSynced(_)),
                                TransactionState::StagedUnverified,
                            )
                            | (
                                Some(DurableRenameOutcome::ConfirmedNotAppliedAtSource(_)),
                                TransactionState::RestoreIntent,
                            )
                            | (_, TransactionState::RecoveryRequired) => {}
                            _ => {
                                return Err(ReplayError::InvalidHistory(
                                    "rename transition lacks a matching durable outcome",
                                ));
                            }
                        }
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
                        | TransactionState::SourceParentRestoreIntent
                        | TransactionState::RollbackIntent
                        | TransactionState::Quarantined
                ) {
                    return Err(ReplayError::InvalidHistory(
                        "permission intent is outside a permission-intent phase",
                    ));
                }
                if phase == TransactionState::TreeSealIntent && tx.tree_manifest.is_some() {
                    return Err(ReplayError::InvalidHistory(
                        "tree permission membership changed after manifest completion",
                    ));
                }
                if let Some(metadata) = &tx.staging {
                    if evidence.filesystem_id() != Some(metadata.filesystem_id())
                        || evidence.generation_or_btime().is_none()
                    {
                        return Err(ReplayError::InvalidHistory(
                            "staging permission lacks bound filesystem or strong incarnation",
                        ));
                    }
                    if phase == TransactionState::ParentSealIntent
                        && (!matches!(
                            metadata.source_parent_strategy,
                            DurableSourceParentStrategy::PermissionSeal
                        ) || !evidence_is_exact_source_parent(&evidence, metadata))
                    {
                        return Err(ReplayError::InvalidHistory(
                            "parent seal evidence differs from the metadata-bound source parent",
                        ));
                    }
                }
                if tx.indices.contains_key(&mutation_id) {
                    return Err(ReplayError::InvalidHistory("duplicate permission intent"));
                }
                tx.indices
                    .insert(mutation_id, (tx.permissions.len(), phase));
                validate_replayed_inverse(
                    &tx.permissions,
                    tx.staging.as_ref(),
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
                    staging_schema_version: tx.staging_schema_version,
                    permissions: tx.permissions,
                    staging: tx.staging,
                    tree_manifest: tx.tree_manifest,
                    rename_outcome: tx.rename_outcome,
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

#[allow(clippy::too_many_arguments)]
fn validate_replayed_inverse(
    permissions: &[DurablePermission],
    staging: Option<&StagingTransactionMetadata>,
    phase: TransactionState,
    mutation_id: u64,
    evidence: &PersistentRecoveryEvidence,
    pre_mode: u32,
    expected_mode: u32,
    reverses_mutation_id: Option<u64>,
) -> Result<(), ReplayError> {
    match (phase, reverses_mutation_id) {
        (TransactionState::ParentSealIntent | TransactionState::TreeSealIntent, None) => Ok(()),
        (
            TransactionState::RestoreIntent
            | TransactionState::SourceParentRestoreIntent
            | TransactionState::RollbackIntent
            | TransactionState::Quarantined,
            Some(original_id),
        ) => {
            let original = permissions
                .iter()
                .find(|permission| permission.mutation_id == original_id)
                .ok_or(ReplayError::InvalidHistory(
                    "permission inverse references no mutation in its transaction",
                ))?;
            if original.application != ApplicationStatus::Applied
                || original.reverses_mutation_id.is_some()
                || (phase == TransactionState::SourceParentRestoreIntent
                    && original.phase != TransactionState::ParentSealIntent)
                || !same_recovery_object(&original.evidence, evidence)
                || (original.phase == TransactionState::ParentSealIntent
                    && staging.is_some_and(|metadata| {
                        !evidence_is_exact_source_parent(evidence, metadata)
                    }))
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

fn evidence_is_exact_source_parent(
    evidence: &PersistentRecoveryEvidence,
    metadata: &StagingTransactionMetadata,
) -> bool {
    evidence.relative_path() == metadata.source_parent.relative_path()
        && evidence.filesystem_id() == Some(metadata.source_parent.filesystem_id())
        && evidence.device() == metadata.source_parent_identity.device
        && evidence.inode() == metadata.source_parent_identity.inode
        && evidence.generation_or_btime() == Some(metadata.source_parent_identity.incarnation.get())
}

fn staging_parent_strategy_is_complete<'a>(
    metadata: Option<&StagingTransactionMetadata>,
    permissions: impl Iterator<Item = &'a DurablePermission>,
) -> bool {
    let Some(metadata) = metadata else {
        return true;
    };
    let parent_permissions = permissions
        .filter(|permission| permission.phase == TransactionState::ParentSealIntent)
        .collect::<Vec<_>>();
    match metadata.source_parent_strategy {
        DurableSourceParentStrategy::PermissionSeal => {
            !parent_permissions.is_empty()
                && parent_permissions
                    .iter()
                    .all(|permission| permission.application == ApplicationStatus::Applied)
        }
        DurableSourceParentStrategy::AlreadyExclusive(_) => parent_permissions.is_empty(),
    }
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
        (TransactionState::SourceParentRestoreIntent, TransactionState::SourceParentRestored) => {
            Some(TransactionState::SourceParentRestoreIntent)
        }
        _ => None,
    };
    completed_phase.is_none_or(|phase| {
        permissions
            .filter(|permission| permission.phase == phase)
            .all(|permission| permission.application == ApplicationStatus::Applied)
    })
}

fn all_applied_parent_seals_have_applied_inverse<'a>(
    permissions: impl Iterator<Item = &'a DurablePermission>,
) -> bool {
    let permissions = permissions.collect::<Vec<_>>();
    permissions.iter().all(|seal| {
        seal.application != ApplicationStatus::Applied
            || seal.phase != TransactionState::ParentSealIntent
            || permissions.iter().any(|inverse| {
                inverse.application == ApplicationStatus::Applied
                    && inverse.phase == TransactionState::SourceParentRestoreIntent
                    && inverse.reverses_mutation_id == Some(seal.mutation_id)
            })
    })
}

fn retains_active_permission_seals<'a>(
    permissions: impl Iterator<Item = &'a DurablePermission>,
) -> bool {
    !all_applied_seals_have_applied_inverse(permissions)
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
            | (S::StagedSealed, S::SourceParentRestoreIntent)
            | (S::SourceParentRestoreIntent, S::SourceParentRestored)
            | (S::SourceParentRestored, S::VerifiedCommitted)
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
                S::StagedUnverified
                    | S::StagedSealed
                    | S::SourceParentRestoreIntent
                    | S::SourceParentRestored
                    | S::RollbackIntent,
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
                    | S::SourceParentRestoreIntent
                    | S::SourceParentRestored
                    | S::RollbackIntent
                    | S::RestoreIntent
                    | S::Quarantined,
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
        SealRecord::StagingBegin {
            transaction,
            metadata,
        } => {
            bytes.push(5);
            bytes.extend_from_slice(&transaction.0);
            encode_staging_metadata(&mut bytes, metadata)?;
        }
        SealRecord::TreeManifestComplete {
            transaction,
            manifest,
        } => {
            bytes.push(6);
            bytes.extend_from_slice(&transaction.0);
            bytes.extend_from_slice(&manifest.entry_count.to_le_bytes());
            bytes.extend_from_slice(&manifest.sha256);
        }
        SealRecord::RenameIntent { transaction } => {
            bytes.push(7);
            bytes.extend_from_slice(&transaction.0);
        }
        SealRecord::RenameOutcome {
            transaction,
            outcome,
        } => {
            bytes.push(8);
            bytes.extend_from_slice(&transaction.0);
            match outcome {
                DurableRenameOutcome::AppliedAndParentsSynced(identity) => {
                    bytes.push(1);
                    encode_strong_identity(&mut bytes, *identity);
                }
                DurableRenameOutcome::ConfirmedNotAppliedAtSource(identity) => {
                    bytes.push(2);
                    encode_strong_identity(&mut bytes, *identity);
                }
            }
        }
    }
    if bytes.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge {
            limit: MAX_PAYLOAD_LEN,
        });
    }
    Ok(bytes)
}

fn decode_record(payload: &[u8], offset: u64, version: u16) -> Result<SealRecord, ReplayError> {
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
        5 if version >= 3 => SealRecord::StagingBegin {
            transaction,
            metadata: decode_staging_metadata(&mut cursor, offset, version)?,
        },
        6 if version >= 3 => SealRecord::TreeManifestComplete {
            transaction,
            manifest: DurableTreeManifest {
                entry_count: cursor.u64()?,
                sha256: cursor.array_32()?,
            },
        },
        7 if version >= 3 => SealRecord::RenameIntent { transaction },
        8 if version >= 3 => {
            let kind = cursor.u8()?;
            let identity = decode_strong_identity(&mut cursor, version)?;
            let outcome = match kind {
                1 => DurableRenameOutcome::AppliedAndParentsSynced(identity),
                2 => DurableRenameOutcome::ConfirmedNotAppliedAtSource(identity),
                _ => {
                    return Err(ReplayError::Malformed {
                        offset,
                        reason: "unknown rename outcome",
                    });
                }
            };
            SealRecord::RenameOutcome {
                transaction,
                outcome,
            }
        }
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

fn decode_strong_identity(
    cursor: &mut Cursor<'_>,
    version: u16,
) -> Result<StrongObjectIdentity, ReplayError> {
    Ok(StrongObjectIdentity {
        device: cursor.u64()?,
        inode: cursor.u64()?,
        incarnation: ObjectIncarnation::new(cursor.u64()?),
        mount_id: if version >= 4 { cursor.u64()? } else { 0 },
    })
}

fn decode_locator(cursor: &mut Cursor<'_>, offset: u64) -> Result<StagingLocator, ReplayError> {
    let path = PathBuf::from(std::ffi::OsString::from_vec(cursor.bytes()?));
    let filesystem_id = String::from_utf8(cursor.bytes()?).map_err(|_| ReplayError::Malformed {
        offset,
        reason: "staging filesystem id is not UTF-8",
    })?;
    StagingLocator::new(path, filesystem_id).ok_or(ReplayError::Malformed {
        offset,
        reason: "staging locator is invalid",
    })
}

fn decode_staging_metadata(
    cursor: &mut Cursor<'_>,
    offset: u64,
    version: u16,
) -> Result<StagingTransactionMetadata, ReplayError> {
    let source_parent = decode_locator(cursor, offset)?;
    let source_parent_identity = decode_strong_identity(cursor, version)?;
    let source_basename = std::ffi::OsString::from_vec(cursor.bytes()?);
    let root_identity = decode_strong_identity(cursor, version)?;
    let destination_parent = decode_locator(cursor, offset)?;
    let destination_parent_identity = decode_strong_identity(cursor, version)?;
    let destination_basename = std::ffi::OsString::from_vec(cursor.bytes()?);
    let backend = match cursor.u8()? {
        1 => CertifiedLocalBackend::Ext4,
        2 => CertifiedLocalBackend::Xfs,
        3 => CertifiedLocalBackend::Apfs,
        _ => {
            return Err(ReplayError::Malformed {
                offset,
                reason: "unknown staging backend",
            });
        }
    };
    let source_parent_strategy = match cursor.u8()? {
        1 => DurableSourceParentStrategy::PermissionSeal,
        2 => DurableSourceParentStrategy::AlreadyExclusive(DurableAlreadyExclusiveParent {
            source_parent: decode_locator(cursor, offset)?,
            source_parent_identity: decode_strong_identity(cursor, version)?,
            observed_mode: cursor.u32()?,
        }),
        _ => {
            return Err(ReplayError::Malformed {
                offset,
                reason: "unknown source-parent strategy",
            });
        }
    };
    let metadata = StagingTransactionMetadata {
        source_parent,
        source_parent_identity,
        source_basename,
        root_identity,
        destination_parent,
        destination_parent_identity,
        destination_basename,
        backend,
        source_parent_strategy,
    };
    let valid = if version >= 4 {
        metadata.invariants_hold()
    } else if metadata.source_parent_identity.mount_id != 0
        || metadata.root_identity.mount_id != 0
        || metadata.destination_parent_identity.mount_id != 0
    {
        false
    } else {
        // Validate every non-mount invariant without inventing mount authority in
        // the replayed value. The promoted clone is discarded immediately.
        let mut promoted = metadata.clone();
        promoted.source_parent_identity.mount_id = 1;
        promoted.root_identity.mount_id = 1;
        promoted.destination_parent_identity.mount_id = 1;
        if let DurableSourceParentStrategy::AlreadyExclusive(proof) =
            &mut promoted.source_parent_strategy
        {
            proof.source_parent_identity.mount_id = 1;
        }
        promoted.invariants_hold()
    };
    valid.then_some(metadata).ok_or(ReplayError::Malformed {
        offset,
        reason: "staging metadata is inconsistent",
    })
}

fn encode_strong_identity(output: &mut Vec<u8>, identity: StrongObjectIdentity) {
    output.extend_from_slice(&identity.device.to_le_bytes());
    output.extend_from_slice(&identity.inode.to_le_bytes());
    output.extend_from_slice(&identity.incarnation.get().to_le_bytes());
    output.extend_from_slice(&identity.mount_id.to_le_bytes());
}

fn encode_locator(output: &mut Vec<u8>, locator: &StagingLocator) -> Result<(), FrameError> {
    put_bytes(output, locator.relative_path().as_os_str().as_bytes())?;
    put_bytes(output, locator.filesystem_id().as_bytes())
}

fn encode_staging_metadata(
    output: &mut Vec<u8>,
    metadata: &StagingTransactionMetadata,
) -> Result<(), FrameError> {
    encode_locator(output, &metadata.source_parent)?;
    encode_strong_identity(output, metadata.source_parent_identity);
    put_bytes(output, metadata.source_basename.as_bytes())?;
    encode_strong_identity(output, metadata.root_identity);
    encode_locator(output, &metadata.destination_parent)?;
    encode_strong_identity(output, metadata.destination_parent_identity);
    put_bytes(output, metadata.destination_basename.as_bytes())?;
    output.push(match metadata.backend {
        CertifiedLocalBackend::Ext4 => 1,
        CertifiedLocalBackend::Xfs => 2,
        CertifiedLocalBackend::Apfs => 3,
    });
    match &metadata.source_parent_strategy {
        DurableSourceParentStrategy::PermissionSeal => output.push(1),
        DurableSourceParentStrategy::AlreadyExclusive(proof) => {
            output.push(2);
            encode_locator(output, &proof.source_parent)?;
            encode_strong_identity(output, proof.source_parent_identity);
            output.extend_from_slice(&proof.observed_mode.to_le_bytes());
        }
    }
    Ok(())
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

    fn array_32(&mut self) -> Result<[u8; 32], ReplayError> {
        Ok(self.take(32)?.try_into().unwrap())
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
        S::SourceParentRestoreIntent => 17,
        S::SourceParentRestored => 18,
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
        17 => Ok(S::SourceParentRestoreIntent),
        18 => Ok(S::SourceParentRestored),
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
