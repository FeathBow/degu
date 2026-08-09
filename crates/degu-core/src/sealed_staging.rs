//! High-level boundary for the sealed-staging transaction stack.
//!
//! The only namespace mutation is the core-private, unwired A3c2 operation that
//! consumes exact held parents and returns `StagedUnverified`. Paths and durable
//! identities remain evidence only; no restore, commit, purge, or deletion seam
//! is exposed here.

use crate::authority::TransactionState;
use crate::seal_store::{SealWalStore, StoreError};
use crate::seal_wal::{
    AppendError, RecoveryIdentity, RecoverySession, RecoveryWork, ReplayError, SealWal,
    StagingTransactionMetadata, TransactionId, decide_recovery,
    quarantined_transaction_retains_active_permission_seals,
};
use crate::staging_recovery::{
    RecoveryAnchors, RecoveryRebindError, StartupRecoveryCapability, prepare_startup_recovery,
    recovery_transaction,
};
use crate::staging_rename::{
    PreparedRootBinding, StagedUnverifiedTree, StagingRenameError, execute_prepared_rename,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_RECOVERY_GENERATION: AtomicU64 = AtomicU64::new(1);

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
    pub candidates: Vec<StartupRecoveryCandidate>,
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
        let work = replay
            .transactions
            .values()
            .map(|transaction| decide_recovery(transaction, |_| RecoveryIdentity::Reestablished))
            .filter(|work| {
                matches!(
                    work,
                    RecoveryWork::RestoreBeforeRename { .. }
                        | RecoveryWork::VerifyOrQuarantineAfterRename { .. }
                        | RecoveryWork::RestoreSourceParentAfterRename { .. }
                        | RecoveryWork::RestoreQuarantinedSeals { .. }
                        | RecoveryWork::ResolveUncertainPermissions { .. }
                        | RecoveryWork::RecoveryRequired { .. }
                )
            })
            .collect::<Vec<_>>();
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
            || work.iter().any(|work| {
                !matches!(
                    work,
                    RecoveryWork::PreserveCommittedSeal { .. }
                        | RecoveryWork::PreserveQuarantine { .. }
                )
            });
        let wal = recovery.resume()?;
        Ok((
            Self {
                wal,
                startup_blocked,
                recovery_generation,
            },
            StartupRecoveryReport { candidates },
        ))
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
    #[allow(dead_code)] // consumed by the lifecycle startup coordinator
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
    /// unwired A3c2 seal/rename sequence. Success reaches only
    /// `StagedUnverified` and retains this engine's exact WAL lease.
    #[allow(dead_code)] // consumed only by the future forward lifecycle coordinator
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

// Restore, commit, purge, unlink, and deletion authorization deliberately have
// no callable engine seam. A3c2 success retains both parent capabilities and the
// staged object under the exact WAL lease, but stops at `StagedUnverified`.

#[cfg(test)]
mod tests;
