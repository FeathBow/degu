//! High-level boundary for the sealed-staging WAL foundation.
//!
//! Namespace mutation is deliberately absent until the held-tree engine can
//! supply verified rename and staged-object authority. Paths and durable
//! identities in this module are evidence only.

use crate::authority::TransactionState;
use crate::seal_store::{SealWalStore, StoreError};
use crate::seal_wal::{
    AppendError, DurableTreeManifest, RecoveryIdentity, RecoverySession, RecoveryWork, ReplayError,
    SealWal, StagingTransactionMetadata, TransactionId, decide_recovery,
    quarantined_transaction_retains_active_permission_seals,
};
use crate::staging_recovery::{
    RecoveryAnchors, RecoveryRebindError, StartupRecoveryCapability, prepare_startup_recovery,
    recovery_transaction,
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

    #[allow(dead_code)] // future held-tree integration seam
    pub(crate) fn complete_tree_manifest(
        &mut self,
        transaction: TransactionId,
        manifest: DurableTreeManifest,
    ) -> Result<(), StagingEngineError> {
        self.wal.complete_tree_manifest(transaction, manifest)?;
        Ok(())
    }

    #[allow(dead_code)] // future held-tree integration seam
    pub(crate) fn begin_rename(
        &mut self,
        transaction: TransactionId,
    ) -> Result<(), StagingEngineError> {
        self.wal.record_rename_intent(transaction)?;
        Ok(())
    }

    #[allow(dead_code)] // future held-tree integration seam
    pub(crate) fn transition(
        &mut self,
        transaction: TransactionId,
        next: TransactionState,
    ) -> Result<(), StagingEngineError> {
        self.wal.transition_staging(transaction, next)?;
        Ok(())
    }
}

// Rename completion and purge authorization deliberately have no callable seam.
// The future held-tree executor must introduce core-private, non-forgeable values
// that retain both rename-parent capabilities or the staged object capability.

#[cfg(test)]
mod tests;
