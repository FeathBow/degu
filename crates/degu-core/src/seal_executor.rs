//! Held-FD-only local mode seal/restore execution.
//!
//! This module is deliberately not connected to lifecycle code. Recovery paths
//! are durable evidence only; every mutation is `fchmod` on the already-held,
//! certified descriptor owned by `HeldLocalBackendEvidence`.

use crate::authority::{PersistentRecoveryEvidence, TransactionState};
use crate::local_backend::{
    HeldLocalBackendEvidence, HeldModeChangeOutcome, LocalModeRevalidationFailure,
    ModeSyscallFailure,
};
use crate::seal_wal::{
    AppendError, ApplicationStatus, DurablePermission, DurableWrite, MutationAppendError,
    PermissionIntent, PermissionResolution, ResolveError, SealWal, TransactionId,
};
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLocator {
    relative_path: PathBuf,
    filesystem_id: Option<String>,
    incarnation: Option<u64>,
}

impl RecoveryLocator {
    /// Authority-neutral A1/A3 locator. It carries no strong incarnation and
    /// cannot satisfy the staging WAL's stronger evidence checks.
    pub fn authority_neutral(relative_path: PathBuf, filesystem_id: Option<String>) -> Self {
        Self {
            relative_path,
            filesystem_id,
            incarnation: None,
        }
    }

    /// Descriptor-derived forward-staging locator. Only degu-core's held-tree
    /// coordinator can attach the strong kernel incarnation.
    pub(crate) fn held_staging(
        relative_path: PathBuf,
        filesystem_id: String,
        incarnation: u64,
    ) -> Self {
        Self {
            relative_path,
            filesystem_id: Some(filesystem_id),
            incarnation: Some(incarnation),
        }
    }

    /// Exact durable restore locator; the executor inherits incarnation from
    /// the original applied seal and refuses any caller override.
    pub(crate) fn durable_restore(relative_path: PathBuf, filesystem_id: Option<String>) -> Self {
        Self {
            relative_path,
            filesystem_id,
            incarnation: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalModeTransform {
    Seal { acquire_owner_write_search: bool },
    Restore { original: DurablePermission },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalModeMutationRequest {
    pub transaction: TransactionId,
    pub mutation_id: u64,
    pub locator: RecoveryLocator,
    pub transform: LocalModeTransform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalModeMutationResult {
    Applied { pre_mode: u32, applied_mode: u32 },
    ConfirmedNotApplied,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalModeExecutionError {
    #[error("held descriptor preparation failed: {0:?}")]
    Preparation(LocalModeRevalidationFailure),
    #[error("invalid local mode mutation request: {0}")]
    InvalidRequest(&'static str),
    #[error("permission intent was not durable: {0}")]
    IntentNotDurable(#[source] AppendError),
    #[error("confirmed-not-applied resolution was not durable: {0}")]
    NotAppliedResolutionNotDurable(#[source] ResolveError),
    #[error("fchmod succeeded but its postconditions were not verified: {reason:?}")]
    AppliedButUnverified {
        reason: LocalModeRevalidationFailure,
        recovery_required: Result<(), AppendError>,
    },
    #[error("fchmod outcome is unknown after syscall error {syscall:?}: {post_failure:?}")]
    OutcomeUnknown {
        syscall: ModeSyscallFailure,
        post_failure: LocalModeRevalidationFailure,
        recovery_required: Result<(), AppendError>,
    },
    #[error("fchmod was verified but its Applied WAL record was not durable: {source}")]
    AppliedRecordNotDurable {
        #[source]
        source: AppendError,
    },
    #[error("WAL rejected the seal or inverse: {0}")]
    InvalidSealOrInverse(#[source] AppendError),
    #[error("applied seal lineage could not be retained: {0:?}")]
    SealLineage(LocalModeRevalidationFailure),
}

pub(crate) fn execute_local_mode_mutation<W: DurableWrite>(
    wal: &mut SealWal<W>,
    held: &mut HeldLocalBackendEvidence,
    request: LocalModeMutationRequest,
) -> Result<LocalModeMutationResult, LocalModeExecutionError> {
    execute_local_mode_mutation_inner(wal, held, request, false)
}

/// Staging-bound entry: unlike the authority-neutral executor this may append
/// only to an exact staging transaction owned by the high-level engine.
pub(crate) fn execute_staging_local_mode_mutation<W: DurableWrite>(
    wal: &mut SealWal<W>,
    held: &mut HeldLocalBackendEvidence,
    request: LocalModeMutationRequest,
) -> Result<LocalModeMutationResult, LocalModeExecutionError> {
    execute_local_mode_mutation_inner(wal, held, request, true)
}

fn execute_local_mode_mutation_inner<W: DurableWrite>(
    wal: &mut SealWal<W>,
    held: &mut HeldLocalBackendEvidence,
    request: LocalModeMutationRequest,
    staging: bool,
) -> Result<LocalModeMutationResult, LocalModeExecutionError> {
    let (prepared, reverses_mutation_id, restore_original) = match &request.transform {
        LocalModeTransform::Seal {
            acquire_owner_write_search,
        } => (
            held.prepare_minimal_seal(*acquire_owner_write_search)
                .map_err(LocalModeExecutionError::Preparation)?,
            None,
            None,
        ),
        LocalModeTransform::Restore { original } => {
            if original.application != ApplicationStatus::Applied
                || !matches!(
                    original.phase,
                    TransactionState::ParentSealIntent | TransactionState::TreeSealIntent
                )
                || original.reverses_mutation_id.is_some()
            {
                return Err(LocalModeExecutionError::InvalidRequest(
                    "restore must reference an applied original seal",
                ));
            }
            // The checks above establish an Applied original seal; A1 validates
            // the resulting inverse again before invoking mutation.
            let prepared = held
                .prepare_wal_bound_restore(
                    request.transaction,
                    original.mutation_id,
                    original.expected_mode,
                    original.pre_mode,
                )
                .map_err(LocalModeExecutionError::Preparation)?;
            (prepared, Some(original.mutation_id), Some(original))
        }
    };
    if let Some(original) = restore_original
        && (prepared.pre_mode() != original.expected_mode
            || prepared.device() != original.evidence.device()
            || prepared.inode() != original.evidence.inode())
    {
        return Err(LocalModeExecutionError::InvalidRequest(
            "held restore target does not match the original seal",
        ));
    }
    let incarnation = match restore_original {
        Some(original) => {
            let durable = original.evidence.generation_or_btime();
            if request.locator.incarnation.is_some() && request.locator.incarnation != durable {
                return Err(LocalModeExecutionError::InvalidRequest(
                    "restore locator incarnation differs from its original seal",
                ));
            }
            durable
        }
        None => request.locator.incarnation,
    };
    let evidence = PersistentRecoveryEvidence::new(
        request.locator.relative_path,
        request.locator.filesystem_id,
        prepared.device(),
        prepared.inode(),
        incarnation,
        prepared.target_mode(),
    )
    .ok_or(LocalModeExecutionError::InvalidRequest(
        "recovery locator is not a confined relative path",
    ))?;
    let pre_mode = prepared.pre_mode();
    let expected_mode = prepared.target_mode();
    let intent = PermissionIntent {
        transaction: request.transaction,
        mutation_id: request.mutation_id,
        evidence,
        pre_mode,
        expected_mode,
        reverses_mutation_id,
    };

    let mut held_outcome = None;
    let mutate = || {
        // A1 invokes this closure only after synchronizing the exact permission
        // intent constructed from `prepared` above.
        let outcome = held.apply_wal_bound_mode_change(prepared);
        let verified = matches!(outcome, HeldModeChangeOutcome::AppliedVerified { .. });
        held_outcome = Some(outcome);
        if verified {
            Ok(())
        } else {
            Err(io::Error::other("held mode mutation was not verified"))
        }
    };
    let wal_result = if staging {
        wal.apply_staging_permission_mutation(intent, mutate)
    } else {
        wal.apply_permission_mutation(intent, mutate)
    };

    match (wal_result, held_outcome) {
        (Ok(()), Some(HeldModeChangeOutcome::AppliedVerified { .. })) => {
            if reverses_mutation_id.is_none() {
                held.record_applied_seal_lineage(
                    request.transaction,
                    request.mutation_id,
                    pre_mode,
                    expected_mode,
                )
                .map_err(LocalModeExecutionError::SealLineage)?;
            }
            Ok(LocalModeMutationResult::Applied {
                pre_mode,
                applied_mode: expected_mode,
            })
        }
        (Err(MutationAppendError::IntentWal(error)), None) => match error {
            AppendError::InvalidState(_) => {
                Err(LocalModeExecutionError::InvalidSealOrInverse(error))
            }
            other => Err(LocalModeExecutionError::IntentNotDurable(other)),
        },
        (Err(MutationAppendError::AppliedWal { source, .. }), Some(_)) => {
            held.invalidate_after_wal_uncertainty();
            Err(LocalModeExecutionError::AppliedRecordNotDurable { source })
        }
        (
            Err(MutationAppendError::Mutation(_)),
            Some(
                HeldModeChangeOutcome::RefusedBeforeMutation { .. }
                | HeldModeChangeOutcome::NotAppliedVerified { .. },
            ),
        ) => {
            let resolution = if staging {
                wal.resolve_staging_permission(request.transaction, request.mutation_id, |_| {
                    Ok(PermissionResolution::ConfirmedNotApplied)
                })
            } else {
                wal.resolve_unresolved_permission(request.transaction, request.mutation_id, |_| {
                    Ok(PermissionResolution::ConfirmedNotApplied)
                })
            };
            if let Err(error) = resolution {
                // The physical state is known not applied, but the durable WAL
                // outcome is still unknown. Do not let this token or a restored
                // seal lineage authorize a second transaction.
                held.invalidate_after_wal_uncertainty();
                return Err(LocalModeExecutionError::NotAppliedResolutionNotDurable(
                    error,
                ));
            }
            Ok(LocalModeMutationResult::ConfirmedNotApplied)
        }
        (
            Err(MutationAppendError::Mutation(_)),
            Some(HeldModeChangeOutcome::AppliedButUnverified { reason, .. }),
        ) => {
            let recovery_required = wal.transition_recovery_required(request.transaction);
            Err(LocalModeExecutionError::AppliedButUnverified {
                reason,
                recovery_required,
            })
        }
        (
            Err(MutationAppendError::Mutation(_)),
            Some(HeldModeChangeOutcome::OutcomeUnknown {
                syscall,
                post_failure,
            }),
        ) => {
            let recovery_required = wal.transition_recovery_required(request.transaction);
            Err(LocalModeExecutionError::OutcomeUnknown {
                syscall,
                post_failure,
                recovery_required,
            })
        }
        _ => Err(LocalModeExecutionError::InvalidRequest(
            "WAL callback and held mode outcome diverged",
        )),
    }
}

// Compile-time witness for the unwired foundation: the only executor entry is
// same-crate, while its generic writer remains available to fault-injection tests.
const _: fn(
    &mut SealWal<std::fs::File>,
    &mut HeldLocalBackendEvidence,
    LocalModeMutationRequest,
) -> Result<LocalModeMutationResult, LocalModeExecutionError> =
    execute_local_mode_mutation::<std::fs::File>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::local_mode::{
        ModeSealAssessment, ModeSealDenial, assess_mode_seal, assess_process_capability,
    };
    use crate::authority::{CapabilityAssessment, UnknownReason};
    use crate::local_backend::{CertificationError, certify_held_fd};
    use crate::seal_store::SealWalStore;
    use crate::seal_wal::{RecoveryWork, decide_recovery};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    struct FailSyncWriter {
        bytes: Vec<u8>,
        sync_count: usize,
        fail_at: usize,
    }

    impl Write for FailSyncWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DurableWrite for FailSyncWriter {
        fn sync_record(&mut self) -> io::Result<()> {
            let current = self.sync_count;
            self.sync_count += 1;
            if current == self.fail_at {
                Err(io::Error::from_raw_os_error(5))
            } else {
                Ok(())
            }
        }

        fn prepare_append(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
    }

    #[test]
    fn invalidated_mode_evidence_cannot_authorize_later_assessment() {
        let temp = crate::secure_test_tempdir().unwrap();
        let directory = temp.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
        let fd = std::fs::File::open(&directory).unwrap().into();
        let mut held = match certify_held_fd(fd) {
            Ok(held) => held,
            Err(CertificationError::UnsupportedFilesystem) => return,
            Err(error) => panic!("unexpected certification failure: {error:?}"),
        };
        let prepared = held.prepare_minimal_seal(false).unwrap();
        // Force a precondition failure. Uncertain postconditions use the same
        // invalidation bit before the token can reach any A2 reader.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            held.apply_wal_bound_mode_change(prepared),
            HeldModeChangeOutcome::RefusedBeforeMutation { .. }
        ));
        assert!(!held.mode_is_verified());
        assert_eq!(
            assess_mode_seal(&held),
            ModeSealAssessment::Denied(ModeSealDenial::EvidenceUnverified)
        );
        assert_eq!(
            assess_process_capability(&held, None),
            CapabilityAssessment::Unknown(UnknownReason::ProbeFailed)
        );
    }

    #[test]
    fn wal_sync_boundaries_prevent_early_mutation_and_report_applied_uncertainty() {
        for (fail_at, expected_mode) in [(2, 0o770), (3, 0o750)] {
            let temp = crate::secure_test_tempdir().unwrap();
            let directory = temp.path().join("directory");
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
            let fd = std::fs::File::open(&directory).unwrap().into();
            let mut held = match certify_held_fd(fd) {
                Ok(held) => held,
                Err(CertificationError::UnsupportedFilesystem) => return,
                Err(error) => panic!("unexpected certification failure: {error:?}"),
            };
            let transaction = TransactionId([fail_at as u8; 16]);
            let mut wal = SealWal::new(FailSyncWriter {
                bytes: Vec::new(),
                sync_count: 0,
                fail_at,
            })
            .unwrap();
            wal.begin(transaction).unwrap();
            wal.transition(transaction, TransactionState::ParentSealIntent)
                .unwrap();
            let error = execute_local_mode_mutation(
                &mut wal,
                &mut held,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id: 1,
                    locator: RecoveryLocator::authority_neutral(PathBuf::from("directory"), None),
                    transform: LocalModeTransform::Seal {
                        acquire_owner_write_search: false,
                    },
                },
            )
            .unwrap_err();
            if fail_at == 2 {
                assert!(matches!(
                    error,
                    LocalModeExecutionError::IntentNotDurable(_)
                ));
            } else {
                assert!(matches!(
                    error,
                    LocalModeExecutionError::AppliedRecordNotDurable { .. }
                ));
                assert!(!held.mode_is_verified());
            }
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
                expected_mode
            );
        }
    }

    #[test]
    fn actual_held_fd_seal_and_bound_restore_replay_cleanly() {
        let temp = crate::secure_test_tempdir().unwrap();
        let directory = temp.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
        let fd = std::fs::File::open(&directory).unwrap().into();
        let mut held = match certify_held_fd(fd) {
            Ok(held) => held,
            Err(CertificationError::UnsupportedFilesystem) => return,
            Err(error) => panic!("unexpected certification failure: {error:?}"),
        };

        let transaction = TransactionId([31; 16]);
        let store_path = temp.path().canonicalize().unwrap().join("wal-store");
        let store = SealWalStore::open_or_create(&store_path).unwrap();
        let mut wal = store.try_lease().unwrap().into_new_wal().unwrap();
        wal.begin(transaction).unwrap();
        wal.transition(transaction, TransactionState::ParentSealIntent)
            .unwrap();
        assert_eq!(
            execute_local_mode_mutation(
                &mut wal,
                &mut held,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id: 1,
                    locator: RecoveryLocator::authority_neutral(
                        PathBuf::from("source/directory"),
                        None,
                    ),
                    transform: LocalModeTransform::Seal {
                        acquire_owner_write_search: false,
                    },
                },
            )
            .unwrap(),
            LocalModeMutationResult::Applied {
                pre_mode: 0o770,
                applied_mode: 0o750,
            }
        );
        assert_eq!(held.mode(), 0o750);
        wal.transition(transaction, TransactionState::ParentSealed)
            .unwrap();
        wal.transition(transaction, TransactionState::RestoreIntent)
            .unwrap();

        let original = DurablePermission {
            mutation_id: 1,
            phase: TransactionState::ParentSealIntent,
            evidence: PersistentRecoveryEvidence::new(
                PathBuf::from("source/directory"),
                None,
                held.device(),
                held.inode(),
                None,
                0o750,
            )
            .unwrap(),
            pre_mode: 0o770,
            expected_mode: 0o750,
            reverses_mutation_id: None,
            application: ApplicationStatus::Applied,
        };
        let fresh_fd = std::fs::File::open(&directory).unwrap().into();
        let mut fresh = certify_held_fd(fresh_fd).unwrap();
        assert!(matches!(
            execute_local_mode_mutation(
                &mut wal,
                &mut fresh,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id: 2,
                    locator: RecoveryLocator::authority_neutral(
                        PathBuf::from("restored/directory"),
                        None,
                    ),
                    transform: LocalModeTransform::Restore {
                        original: original.clone(),
                    },
                },
            ),
            Err(LocalModeExecutionError::Preparation(
                LocalModeRevalidationFailure::MissingSealLineage
            ))
        ));

        assert_eq!(
            execute_local_mode_mutation(
                &mut wal,
                &mut held,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id: 2,
                    locator: RecoveryLocator::authority_neutral(
                        PathBuf::from("restored/directory"),
                        None,
                    ),
                    transform: LocalModeTransform::Restore { original },
                },
            )
            .unwrap(),
            LocalModeMutationResult::Applied {
                pre_mode: 0o750,
                applied_mode: 0o770,
            }
        );
        wal.transition(transaction, TransactionState::Restored)
            .unwrap();
        assert_eq!(held.mode(), 0o770);

        drop(wal);
        let mut recovery = store.try_lease().unwrap();
        let replay = recovery.replay_and_repair().unwrap();
        let recovered = &replay.transactions[&transaction];
        assert_eq!(recovered.state, TransactionState::Restored);
        assert_eq!(recovered.permissions.len(), 2);
        assert!(matches!(
            decide_recovery(recovered, |_| panic!(
                "restored work needs no identity probe"
            )),
            RecoveryWork::Nothing
        ));
    }
}
