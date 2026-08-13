use super::*;
use crate::authority::PersistentRecoveryEvidence;
use crate::local_backend::CertifiedLocalBackend;
use crate::seal_wal::{
    ApplicationStatus, DurablePermission, DurableSourceParentStrategy, DurableTreeManifest,
    ObjectIncarnation, PermissionIntent, StagingLocator, StrongObjectIdentity,
};
use std::ffi::OsString;
use std::path::PathBuf;

fn identity(inode: u64) -> StrongObjectIdentity {
    StrongObjectIdentity::new_with_mount(1, inode, ObjectIncarnation::new(inode + 1000), 7)
}

fn captured_identity(path: &std::path::Path) -> StrongObjectIdentity {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    strong_identity_fd(&fd).unwrap()
}

fn metadata() -> StagingTransactionMetadata {
    StagingTransactionMetadata::new(
        StagingLocator::new(PathBuf::from("source-parent"), "fs".into()).unwrap(),
        identity(10),
        OsString::from("root"),
        identity(11),
        StagingLocator::new(PathBuf::from("trash-parent"), "fs".into()).unwrap(),
        identity(12),
        OsString::from("staged"),
        CertifiedLocalBackend::Ext4,
        DurableSourceParentStrategy::PermissionSeal,
    )
    .unwrap()
}

#[test]
fn forward_identity_probe_distinguishes_match_mismatch_and_uncertainty() {
    let temp = crate::secure_test_tempdir().unwrap();
    let directory = temp.path().join("directory");
    let file = temp.path().join("file");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"not a directory").unwrap();
    let expected = captured_identity(&directory);

    assert_eq!(
        probe_forward_directory_identity(&directory, expected),
        ForwardDirectoryIdentityProbe::Match
    );
    assert_eq!(
        probe_forward_directory_identity(&file, expected),
        ForwardDirectoryIdentityProbe::Mismatch
    );
    assert_eq!(
        probe_forward_directory_identity(&temp.path().join("missing"), expected),
        ForwardDirectoryIdentityProbe::Mismatch
    );
    let oversized = temp.path().join("x".repeat(8192));
    assert!(matches!(
        probe_forward_directory_identity(&oversized, expected),
        ForwardDirectoryIdentityProbe::Uncertain(_)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn forward_identity_probe_does_not_require_directory_read_permission() {
    use std::os::unix::fs::PermissionsExt;

    let temp = crate::secure_test_tempdir().unwrap();
    let directory = temp.path().join("execute-only");
    std::fs::create_dir(&directory).unwrap();
    let expected = captured_identity(&directory);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o100)).unwrap();

    assert_eq!(
        probe_forward_directory_identity(&directory, expected),
        ForwardDirectoryIdentityProbe::Match
    );
}

#[test]
fn bare_transaction_without_staging_provenance_is_rejected() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store =
        SealWalStore::open_or_create(&temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    {
        let mut lease = store.try_lease().unwrap();
        lease.replay_and_repair().unwrap();
        let mut wal = lease.resume().unwrap();
        wal.begin(TransactionId([0x80; 16])).unwrap();
    }
    assert!(matches!(
        SealedStagingEngine::open(&store),
        Err(StagingEngineError::InsufficientRecoveryIdentity(
            "transaction has no atomic staging metadata"
        ))
    ));
}

#[test]
fn high_level_open_owns_staging_begin_and_blocks_parallel_transaction() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
    assert!(report.candidates.is_empty());
    let first = TransactionId([81; 16]);
    engine.begin_transaction(first, metadata()).unwrap();
    assert_eq!(engine.state(first), Some(TransactionState::Prepared));
    assert!(
        engine
            .begin_transaction(TransactionId([82; 16]), metadata())
            .is_err()
    );
}

#[test]
fn invalid_metadata_is_rejected_without_poisoning_runtime_or_reopen() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let invalid_transaction = TransactionId([86; 16]);
    {
        let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
        assert!(report.candidates.is_empty());
        let mut invalid = metadata();
        invalid.invalidate_for_test();
        assert!(matches!(
            engine.begin_transaction(invalid_transaction, invalid),
            Err(StagingEngineError::Wal(AppendError::InvalidState(
                "staging metadata invariants are invalid"
            )))
        ));
        assert_eq!(engine.state(invalid_transaction), None);
    }

    let (mut reopened, report) = SealedStagingEngine::open(&store).unwrap();
    assert!(report.candidates.is_empty());
    let valid_transaction = TransactionId([87; 16]);
    reopened
        .begin_transaction(valid_transaction, metadata())
        .unwrap();
    assert_eq!(
        reopened.state(valid_transaction),
        Some(TransactionState::Prepared)
    );
}

#[test]
fn reopen_blocks_new_mutation_when_staging_recovery_is_incomplete() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    {
        let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
        engine
            .begin_transaction(TransactionId([83; 16]), metadata())
            .unwrap();
    }
    let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].transaction(), TransactionId([83; 16]));
    assert!(
        engine
            .begin_transaction(TransactionId([84; 16]), metadata())
            .is_err()
    );
}

#[test]
fn recovery_candidate_cannot_cross_engine_generation() {
    let first_temp = crate::secure_test_tempdir().unwrap();
    let first_store =
        SealWalStore::open_or_create(&first_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let transaction = TransactionId([0x91; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&first_store).unwrap();
        engine.begin_transaction(transaction, metadata()).unwrap();
    }
    let (_first_engine, mut first_report) = SealedStagingEngine::open(&first_store).unwrap();
    let candidate = first_report.candidates.pop().unwrap();

    let second_temp = crate::secure_test_tempdir().unwrap();
    let second_store =
        SealWalStore::open_or_create(&second_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let (second_engine, _) = SealedStagingEngine::open(&second_store).unwrap();
    assert!(matches!(
        second_engine.validate_recovery_candidate(&candidate),
        Err(RecoveryRebindError::CandidateFromAnotherEngine)
    ));
}

#[test]
fn active_seals_in_quarantine_block_runtime_and_reopen() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let transaction = TransactionId([88; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
        let metadata = metadata();
        let parent_identity = metadata.source_parent_identity();
        let root_identity = metadata.root_identity();
        engine
            .begin_transaction(transaction, metadata.clone())
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::ParentSealIntent)
            .unwrap();
        engine
            .wal
            .apply_staging_permission_mutation(
                PermissionIntent {
                    transaction,
                    mutation_id: 1,
                    evidence: PersistentRecoveryEvidence::new(
                        PathBuf::from("source-parent"),
                        Some("fs".into()),
                        parent_identity.device(),
                        parent_identity.inode(),
                        Some(parent_identity.incarnation().get()),
                        0o500,
                    )
                    .unwrap(),
                    pre_mode: 0o770,
                    expected_mode: 0o500,
                    reverses_mutation_id: None,
                },
                || Ok(()),
            )
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::ParentSealed)
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::TreeSealIntent)
            .unwrap();
        engine
            .wal
            .apply_staging_permission_mutation(
                PermissionIntent {
                    transaction,
                    mutation_id: 2,
                    evidence: PersistentRecoveryEvidence::new(
                        PathBuf::from("source-parent/root"),
                        Some("fs".into()),
                        root_identity.device(),
                        root_identity.inode(),
                        Some(root_identity.incarnation().get()),
                        0o500,
                    )
                    .unwrap(),
                    pre_mode: 0o770,
                    expected_mode: 0o500,
                    reverses_mutation_id: None,
                },
                || Ok(()),
            )
            .unwrap();
        engine
            .wal
            .complete_tree_manifest(
                transaction,
                DurableTreeManifest {
                    schema_version: 2,
                    entry_count: 1,
                    sha256: [0x88; 32],
                },
            )
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::TreeSealed)
            .unwrap();
        engine.wal.record_rename_intent(transaction).unwrap();
        engine
            .wal
            .record_applied_rename_for_test(transaction)
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::StagedUnverified)
            .unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::Quarantined)
            .unwrap();

        assert!(
            engine
                .begin_transaction(TransactionId([89; 16]), metadata)
                .is_err()
        );
    }

    let (mut reopened, report) = SealedStagingEngine::open(&store).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].transaction(), transaction);
    assert!(
        reopened
            .begin_transaction(TransactionId([90; 16]), metadata())
            .is_err()
    );
}

#[test]
fn permission_and_path_workload_limits_are_checked_before_rebind() {
    let permission = DurablePermission {
        mutation_id: 1,
        phase: TransactionState::TreeSealIntent,
        evidence: PersistentRecoveryEvidence::new(
            PathBuf::from("source-parent/root"),
            Some("fs".into()),
            1,
            2,
            Some(3),
            0o500,
        )
        .unwrap(),
        pre_mode: 0o700,
        expected_mode: 0o500,
        reverses_mutation_id: None,
        application: ApplicationStatus::Applied,
    };
    let mut snapshot = ReplayedTransaction {
        id: TransactionId([0xd1; 16]),
        state: TransactionState::TreeSealIntent,
        staging_schema_version: Some(4),
        permissions: vec![permission; MAX_RECOVERY_PERMISSION_RECORDS + 1],
        staging: Some(metadata()),
        tree_manifest: None,
        rename_outcome: None,
        undo_rename_outcome: None,
        purge_removed_entries: 0,
        purge_last_path: None,
    };
    assert!(validate_recovery_workload(&snapshot).is_err());

    let permission = snapshot.permissions[0].clone();
    snapshot.permissions = vec![permission; MAX_RECOVERY_PERMISSION_OPERATIONS + 1];
    assert!(validate_recovery_workload(&snapshot).is_err());

    let deep = (0..=MAX_RECOVERY_PATH_COMPONENTS)
        .map(|index| format!("d{index}"))
        .collect::<PathBuf>();
    snapshot.permissions = vec![DurablePermission {
        mutation_id: 2,
        phase: TransactionState::TreeSealIntent,
        evidence: PersistentRecoveryEvidence::new(deep, Some("fs".into()), 1, 2, Some(3), 0o500)
            .unwrap(),
        pre_mode: 0o700,
        expected_mode: 0o500,
        reverses_mutation_id: None,
        application: ApplicationStatus::Applied,
    }];
    assert!(validate_recovery_workload(&snapshot).is_err());
}

#[test]
fn oversized_candidate_set_is_rejected_before_anchor_acquisition() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    {
        let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
        for index in 0..=MAX_RECOVERY_TRANSACTIONS {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            engine
                .wal
                .begin_staging(TransactionId(bytes), metadata())
                .unwrap();
        }
    }

    let (engine, report) = SealedStagingEngine::open(&store).unwrap();
    let calls = std::cell::Cell::new(0);
    let error = engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other("provider must not run"))
        })
        .err()
        .unwrap();
    assert_eq!(error.stage(), "recovery workload budget");
    assert_eq!(calls.get(), 0);
}

#[test]
fn recovery_candidate_order_is_deterministic_by_transaction_id() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    {
        let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
        assert!(report.is_empty());
        engine
            .wal
            .begin_staging(TransactionId([0xf2; 16]), metadata())
            .unwrap();
        engine
            .wal
            .begin_staging(TransactionId([0x12; 16]), metadata())
            .unwrap();
    }

    let (_engine, report) = SealedStagingEngine::open(&store).unwrap();
    assert_eq!(
        report
            .candidates()
            .iter()
            .map(StartupRecoveryCandidate::transaction)
            .collect::<Vec<_>>(),
        vec![TransactionId([0x12; 16]), TransactionId([0xf2; 16])]
    );
}

#[test]
fn report_omission_duplication_and_reordering_fail_before_provider_or_wal_change() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let first = TransactionId([0x31; 16]);
    let second = TransactionId([0x32; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
        engine.wal.begin_staging(second, metadata()).unwrap();
        engine.wal.begin_staging(first, metadata()).unwrap();
    }

    for mutation in ["omit", "duplicate", "reorder"] {
        let (engine, mut report) = SealedStagingEngine::open(&store).unwrap();
        match mutation {
            "omit" => {
                report.candidates.pop();
            }
            "duplicate" => {
                let transaction = report.candidates[0].transaction;
                let generation = report.candidates[0].generation;
                report.candidates.push(StartupRecoveryCandidate {
                    transaction,
                    generation,
                });
            }
            "reorder" => report.candidates.reverse(),
            _ => unreachable!(),
        }
        let calls = std::cell::Cell::new(0);
        let error = engine
            .recover_startup(report, |_, _| {
                calls.set(calls.get() + 1);
                Err(std::io::Error::other("provider must not run"))
            })
            .err()
            .unwrap();
        assert_eq!(error.stage(), "report validation");
        assert_eq!(calls.get(), 0);

        let (reopened, report) = SealedStagingEngine::open(&store).unwrap();
        assert_eq!(reopened.state(first), Some(TransactionState::Prepared));
        assert_eq!(reopened.state(second), Some(TransactionState::Prepared));
        assert_eq!(report.candidates().len(), 2);
        drop(reopened);
    }
}

#[test]
fn cross_generation_report_fails_before_provider_or_wal_change() {
    let first_temp = crate::secure_test_tempdir().unwrap();
    let first_store =
        SealWalStore::open_or_create(&first_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let transaction = TransactionId([0x41; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&first_store).unwrap();
        engine.begin_transaction(transaction, metadata()).unwrap();
    }
    let (_first_engine, report) = SealedStagingEngine::open(&first_store).unwrap();

    let second_temp = crate::secure_test_tempdir().unwrap();
    let second_store =
        SealWalStore::open_or_create(&second_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let (second_engine, _) = SealedStagingEngine::open(&second_store).unwrap();
    let calls = std::cell::Cell::new(0);
    let error = second_engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other("provider must not run"))
        })
        .err()
        .unwrap();
    assert_eq!(error.stage(), "report validation");
    assert_eq!(calls.get(), 0);
}

#[test]
fn recovery_step_exhaustion_never_mints_readiness() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let transaction = TransactionId([0xe1; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
    engine.begin_transaction(transaction, metadata()).unwrap();
    let mut provider = |_, _: &StagingTransactionMetadata| {
        Err(std::io::Error::other(
            "provider must not run after exhaustion",
        ))
    };

    let error = engine
        .recover_transaction_with_step_limit_for_test(transaction, &mut provider, 0)
        .unwrap_err();
    assert_eq!(error.transaction(), Some(transaction));
    assert_eq!(error.stage(), "step exhaustion");
    assert_eq!(engine.state(transaction), Some(TransactionState::Prepared));
    assert!(
        engine
            .begin_transaction(TransactionId([0xe2; 16]), metadata())
            .is_err()
    );
}

#[test]
fn manual_recovery_block_never_requests_filesystem_anchors() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let transaction = TransactionId([0xe3; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
        engine.begin_transaction(transaction, metadata()).unwrap();
        engine
            .wal
            .transition_staging_for_test(transaction, TransactionState::RecoveryRequired)
            .unwrap();
    }

    let (engine, report) = SealedStagingEngine::open(&store).unwrap();
    let calls = std::cell::Cell::new(0);
    let error = engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other("anchor lookup must be forbidden"))
        })
        .err()
        .unwrap();
    assert_eq!(error.stage(), "manual recovery block");
    assert_eq!(calls.get(), 0);
}

#[test]
fn raw_state_transition_cannot_mint_object_bound_purge_authority() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
    let transaction = TransactionId([85; 16]);
    engine.begin_transaction(transaction, metadata()).unwrap();
    for state in [TransactionState::Purgeable, TransactionState::Purged] {
        assert!(
            engine
                .wal
                .transition_staging_for_test(transaction, state)
                .is_err()
        );
    }
    assert_eq!(engine.state(transaction), Some(TransactionState::Prepared));
}
