use super::*;
use crate::authority::PersistentRecoveryEvidence;
use crate::local_backend::CertifiedLocalBackend;
use crate::seal_wal::{
    DurableSourceParentStrategy, ObjectIncarnation, PermissionIntent, StagingLocator,
    StrongObjectIdentity,
};
use std::ffi::OsString;
use std::path::PathBuf;

fn identity(inode: u64) -> StrongObjectIdentity {
    StrongObjectIdentity::new(1, inode, ObjectIncarnation::new(inode + 1000))
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
fn high_level_open_owns_staging_begin_and_blocks_parallel_transaction() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
    assert!(report.work.is_empty());
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
        assert!(report.work.is_empty());
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
    assert!(report.work.is_empty());
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
    assert!(matches!(
        report.work.as_slice(),
        [RecoveryWork::RestoreBeforeRename { .. }]
    ));
    assert!(
        engine
            .begin_transaction(TransactionId([84; 16]), metadata())
            .is_err()
    );
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
            .transition_staging(transaction, TransactionState::ParentSealIntent)
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
            .transition_staging(transaction, TransactionState::ParentSealed)
            .unwrap();
        engine
            .wal
            .transition_staging(transaction, TransactionState::TreeSealIntent)
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
                    entry_count: 1,
                    sha256: [0x88; 32],
                },
            )
            .unwrap();
        engine
            .wal
            .transition_staging(transaction, TransactionState::TreeSealed)
            .unwrap();
        engine.wal.record_rename_intent(transaction).unwrap();
        engine
            .wal
            .record_applied_rename_for_test(transaction)
            .unwrap();
        engine
            .wal
            .transition_staging(transaction, TransactionState::StagedUnverified)
            .unwrap();
        engine
            .wal
            .transition_staging(transaction, TransactionState::Quarantined)
            .unwrap();

        assert!(
            engine
                .begin_transaction(TransactionId([89; 16]), metadata)
                .is_err()
        );
    }

    let (mut reopened, report) = SealedStagingEngine::open(&store).unwrap();
    assert!(matches!(
        report.work.as_slice(),
        [RecoveryWork::PreserveQuarantine { transaction: id }] if *id == transaction
    ));
    assert!(
        reopened
            .begin_transaction(TransactionId([90; 16]), metadata())
            .is_err()
    );
}

#[test]
fn purge_states_are_unreachable_without_future_held_object_capability() {
    let temp = crate::secure_test_tempdir().unwrap();
    let store_path = temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let (mut engine, _) = SealedStagingEngine::open(&store).unwrap();
    let transaction = TransactionId([85; 16]);
    engine.begin_transaction(transaction, metadata()).unwrap();
    for state in [TransactionState::Purgeable, TransactionState::Purged] {
        assert!(engine.transition(transaction, state).is_err());
    }
    assert_eq!(engine.state(transaction), Some(TransactionState::Prepared));
}
