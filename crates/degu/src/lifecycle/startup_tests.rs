use super::*;
use degu_core::authority::TransactionState;
use degu_core::local_backend::CertifiedLocalBackend;
use degu_core::seal_store::WAL_FILE_NAME;
use degu_core::seal_wal::{
    DurableSourceParentStrategy, ObjectIncarnation, StagingLocator, StagingTransactionMetadata,
    StrongObjectIdentity, TransactionId,
};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn context() -> (tempfile::TempDir, DetectCtx) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let state = home.join("state");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ctx = DetectCtx::for_test(
        home,
        [(OsString::from("XDG_STATE_HOME"), state.into_os_string())],
    );
    (temp, ctx)
}

fn store_path(ctx: &DetectCtx) -> PathBuf {
    std::fs::canonicalize(ctx.xdg_state())
        .unwrap()
        .join("degu/sealed-staging")
}

fn identity(inode: u64) -> StrongObjectIdentity {
    StrongObjectIdentity::new_with_mount(1, inode, ObjectIncarnation::new(inode + 1000), 7)
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
fn never_activated_store_stays_dormant_under_shared_state_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let state = home.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o770)).unwrap();
    let ctx = DetectCtx::for_test(
        home,
        [(OsString::from("XDG_STATE_HOME"), state.into_os_string())],
    );

    let session = Lifecycle::new(&ctx).lock().unwrap();
    assert!(!storage::sealed_staging_store_path(&ctx).exists());
    drop(session);
}

#[test]
fn production_mutation_session_retains_the_exact_wal_lease() {
    let (_temp, ctx) = context();
    let store_path = store_path(&ctx);
    let session = Lifecycle::new(&ctx).lock().unwrap();
    assert!(store_path.join(WAL_FILE_NAME).is_file());

    let store = SealWalStore::open_or_create(&store_path).unwrap();
    assert!(matches!(
        SealedStagingEngine::open(&store),
        Err(degu_core::sealed_staging::StagingEngineError::Store(
            degu_core::seal_store::StoreError::Lease(degu_core::seal_wal::RecoveryLockError::Busy)
        ))
    ));
    drop(session);

    let (engine, report) = SealedStagingEngine::open(&store).unwrap();
    assert!(report.is_empty());
    drop(engine);
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol authority loss
fn missing_production_wal_blocks_every_mutation_session() {
    let (_temp, ctx) = context();
    let store_path = store_path(&ctx);
    drop(Lifecycle::new(&ctx).lock().unwrap());
    std::fs::remove_file(store_path.join(WAL_FILE_NAME)).unwrap();

    let error = match Lifecycle::new(&ctx).lock() {
        Ok(_) => panic!("missing WAL unexpectedly produced a mutation session"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("missing its durable WAL entry"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn unexpected_nonterminal_recovery_blocks_legacy_clean_purge_and_undo_session() {
    let (_temp, ctx) = context();
    let store_path = store_path(&ctx);
    // Initialize the production store under the same global lifecycle gate.
    drop(Lifecycle::new(&ctx).lock().unwrap());

    let transaction = TransactionId([0xa3; 16]);
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    {
        let (mut engine, report) = SealedStagingEngine::open(&store).unwrap();
        assert!(report.is_empty());
        engine.begin_transaction(transaction, metadata()).unwrap();
    }

    let error = match Lifecycle::new(&ctx).lock() {
        Ok(_) => panic!("nonterminal recovery unexpectedly produced a mutation session"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("anchor certification"),
        "unexpected error: {error:#}"
    );

    let (mut reopened, report) = SealedStagingEngine::open(&store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(
        reopened.state(transaction),
        Some(TransactionState::Prepared)
    );
    assert!(
        reopened
            .begin_transaction(TransactionId([0xa4; 16]), metadata())
            .is_err()
    );
}
