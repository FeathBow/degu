use super::*;
use degu_core::finding::{
    FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost, finalize_findings,
};
use degu_core::oplog::{ObjectIdentity, OpOutcome};
use degu_core::seal_store::SealWalStore;
use degu_core::seal_wal::{ProductionAssociation, StagingLocator, TransactionId};
use degu_core::sealed_staging::{ForwardStagingRequest, forward_filesystem_id};
use degu_core::store_activation::StoreActivationError;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn context() -> (tempfile::TempDir, DetectCtx) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let home = temp.path().canonicalize().unwrap();
    let state = home.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(state.join("degu")).unwrap();
    std::fs::set_permissions(state.join("degu"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let ctx = DetectCtx::for_test(
        home,
        [(OsString::from("XDG_STATE_HOME"), state.into_os_string())],
    );
    (temp, ctx)
}

#[test]
fn missing_fixed_anchor_blocks_without_creating_a_store() {
    let (_temp, ctx) = context();
    let desired = std::fs::canonicalize(ctx.xdg_state())
        .unwrap()
        .join("degu/sealed-staging");
    let missing = ctx.home.join("system-anchor");
    let error = storage::sealed_staging_store_for_mutation_with(&ctx, |actual| {
        assert_eq!(actual, desired);
        Err(StoreActivationError::AnchorNotProvisioned {
            path: missing.clone(),
        })
    })
    .err()
    .expect("missing anchor unexpectedly allowed a store");

    assert!(
        format!("{error:#}").contains("not provisioned"),
        "unexpected error: {error:#}"
    );
    assert!(!missing.exists());
    assert!(!desired.exists());
}

#[test]
fn clean_lock_selects_forward_staging_only_for_restorable_clean() {
    let (_temp, ctx) = context();
    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-session-lock")).unwrap();
    let restorable = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: None,
        forward_clean: true,
        _unsupported_legacy_lease: None,
    };
    assert!(restorable.forward_clean);

    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-purge-lock")).unwrap();
    let direct_purge = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: None,
        forward_clean: false,
        _unsupported_legacy_lease: None,
    };
    assert!(!direct_purge.forward_clean);
}

#[test]
fn production_locator_selection_has_no_home_or_xdg_input() {
    let first = degu_core::store_activation::ActivationAnchorLocator::for_current_euid().unwrap();
    let changed_home = Path::new("/tmp/degu-home-trap");
    let changed_state = Path::new("/tmp/degu-xdg-trap");
    let ctx = DetectCtx::for_test(
        changed_home.to_path_buf(),
        [(
            OsString::from("XDG_STATE_HOME"),
            changed_state.as_os_str().to_os_string(),
        )],
    );
    assert_ne!(storage::sealed_staging_store_path(&ctx), first.as_path());
    assert_eq!(
        degu_core::store_activation::ActivationAnchorLocator::for_current_euid()
            .unwrap()
            .as_path(),
        first.as_path()
    );
}

#[test]
fn desired_store_remains_the_canonical_current_xdg_locator_before_activation() {
    let (_temp, ctx) = context();
    let expected = std::fs::canonicalize(ctx.xdg_state())
        .unwrap()
        .join("degu/sealed-staging");
    let mut observed = PathBuf::new();
    let error = storage::sealed_staging_store_for_mutation_with(&ctx, |desired| {
        observed = desired.to_path_buf();
        Err(StoreActivationError::NotResumable)
    })
    .err()
    .expect("sentinel activation failure unexpectedly succeeded");
    assert!(format!("{error:#}").contains("not in a resumable"));
    assert_eq!(observed, expected);
}

#[test]
fn production_clean_reaches_verified_commit_and_keeps_jsonl_diagnostic_only() {
    let (_temp, ctx) = context();
    let source_parent = ctx.home.join("source-parent");
    let source = source_parent.join("root");
    std::fs::create_dir(&source_parent).unwrap();
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("payload"), b"sealed").unwrap();
    std::fs::set_permissions(&source_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();

    let finding = finalize_findings(
        vec![FindingCandidate {
            ecosystem: "test".to_string(),
            path: source.clone(),
            kind: FindingKind::PackageCache,
            bytes_apparent: 6,
            bytes_allocated: 4096,
            age_days: None,
            bytes_hardlinked: 0,
            inodes: 2,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            shared_writable_dirs: 0,
            parent_grants_foreign_mutation: false,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery: Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            ownership: Ownership::Standalone,
            hazard: None,
            rationale: "production fixture".to_string(),
        }],
        FindingSource::WellKnownRoot,
    )
    .pop()
    .unwrap();
    let plan =
        CapturedCleanPlan::capture(degu_core::plan::Plan::new(vec![finding], false).unwrap())
            .unwrap();
    let store = SealWalStore::open_or_create(&ctx.xdg_state().join("degu/sealed-staging")).unwrap();
    let (engine, startup) = SealedStagingEngine::open(&store).unwrap();
    let (ready, _) = engine
        .recover_startup(startup, |_, _| {
            Err(std::io::Error::other(
                "empty recovery must not request anchors",
            ))
        })
        .unwrap();
    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-clean-lock")).unwrap();
    let mut session = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: Some(ready),
        forward_clean: true,
        _unsupported_legacy_lease: None,
    };

    let executed = session.execute_clean(&plan, false, &|_| Ok(())).unwrap();
    assert_eq!(executed.len(), 1);
    assert!(!executed[0].failed());
    assert_eq!(executed[0].state_label(), "staged");
    assert!(!source.exists());
    let staged = executed[0].trash_entry().unwrap();
    assert!(staged.is_dir());

    let entries = session
        .sealed_staging
        .as_ref()
        .unwrap()
        .production_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].state(),
        degu_core::authority::TransactionState::VerifiedCommitted
    );
    assert_eq!(
        entries[0].destination_basename(),
        staged.file_name().unwrap()
    );

    let records = session.lifecycle.operations().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, OpOutcome::Ok);
    let json = serde_json::to_value(&records[0]).unwrap();
    assert!(json.get("transaction").is_none());
}

#[test]
fn exact_wal_association_blocks_purge_and_undo_without_jsonl_authority() {
    let (_temp, ctx) = context();
    let source_parent = ctx.home.join("source-parent");
    let source = source_parent.join("root");
    let trash_parent = ctx.xdg_state().join("degu/trash");
    let staged = trash_parent.join("0001-sealed");
    std::fs::create_dir(&source_parent).unwrap();
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("payload"), b"sealed").unwrap();
    std::fs::create_dir(&trash_parent).unwrap();
    std::fs::set_permissions(&source_parent, std::fs::Permissions::from_mode(0o770)).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o770)).unwrap();
    std::fs::set_permissions(&trash_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    let home_fd: rustix::fd::OwnedFd = std::fs::File::open(&ctx.home).unwrap().into();
    let filesystem_id = forward_filesystem_id(&home_fd).unwrap();
    let request = ForwardStagingRequest::new(
        rustix::io::dup(&home_fd).unwrap(),
        std::fs::File::open(&source_parent).unwrap().into(),
        StagingLocator::new(PathBuf::from("source-parent"), filesystem_id.clone()).unwrap(),
        OsString::from("root"),
        rustix::io::dup(&home_fd).unwrap(),
        std::fs::File::open(&trash_parent).unwrap().into(),
        StagingLocator::new(PathBuf::from("state/degu/trash"), filesystem_id).unwrap(),
        OsString::from("0001-sealed"),
    )
    .with_production_association(
        ProductionAssociation::new("sealed-reclamation".to_string()).unwrap(),
    );
    let store = SealWalStore::open_or_create(&ctx.xdg_state().join("degu/sealed-staging")).unwrap();
    let (engine, startup) = SealedStagingEngine::open(&store).unwrap();
    let (mut ready, _) = engine
        .recover_startup(startup, |_, _| {
            Err(std::io::Error::other(
                "empty recovery must not request anchors",
            ))
        })
        .unwrap();
    ready
        .stage_to_verified_commit(TransactionId([0xc2; 16]), request)
        .unwrap();
    assert!(staged.is_dir());

    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-session-lock")).unwrap();
    let session = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: Some(ready),
        forward_clean: false,
        _unsupported_legacy_lease: None,
    };

    // WAL alone blocks purge before a claim, even with no JSONL record.
    let plan = session.plan_purge_all().unwrap();
    let purge = session.execute_purge_all(plan);
    assert!(purge.purged.is_empty());
    assert_eq!(purge.failed.len(), 1);
    assert!(purge.failed[0].1.contains("sealed-staging WAL"));
    assert!(staged.is_dir());
    assert!(!trash_parent.join(".claims").exists());

    // A plausible legacy JSONL record cannot steal undo authority from WAL.
    let original = ctx.home.join("restored-cache");
    let record = serde_json::json!({
        "ts": "2000-01-01T00:00:00Z",
        "tool_version": "0.0.0",
        "command": "clean",
        "action": "trash",
        "path": original,
        "bytes_allocated": 1,
        "inodes": 1,
        "trash_entry": staged,
        "reclamation_id": "sealed-reclamation",
        "expected_identity": ObjectIdentity::capture(&staged).unwrap(),
        "destination_parent": ObjectIdentity::capture(&ctx.home).unwrap(),
        "outcome": "ok"
    });
    let log_path = ctx.xdg_state().join("degu/ops.jsonl");
    std::fs::write(&log_path, format!("{record}\n")).unwrap();
    let before = std::fs::read(&log_path).unwrap();
    let undo = session.undo_latest().unwrap().unwrap();
    assert!(undo.restored.is_empty());
    assert_eq!(undo.failed.len(), 1);
    assert!(undo.failed[0].reason.contains("sealed-staging WAL"));
    assert_eq!(std::fs::read(&log_path).unwrap(), before);
    assert!(staged.is_dir());
    assert!(!original.exists());
}
