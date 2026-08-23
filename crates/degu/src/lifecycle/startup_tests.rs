use super::*;
use degu_core::activation::StoreActivationError;
use degu_core::finding::{
    FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost, finalize_findings,
};
use degu_core::oplog::{ObjectIdentity, OpOutcome};
use degu_core::seal::store::SealWalStore;
use degu_core::seal::wal::{ProductionAssociation, StagingLocator, TransactionId};
use degu_core::staging::{ForwardStagingRequest, SealedStagingEngine, forward_filesystem_id};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

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
fn clean_lock_selects_forward_staging_for_restorable_and_direct_purge() {
    let (_temp, ctx) = context();
    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-session-lock")).unwrap();
    let restorable = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: None,
        forward_clean: true,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };
    assert!(restorable.forward_clean);

    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-purge-lock")).unwrap();
    let direct_purge = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: None,
        forward_clean: true,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };
    assert!(direct_purge.forward_clean);
}

#[test]
fn restored_association_no_longer_blocks_legacy_mutation() {
    assert!(!sealed_mutation_authority_active(
        degu_core::authority::TransactionState::Restored
    ));
    assert!(sealed_mutation_authority_active(
        degu_core::authority::TransactionState::VerifiedCommitted
    ));
    assert!(sealed_mutation_authority_active(
        degu_core::authority::TransactionState::UndoConflict
    ));
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
fn production_clean_reaches_verified_commit_outside_home_on_the_same_mount() {
    let (_temp, ctx) = context();
    let external = tempfile::tempdir().unwrap();
    std::fs::set_permissions(external.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source_parent = external
        .path()
        .canonicalize()
        .unwrap()
        .join("source-parent");
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
    let store = SealWalStore::open_or_create_for_integration_test(
        &ctx.xdg_state().join("degu/sealed-staging"),
    )
    .unwrap();
    let (engine, startup) = SealedStagingEngine::open_for_integration_test(&store).unwrap();
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
        sealed_staging: Some(ActivatedReadyStagingEngine::from_ready_for_integration_test(ready)),
        forward_clean: true,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };

    let executed = session.execute_clean(&plan, false, &|_| Ok(())).unwrap();
    assert_eq!(executed.len(), 1);
    assert!(!executed[0].failed(), "{:?}", executed[0].failure_reason());
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
    let recovery_anchor = entries[0]
        .recovery_anchor()
        .expect("v11 production entry must persist its mount-domain anchor");
    assert!(source_parent.starts_with(recovery_anchor));
    assert!(staged.starts_with(recovery_anchor));
    assert_ne!(recovery_anchor, ctx.home.as_path());

    let records = session.lifecycle.operations().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, OpOutcome::Ok);
    let json = serde_json::to_value(&records[0]).unwrap();
    assert!(json.get("transaction").is_none());

    // Before undo authority is minted, the c2 gate still blocks legacy purge.
    let purge = session.execute_purge_all(session.plan_purge_all().unwrap());
    assert!(purge.purged.is_empty());
    assert_eq!(purge.failed.len(), 1);
    assert!(staged.is_dir());

    // Reopen the WAL under a different current HOME. The v11 entry's recorded
    // mount-domain anchor, not ambient HOME, must still drive verified undo.
    drop(session);
    let changed_home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(changed_home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let changed_ctx = DetectCtx::for_test(
        changed_home.path().canonicalize().unwrap(),
        [(
            "XDG_STATE_HOME".to_owned(),
            ctx.xdg_state().into_os_string(),
        )],
    );
    let store = SealWalStore::open_or_create_for_integration_test(
        &changed_ctx.xdg_state().join("degu/sealed-staging"),
    )
    .unwrap();
    let (engine, startup) = SealedStagingEngine::open_for_integration_test(&store).unwrap();
    let (ready, _) = engine
        .recover_startup(startup, |_, metadata| {
            mount::metadata_anchors(&changed_ctx.home, metadata)
        })
        .unwrap();
    let lock =
        std::fs::File::create(changed_ctx.xdg_state().join("degu/reopened-clean-lock")).unwrap();
    let mut session = MutationSession {
        lifecycle: Lifecycle::new(&changed_ctx),
        _mutation_lock: lock,
        sealed_staging: Some(ActivatedReadyStagingEngine::from_ready_for_integration_test(ready)),
        forward_clean: true,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };

    // Remove the entire reporting projection. The leased WAL must still select
    // and authorize the exact group without reconstructing authority from JSONL.
    std::fs::rename(
        ctx.xdg_state().join("degu/ops.jsonl"),
        ctx.xdg_state().join("degu/ops.detached"),
    )
    .unwrap();
    let undo = session.undo_latest().unwrap().unwrap();
    assert_eq!(undo.restored.len(), 1);
    assert!(undo.failed.is_empty());
    assert!(source.is_dir());
    assert!(!staged.exists());
    assert_eq!(std::fs::read(source.join("payload")).unwrap(), b"sealed");

    let records = session.lifecycle.operations().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, degu_core::oplog::OpAction::Restore);
    assert_eq!(records[0].outcome, OpOutcome::Ok);
    let json = serde_json::to_value(&records[0]).unwrap();
    assert!(json.get("transaction").is_none());

    // A later explicit trash batch that finds sealed drift must stop before a
    // legacy sibling reaches claim, deletion, or claim housekeeping.
    let second = source_parent.join("second-root");
    std::fs::create_dir(&second).unwrap();
    std::fs::write(second.join("payload"), b"second").unwrap();
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o700)).unwrap();
    let second_finding = finalize_findings(
        vec![FindingCandidate {
            ecosystem: "test".to_string(),
            path: second.clone(),
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
            rationale: "mixed purge fixture".to_string(),
        }],
        FindingSource::WellKnownRoot,
    )
    .pop()
    .unwrap();
    let second_plan = CapturedCleanPlan::capture(
        degu_core::plan::Plan::new(vec![second_finding], false).unwrap(),
    )
    .unwrap();
    let second_execution = session
        .execute_clean(&second_plan, false, &|_| Ok(()))
        .unwrap();
    let sealed = second_execution[0].trash_entry().unwrap().to_path_buf();
    std::fs::write(sealed.join("post-commit-drift"), b"drift").unwrap();
    let legacy = sealed.parent().unwrap().join("9999-legacy");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(legacy.join("keep"), b"keep").unwrap();

    let mixed = session.plan_purge_all().unwrap();
    let report = session.execute_explicit_purge_all(mixed);
    assert!(report.purged.is_empty());
    assert!(report.failed.len() >= 2);
    assert!(sealed.is_dir());
    assert!(legacy.is_dir());
    assert!(!sealed.parent().unwrap().join(".claims/9999").exists());
}

#[test]
fn production_clean_purge_consumes_authority_and_reaches_purged() {
    let (_temp, ctx) = context();
    let source_parent = ctx.home.join("purge-source-parent");
    let source = source_parent.join("root");
    std::fs::create_dir(&source_parent).unwrap();
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("payload"), b"sealed purge").unwrap();
    std::fs::set_permissions(&source_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    let finding = finalize_findings(
        vec![FindingCandidate {
            ecosystem: "test".to_string(),
            path: source.clone(),
            kind: FindingKind::PackageCache,
            bytes_apparent: 12,
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
            rationale: "production purge fixture".to_string(),
        }],
        FindingSource::WellKnownRoot,
    )
    .pop()
    .unwrap();
    let plan =
        CapturedCleanPlan::capture(degu_core::plan::Plan::new(vec![finding], false).unwrap())
            .unwrap();
    let store = SealWalStore::open_or_create_for_integration_test(
        &ctx.xdg_state().join("degu/sealed-staging"),
    )
    .unwrap();
    let (engine, startup) = SealedStagingEngine::open_for_integration_test(&store).unwrap();
    let (ready, _) = engine
        .recover_startup(startup, |_, _| {
            Err(std::io::Error::other(
                "empty recovery must not request anchors",
            ))
        })
        .unwrap();
    let lock = std::fs::File::create(ctx.xdg_state().join("degu/test-clean-purge-lock")).unwrap();
    let mut session = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: Some(ActivatedReadyStagingEngine::from_ready_for_integration_test(ready)),
        forward_clean: true,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };

    let executed = session.execute_clean(&plan, true, &|_| Ok(())).unwrap();
    assert_eq!(executed.len(), 1);
    assert!(!executed[0].failed(), "{:?}", executed[0].failure_reason());
    assert!(executed[0].purged());
    assert_eq!(executed[0].state_label(), "purged");
    let staged = executed[0].trash_entry().unwrap().to_path_buf();
    assert!(!staged.exists());
    assert!(!source.exists());
    let entries = session
        .sealed_staging
        .as_ref()
        .unwrap()
        .production_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].state(),
        degu_core::authority::TransactionState::Purged
    );
    assert!(
        session
            .sealed_staging
            .as_ref()
            .unwrap()
            .verified_undo_token(entries[0].transaction(), entries[0].reclamation_id())
            .is_none()
    );
    assert!(!staged.parent().unwrap().join(".claims/0001").exists());
}

#[test]
fn forged_jsonl_mapping_cannot_steal_wal_undo_authority() {
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
    )
    .with_recovery_anchor(ctx.home.clone());
    let store = SealWalStore::open_or_create_for_integration_test(
        &ctx.xdg_state().join("degu/sealed-staging"),
    )
    .unwrap();
    let (engine, startup) = SealedStagingEngine::open_for_integration_test(&store).unwrap();
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
    let mut session = MutationSession {
        lifecycle: Lifecycle::new(&ctx),
        _mutation_lock: lock,
        sealed_staging: Some(ActivatedReadyStagingEngine::from_ready_for_integration_test(ready)),
        forward_clean: false,
        authority_purged: std::collections::HashSet::new(),
        _unsupported_legacy_lease: None,
    };

    // Snapshot blockers retain strong identity, so a different current name
    // cannot route the exact WAL-bound object into legacy undo.
    let identity = session
        .sealed_staging
        .as_ref()
        .unwrap()
        .production_entries()[0]
        .root_identity();
    let alternate = trash_parent.join("alternate-sealed-name");
    std::fs::rename(&staged, &alternate).unwrap();
    let reason = sealed_legacy_undo_block(&alternate, &[(Some(staged.clone()), identity)], true)
        .expect("strong identity match did not block the alternate name");
    assert!(reason.contains("exact object"));
    let reason = sealed_legacy_undo_block(&alternate, &[(None, identity)], false)
        .expect("HOME authentication failure dropped the active strong identity");
    assert!(reason.contains("exact object"));
    std::fs::rename(&alternate, &staged).unwrap();

    // WAL alone blocks purge before a claim, even with no JSONL record.
    let plan = session.plan_purge_all().unwrap();
    let purge = session.execute_purge_all(plan);
    assert!(purge.purged.is_empty());
    assert_eq!(purge.failed.len(), 1);
    assert!(purge.failed[0].1.contains("sealed-staging WAL"));
    assert!(staged.is_dir());
    assert!(!trash_parent.join(".claims").exists());
    assert!(session.lifecycle.operations().unwrap().is_empty());

    // A plausible record with the genuine group and trash destination but a
    // forged source mapping cannot select or authorize WAL undo.
    let forged_original = ctx.home.join("forged-restored-cache");
    let record = serde_json::json!({
        "ts": "2000-01-01T00:00:00Z",
        "tool_version": "0.0.0",
        "command": "clean",
        "action": "trash",
        "path": forged_original,
        "bytes_allocated": 1,
        "inodes": 1,
        "trash_entry": staged,
        "reclamation_id": "sealed-reclamation",
        "expected_identity": ObjectIdentity::capture(&staged).unwrap(),
        "destination_parent": ObjectIdentity::capture(&ctx.home).unwrap(),
        "outcome": "ok"
    });
    let log_path = ctx.xdg_state().join("degu/ops.jsonl");
    let unrelated_trash = trash_parent.join("9999-unrelated");
    std::fs::create_dir(&unrelated_trash).unwrap();
    let unrelated_original = ctx.home.join("unrelated-original");
    let newer_unrelated = serde_json::json!({
        "ts": "2000-01-02T00:00:00Z",
        "tool_version": "0.0.0",
        "command": "clean",
        "action": "trash",
        "path": unrelated_original,
        "bytes_allocated": 1,
        "inodes": 1,
        "trash_entry": unrelated_trash,
        "reclamation_id": "newer-unrelated-group",
        "expected_identity": ObjectIdentity::capture(&unrelated_trash).unwrap(),
        "destination_parent": ObjectIdentity::capture(&ctx.home).unwrap(),
        "outcome": "ok"
    });
    std::fs::write(&log_path, format!("{record}\n{newer_unrelated}\n")).unwrap();
    let before = std::fs::read(&log_path).unwrap();

    // The newer unrelated group must not hide the forged member of the exact
    // WAL-selected reclamation group.
    let undo = session.undo_latest().unwrap().unwrap();
    assert!(undo.restored.is_empty());
    assert!(!undo.failed.is_empty());
    assert!(
        undo.failed
            .iter()
            .all(|failed| failed.reason.contains("mixes legacy/unmapped"))
    );
    assert_eq!(std::fs::read(&log_path).unwrap(), before);
    assert!(staged.is_dir());
    assert!(!source.exists());
    assert!(!forged_original.exists());
}
