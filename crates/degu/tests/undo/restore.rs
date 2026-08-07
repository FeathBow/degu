use super::*;

#[test]
fn undo_restores_latest_trash_record_once() {
    let (home, state, cache) = fake_pip_cache();
    let expected = std::fs::read(cache.join("wheel.whl")).unwrap();
    clean_pip_cache(&home, &state);
    let records = oplog_records(&state);
    let trash_entry = final_trash_entry(&records);

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let restored_path = cache.canonicalize().unwrap();
    assert!(stdout.contains(&format!("restored {}", restored_path.display())));
    assert!(stdout.contains("Restored 1 of 1 from reclamation "));
    assert!(cache.is_dir());
    assert_eq!(std::fs::read(cache.join("wheel.whl")).unwrap(), expected);
    assert!(!trash_entry.exists());
    let records = oplog_records(&state);
    assert_eq!(records.len(), 4);
    assert_eq!(records[2]["action"], "restore");
    assert_eq!(records[2]["outcome"], "pending");
    assert_eq!(records[3]["action"], "restore");
    assert_eq!(records[3]["outcome"], "ok");
    assert_eq!(records[3]["reclamation_id"], records[1]["reclamation_id"]);

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "Nothing to undo.\n");
}

// Two sibling caches (the platform default pip and go-build dirs) restore into
// the SAME parent directory in one reclamation. This is the multi-sibling guard for
// issue #254: the destination-parent check MUST stay `Stable` (device+inode+kind)
// so that restoring the first sibling — which bumps the parent's ctime — does not
// make the second sibling's parent check spuriously refuse. Do not tighten the
// parent check to `Exact`; it would break this test.
#[test]
fn undo_restores_entire_latest_reclamation() {
    let (home, state, pip_cache) = fake_pip_cache();
    let go_build_cache = fake_go_build_cache(&home);
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    // Both caches share the same parent so this exercises sibling restores.
    assert_eq!(pip_cache.parent(), go_build_cache.parent());
    clean_all_caches(&home, &state);
    let records = oplog_records(&state);
    let trashed = ok_trash_records(&records);
    assert_eq!(trashed.len(), 2);
    let reclamation_id = record_reclamation_id(trashed[0]).to_string();
    assert_eq!(record_reclamation_id(trashed[1]), reclamation_id);

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    // Both siblings restored into the shared parent.
    assert!(pip_cache.exists());
    assert!(go_build_cache.exists());
    let records = oplog_records(&state);
    let restores = restore_records(&records);
    assert_eq!(restores.len(), 2);
    assert_eq!(record_reclamation_id(restores[0]), reclamation_id);
    assert_eq!(record_reclamation_id(restores[1]), reclamation_id);
    assert_eq!(record_path(restores[0]), record_path(trashed[1]));
    assert_eq!(record_path(restores[1]), record_path(trashed[0]));
}

#[test]
fn undo_resumes_same_reclamation_after_failed_restore() {
    let (home, state, _) = fake_pip_cache();
    let _go_build_cache = fake_go_build_cache(&home);
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    clean_all_caches(&home, &state);
    let records = oplog_records(&state);
    let trashed = ok_trash_records(&records);
    assert_eq!(trashed.len(), 2);
    let blocked_path = record_path(trashed[1]);
    let restored_path = record_path(trashed[0]);
    let reclamation_id = record_reclamation_id(trashed[0]).to_string();
    std::fs::create_dir_all(&blocked_path).unwrap();
    std::fs::write(blocked_path.join("replacement"), b"replacement").unwrap();

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("failed {}:", blocked_path.display())));
    assert!(stdout.contains(&format!("restored {}", restored_path.display())));
    assert!(restored_path.exists());
    assert!(record_trash_entry(trashed[1]).exists());
    let records = oplog_records(&state);
    let restores = restore_records(&records);
    assert_eq!(restores.len(), 2);
    let failure = restores[0]["outcome"]["failed"]["reason"].as_str().unwrap();
    assert!(failure.contains("restore target already exists"));
    assert!(failure.contains(&record_trash_entry(trashed[1]).display().to_string()));
    assert_eq!(restores[1]["outcome"], "ok");
    assert_eq!(record_reclamation_id(restores[0]), reclamation_id);
    assert_eq!(record_reclamation_id(restores[1]), reclamation_id);

    let _detached = detach_fixture_dir(&blocked_path);
    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    assert!(blocked_path.exists());
    let records = oplog_records(&state);
    let restores = restore_records(&records);
    assert_eq!(restores.len(), 3);
    assert_eq!(record_path(restores[2]), blocked_path);
    assert_eq!(record_reclamation_id(restores[2]), reclamation_id);
}

#[test]
fn undo_reports_gone_entry_without_writing_log_record() {
    let (home, state, _) = fake_pip_cache();
    let _go_build_cache = fake_go_build_cache(&home);
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    clean_all_caches(&home, &state);
    let records = oplog_records(&state);
    let trashed = ok_trash_records(&records);
    assert_eq!(trashed.len(), 2);
    let missing_path = record_path(trashed[1]);
    let missing_entry = record_trash_entry(trashed[1]);
    let restored_path = record_path(trashed[0]);
    let _detached = detach_fixture_dir(&missing_entry);

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!(
        "gone {} (trash entry missing)",
        missing_path.display()
    )));
    assert!(stdout.contains(&format!("restored {}", restored_path.display())));
    let records = oplog_records(&state);
    let restores = restore_records(&records);
    assert_eq!(restores.len(), 1);
    assert_eq!(record_path(restores[0]), restored_path);

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "Nothing to undo.\n");
    assert_eq!(restore_records(&oplog_records(&state)).len(), 1);
}

#[test]
fn undo_keeps_legacy_idless_records_as_singletons() {
    let (home, state, _) = fake_pip_cache();
    // fake_pip_cache created the platform cache dir, so restore into it.
    let first_path = crate::common::platform_cache_dir(home.path(), "legacy-one");
    let second_path = crate::common::platform_cache_dir(home.path(), "legacy-two");
    let first_entry = state.path().join("degu/trash/0001-legacy-one");
    let second_entry = state.path().join("degu/trash/0002-legacy-two");
    std::fs::create_dir_all(&first_entry).unwrap();
    std::fs::write(first_entry.join("one"), b"one").unwrap();
    std::fs::create_dir_all(&second_entry).unwrap();
    std::fs::write(second_entry.join("two"), b"two").unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&first_path, &first_entry),
            TrashStatus::Ok(None),
        ),
        trash_record(
            "2000-01-01T00:00:01Z",
            (&second_path, &second_entry),
            TrashStatus::Ok(None),
        ),
    ];
    write_oplog(&state, &records);

    assert!(run_undo(&home, &state, false).status.success());
    assert!(!first_path.exists());
    assert!(second_path.exists());
    assert!(run_undo(&home, &state, false).status.success());
    assert!(first_path.exists());
    assert!(second_path.exists());
}
