use super::fixtures::both_missing_pending_fixture;
use super::*;

#[test]
fn undo_restores_pending_staged_entry() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let original = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(original.parent().unwrap()).unwrap();
    let trash_entry = state.path().join("degu/trash/0001-pip");
    std::fs::create_dir_all(&trash_entry).unwrap();
    std::fs::write(trash_entry.join("wheel.whl"), b"cached wheel").unwrap();
    write_oplog(
        &state,
        &[trash_record(
            "2000-01-01T00:00:00Z",
            (&original, &trash_entry),
            TrashStatus::Pending(Some("interrupted-run")),
        )],
    );

    let out = run_undo(&home, &state, false);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("restored {}", original.display())));
    assert!(stdout.contains("Restored 1 of 1 from reclamation interrupted-run."));
    assert!(!trash_entry.exists());
    assert_eq!(
        std::fs::read_to_string(original.join("wheel.whl")).unwrap(),
        "cached wheel"
    );
    let records = oplog_records(&state);
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["action"], "restore");
    assert_eq!(records[1]["outcome"], "pending");
    assert_eq!(records[1]["reclamation_id"], "interrupted-run");
    assert_eq!(records[2]["action"], "restore");
    assert_eq!(records[2]["outcome"], "ok");
    assert_eq!(records[2]["reclamation_id"], "interrupted-run");

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "Nothing to undo.\n");
}

#[test]
fn undo_reports_both_exist_pending_as_ambiguous() {
    let (home, state, cache) = fake_pip_cache();
    let trash_entry = state.path().join("degu/trash/0001-pip-cache");
    std::fs::create_dir_all(&trash_entry).unwrap();
    write_oplog(
        &state,
        &[trash_record(
            "2000-01-01T00:00:00Z",
            (&cache, &trash_entry),
            TrashStatus::Pending(None),
        )],
    );

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("ambiguous {}", cache.display())));
    assert!(stdout.contains("Restored 0 of 1 from reclamation -."));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("ambiguous"), "stderr: {stderr}");
    assert!(trash_entry.exists());
    assert!(cache.exists());
    assert_eq!(oplog_records(&state).len(), 1);
}

#[test]
fn undo_treats_pending_with_present_original_and_missing_entry_as_not_moved() {
    let (home, state, cache) = fake_pip_cache();
    let trash_entry = state.path().join("degu/trash/0001-pip-cache");
    write_oplog(
        &state,
        &[trash_record(
            "2000-01-01T00:00:00Z",
            (&cache, &trash_entry),
            TrashStatus::Pending(Some("run")),
        )],
    );

    let out = run_undo(&home, &state, false);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "Nothing to undo.\n");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("ambiguous"), "stderr: {stderr}");
    assert!(cache.exists());
    assert_eq!(oplog_records(&state).len(), 1);
}

#[test]
fn undo_reports_both_missing_pending_as_ambiguous() {
    let (home, state) = both_missing_pending_fixture();
    let original = crate::common::platform_cache_dir(home.path(), "pip");
    let trash_entry = state.path().join("degu/trash/0001-pip");

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("ambiguous {}", original.display())));
    assert!(stdout.contains("Restored 0 of 1 from reclamation interrupted-run."));

    let out = run_undo(&home, &state, true);
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ambiguous = report["ambiguous"].as_array().unwrap();
    assert_eq!(ambiguous.len(), 1);
    let mut keys = ambiguous[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ["path", "reclamation_id", "trash_entry"]);
    assert_eq!(ambiguous[0]["path"], original.to_string_lossy().as_ref());
    assert_eq!(
        ambiguous[0]["trash_entry"],
        trash_entry.to_string_lossy().as_ref()
    );
    assert_eq!(ambiguous[0]["reclamation_id"], "interrupted-run");
    assert!(!original.exists());
    assert!(!trash_entry.exists());
    assert_eq!(oplog_records(&state).len(), 1);
}
