use super::fixtures::{
    mixed_pending_fixture, multiple_ambiguous_fixture, newest_ambiguous_fixture,
};
use super::*;

#[test]
fn undo_reports_only_latest_ambiguous_group() {
    let (home, state) = multiple_ambiguous_fixture();
    let human = run_undo(&home, &state, false);
    assert!(!human.status.success());
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(stdout.contains("new-ambiguous"));
    assert!(!stdout.contains("old-ambiguous"));

    let json = run_undo(&home, &state, true);
    assert!(!json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["reclamation_id"], "new-run");
    let ambiguous = report["ambiguous"].as_array().unwrap();
    assert_eq!(ambiguous.len(), 1);
    assert_eq!(ambiguous[0]["reclamation_id"], "new-run");
}

#[test]
fn undo_newer_ambiguity_does_not_restore_older_group() {
    let (home, state) = newest_ambiguous_fixture();
    let old_original = home.path().join(".cache/old");
    let old_entry = state.path().join("degu/trash/0001-old");
    let ambiguous_original = home.path().join(".cache/ambiguous");
    let ambiguous_entry = state.path().join("degu/trash/0002-ambiguous");

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("ambiguous {}", ambiguous_original.display())));
    assert!(stdout.contains("Restored 0 of 1 from reclamation new-run."));
    assert!(!stdout.contains(&format!("restored {}", old_original.display())));
    assert!(!old_original.exists());
    assert!(old_entry.exists());
    assert!(ambiguous_entry.exists());
    assert!(ambiguous_original.exists());
    assert!(!home.path().join(".cache/superseded").exists());
    assert!(restore_records(&oplog_records(&state)).is_empty());
}

#[test]
fn undo_json_stops_at_newer_ambiguity() {
    let (home, state) = newest_ambiguous_fixture();
    let old_original = home.path().join(".cache/old");
    let old_entry = state.path().join("degu/trash/0001-old");
    let ambiguous_original = home.path().join(".cache/ambiguous");

    let out = run_undo(&home, &state, true);
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["reclamation_id"], "new-run");
    assert!(report["restored"].as_array().unwrap().is_empty());
    assert_eq!(report["ambiguous"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["ambiguous"][0]["path"],
        ambiguous_original.to_string_lossy().as_ref()
    );
    assert_eq!(report["ambiguous"][0]["reclamation_id"], "new-run");
    assert!(!old_original.exists());
    assert!(old_entry.exists());
    assert!(!home.path().join(".cache/superseded").exists());
    assert!(restore_records(&oplog_records(&state)).is_empty());
}

#[test]
fn undo_does_not_restore_legacy_entry_past_newer_ambiguity() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let legacy_original = home.path().join(".cache/legacy");
    std::fs::create_dir_all(legacy_original.parent().unwrap()).unwrap();
    let legacy_entry = state.path().join("degu/trash/0001-legacy");
    std::fs::create_dir_all(&legacy_entry).unwrap();
    let ambiguous_original = home.path().join(".cache/ambiguous");
    std::fs::create_dir_all(&ambiguous_original).unwrap();
    let ambiguous_entry = state.path().join("degu/trash/0002-ambiguous");
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&legacy_original, &legacy_entry),
            TrashStatus::Ok(None),
        ),
        trash_record(
            "2000-01-02T00:00:00Z",
            (&ambiguous_original, &ambiguous_entry),
            TrashStatus::Pending(Some("new-run")),
        ),
    ];
    write_oplog(&state, &records);

    let out = run_undo(&home, &state, true);
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["reclamation_id"], "new-run");
    assert!(report["restored"].as_array().unwrap().is_empty());
    assert_eq!(report["ambiguous"][0]["reclamation_id"], "new-run");
    assert!(!legacy_original.exists());
    assert!(legacy_entry.exists());
    assert!(restore_records(&oplog_records(&state)).is_empty());
}

#[test]
fn undo_summary_counts_ambiguous_pending_entries() {
    let (home, state) = mixed_pending_fixture();
    let staged_original = home.path().join(".cache/staged");
    let ambiguous_original = home.path().join(".cache/ambiguous");
    let ambiguous_entry = state.path().join("degu/trash/0002-ambiguous");

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("restored {}", staged_original.display())));
    assert!(stdout.contains(&format!("ambiguous {}", ambiguous_original.display())));
    assert!(stdout.contains("Restored 1 of 2 from reclamation run."));
    assert!(staged_original.exists());
    assert!(ambiguous_original.exists());
    assert!(ambiguous_entry.exists());
}

#[test]
fn undo_ignores_pending_superseded_by_reused_sequence_name() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let dead_original = home.path().join(".cache/dead");
    let live_original = home.path().join(".cache/live");
    std::fs::create_dir_all(home.path().join(".cache")).unwrap();
    let entry = state.path().join("degu/trash/0001-cache");
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::write(entry.join("data"), b"live data").unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&dead_original, &entry),
            TrashStatus::Pending(Some("one")),
        ),
        trash_record(
            "2000-01-02T00:00:00Z",
            (&live_original, &entry),
            TrashStatus::Ok(Some("two")),
        ),
    ];
    write_oplog(&state, &records);

    let out = run_undo(&home, &state, false);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("restored {}", live_original.display())));
    assert!(stdout.contains("Restored 1 of 1"));
    assert!(live_original.join("data").exists());
    assert!(!dead_original.exists());
    assert!(!entry.exists());
}

#[test]
fn undo_double_pending_same_original_restores_one_and_fails_the_other() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let original = home.path().join(".cache/cache");
    std::fs::create_dir_all(original.parent().unwrap()).unwrap();
    let first_entry = state.path().join("degu/trash/0001-cache");
    let second_entry = state.path().join("degu/trash/0002-cache");
    std::fs::create_dir_all(state.path().join("degu/trash")).unwrap();
    std::fs::write(&first_entry, b"first").unwrap();
    std::fs::write(&second_entry, b"second").unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&original, &first_entry),
            TrashStatus::Pending(Some("run")),
        ),
        trash_record(
            "2000-01-01T00:00:01Z",
            (&original, &second_entry),
            TrashStatus::Pending(Some("run")),
        ),
    ];
    write_oplog(&state, &records);

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("restored {}", original.display())));
    assert!(stdout.contains(&format!("failed {}:", original.display())));
    assert_eq!(std::fs::read_to_string(&original).unwrap(), "second");
    assert!(first_entry.exists());
    assert!(!second_entry.exists());
    let records = oplog_records(&state);
    let restores = restore_records(&records);
    assert_eq!(restores.len(), 2);
    assert_eq!(restores[0]["outcome"], "ok");
    let failure = restores[1]["outcome"]["failed"]["reason"].as_str().unwrap();
    assert!(failure.contains("restore target already exists"));
    assert!(failure.contains(&first_entry.display().to_string()));
}
