use std::path::{Path, PathBuf};

use degu_core::oplog::{OpAction, OpOutcome, OpRecord};

use super::{active_trash_indices, active_trash_state, reconciled_trash_info};

struct RecordSpec<'a> {
    action: OpAction,
    outcome: OpOutcome,
    path: &'a str,
    trash_entry: Option<&'a str>,
    reclamation_id: Option<&'a str>,
}

fn op_record_for_test(spec: RecordSpec<'_>) -> OpRecord {
    OpRecord {
        ts: "2000-01-01T00:00:00Z".to_string(),
        tool_version: "0.0.1".to_string(),
        command: "test".to_string(),
        action: spec.action,
        path: PathBuf::from(spec.path),
        bytes_allocated: 0,
        inodes: 0,
        trash_entry: spec.trash_entry.map(PathBuf::from),
        reclamation_id: spec.reclamation_id.map(str::to_string),
        expected_identity: None,
        destination_parent: None,
        outcome: spec.outcome,
    }
}

fn trash_record_for_test(path: &str, entry: &str, reclamation_id: Option<&str>) -> OpRecord {
    op_record_for_test(RecordSpec {
        action: OpAction::Trash,
        outcome: OpOutcome::Ok,
        path,
        trash_entry: Some(entry),
        reclamation_id,
    })
}

fn pending_record_for_test(path: &str, entry: &str, reclamation_id: Option<&str>) -> OpRecord {
    op_record_for_test(RecordSpec {
        action: OpAction::Trash,
        outcome: OpOutcome::Pending,
        path,
        trash_entry: Some(entry),
        reclamation_id,
    })
}

fn restore_record_with_paths(path: &Path, entry: &Path, outcome: OpOutcome) -> OpRecord {
    op_record_for_test(RecordSpec {
        action: OpAction::Restore,
        outcome,
        path: path.to_str().unwrap(),
        trash_entry: Some(entry.to_str().unwrap()),
        reclamation_id: Some("run"),
    })
}

#[test]
fn active_trash_indices_keeps_only_the_last_record_naming_an_entry() {
    let records = vec![
        pending_record_for_test("/completed", "/trash/0001-a", Some("run")),
        trash_record_for_test("/completed", "/trash/0001-a", Some("run")),
        pending_record_for_test("/reused-old", "/trash/0002-b", Some("run")),
        pending_record_for_test("/reused-new", "/trash/0002-b", Some("run")),
        pending_record_for_test("/live", "/trash/0003-c", Some("run")),
    ];

    assert_eq!(active_trash_indices(&records), vec![4, 3, 1]);
}

#[test]
fn ambiguous_pending_restore_is_exposed_to_undo_selection() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&original, "replacement").unwrap();
    std::fs::write(&entry, "staged").unwrap();
    let records = vec![
        trash_record_for_test(
            original.to_str().unwrap(),
            entry.to_str().unwrap(),
            Some("run"),
        ),
        restore_record_with_paths(&original, &entry, OpOutcome::Pending),
    ];

    let state = active_trash_state(&records);
    assert_eq!(state.indices, vec![0]);
    assert!(state.ambiguous_restores.contains(&entry));
    assert!(reconciled_trash_info(&records)[&entry].ambiguous);
}

#[test]
fn reused_entry_name_supersedes_an_older_pending_restore() {
    let dir = tempfile::tempdir().unwrap();
    let old_original = dir.path().join("old-original");
    let new_original = dir.path().join("new-original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&old_original, "previously restored").unwrap();
    std::fs::write(&entry, "new staged data").unwrap();
    let records = vec![
        trash_record_for_test(
            old_original.to_str().unwrap(),
            entry.to_str().unwrap(),
            Some("old"),
        ),
        restore_record_with_paths(&old_original, &entry, OpOutcome::Pending),
        trash_record_for_test(
            new_original.to_str().unwrap(),
            entry.to_str().unwrap(),
            Some("new"),
        ),
    ];

    let state = active_trash_state(&records);
    assert_eq!(state.indices, vec![2]);
    assert!(state.ambiguous_restores.is_empty());
}
