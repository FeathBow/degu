use std::path::{Path, PathBuf};

use degu_core::oplog::{OpAction, OpOutcome, OpRecord};

use super::{
    active_trash_indices, active_trash_state, reconcile_pending_record, reconciled_trash_info,
};
use crate::lifecycle::EntryIdentity;

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

fn with_expected_identity(mut record: OpRecord, path: &Path) -> OpRecord {
    record.expected_identity = Some(EntryIdentity::capture(path).unwrap().oplog_identity());
    record
}

fn restore_record_for_test(entry: &str, outcome: OpOutcome) -> OpRecord {
    op_record_for_test(RecordSpec {
        action: OpAction::Restore,
        outcome,
        path: "/original",
        trash_entry: Some(entry),
        reclamation_id: Some("run"),
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
fn reconciled_trash_info_reads_pendings_and_prefers_ok_records() {
    let dir = tempfile::tempdir().unwrap();
    let staged_entry = dir.path().join("trash/0001-staged");
    let ambiguous_entry = dir.path().join("trash/0002-ambiguous");
    let ambiguous_original = dir.path().join("recreated");
    std::fs::create_dir_all(&staged_entry).unwrap();
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    std::fs::write(&ambiguous_original, b"new occupant").unwrap();
    let records = reconciliation_records(ReconciliationPaths {
        dir: &dir,
        staged_entry: &staged_entry,
        ambiguous_entry: &ambiguous_entry,
        ambiguous_original: &ambiguous_original,
    });

    let info = reconciled_trash_info(&records);
    let staged = info.get(&staged_entry).unwrap();
    assert_eq!(staged.original, dir.path().join("gone"));
    assert!(!staged.ambiguous);
    assert!(staged.staged_at.is_some());
    let ambiguous = info.get(&ambiguous_entry).unwrap();
    assert_eq!(ambiguous.original, ambiguous_original);
    assert!(ambiguous.ambiguous);
    assert!(!info.contains_key(Path::new("/trash/0003-both")));
}

struct ReconciliationPaths<'a> {
    dir: &'a tempfile::TempDir,
    staged_entry: &'a Path,
    ambiguous_entry: &'a Path,
    ambiguous_original: &'a Path,
}

fn reconciliation_records(paths: ReconciliationPaths<'_>) -> Vec<OpRecord> {
    vec![
        with_expected_identity(
            pending_record_for_test(
                paths.dir.path().join("gone").to_str().unwrap(),
                paths.staged_entry.to_str().unwrap(),
                Some("run"),
            ),
            paths.staged_entry,
        ),
        pending_record_for_test(
            paths.ambiguous_original.to_str().unwrap(),
            paths.ambiguous_entry.to_str().unwrap(),
            Some("run"),
        ),
        pending_record_for_test("/pending-original", "/trash/0003-both", Some("run")),
        trash_record_for_test("/ok-original", "/trash/0003-both", Some("run")),
    ]
}

#[test]
fn reconciled_trash_info_prefers_new_pending_after_settled_ok() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("trash/0001-cache");
    let new_original = dir.path().join("new-original");
    std::fs::create_dir_all(&entry).unwrap();
    let entry_text = entry.to_str().unwrap();
    let records = vec![
        trash_record_for_test("/old-original", entry_text, Some("old")),
        restore_record_for_test(entry_text, OpOutcome::Ok),
        with_expected_identity(
            pending_record_for_test(new_original.to_str().unwrap(), entry_text, Some("new")),
            &entry,
        ),
    ];

    let info = reconciled_trash_info(&records);

    assert_eq!(info[&entry].original, new_original);
    assert!(!info[&entry].ambiguous);
}

#[test]
fn completed_pending_trash_requires_the_recorded_destination_identity() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("gone");
    let entry = dir.path().join("trash/0001-cache");
    let other = dir.path().join("other");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "staged").unwrap();
    std::fs::write(&other, "different object").unwrap();
    let record = pending_record_for_test(
        original.to_str().unwrap(),
        entry.to_str().unwrap(),
        Some("run"),
    );

    assert_eq!(
        reconcile_pending_record(&record, &entry),
        degu_core::oplog::PendingState::AmbiguousIdentity
    );
    let mismatched = with_expected_identity(record.clone(), &other);
    assert_eq!(
        reconcile_pending_record(&mismatched, &entry),
        degu_core::oplog::PendingState::AmbiguousIdentity
    );
    let matched = with_expected_identity(record, &entry);
    assert_eq!(
        reconcile_pending_record(&matched, &entry),
        degu_core::oplog::PendingState::Moved
    );
}

#[test]
fn completed_pending_restore_is_not_left_active_after_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::write(&original, "restored").unwrap();
    let records = vec![
        trash_record_for_test(
            original.to_str().unwrap(),
            entry.to_str().unwrap(),
            Some("run"),
        ),
        with_expected_identity(
            restore_record_with_paths(&original, &entry, OpOutcome::Pending),
            &original,
        ),
    ];

    assert!(active_trash_indices(&records).is_empty());
}

#[test]
fn pending_restore_before_the_move_keeps_the_trash_entry_active() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "staged").unwrap();
    let records = vec![
        trash_record_for_test(
            original.to_str().unwrap(),
            entry.to_str().unwrap(),
            Some("run"),
        ),
        with_expected_identity(
            restore_record_with_paths(&original, &entry, OpOutcome::Pending),
            &entry,
        ),
    ];

    assert_eq!(active_trash_indices(&records), vec![0]);
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
