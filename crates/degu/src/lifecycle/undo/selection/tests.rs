use std::path::PathBuf;

use degu_core::oplog::{OpAction, OpOutcome, OpRecord};

use super::{select_actionable_undo_group, select_undo_group};
use crate::lifecycle::expiry::{TrashEntryExpiry, trash_entry_expiry};
use crate::lifecycle::reconcile::reconciled_trash_info;

fn trash_record_for_test(path: &str, entry: &str, reclamation_id: Option<&str>) -> OpRecord {
    op_record_for_test(TestRecord {
        action: OpAction::Trash,
        outcome: OpOutcome::Ok,
        path,
        trash_entry: Some(entry),
        reclamation_id,
    })
}

fn pending_record_for_test(path: &str, entry: &str, reclamation_id: Option<&str>) -> OpRecord {
    op_record_for_test(TestRecord {
        action: OpAction::Trash,
        outcome: OpOutcome::Pending,
        path,
        trash_entry: Some(entry),
        reclamation_id,
    })
}

fn failed_record_for_test(path: &str, entry: &str, reclamation_id: Option<&str>) -> OpRecord {
    op_record_for_test(TestRecord {
        action: OpAction::Trash,
        outcome: OpOutcome::Failed {
            reason: "verification failed".to_owned(),
        },
        path,
        trash_entry: Some(entry),
        reclamation_id,
    })
}

struct TestRecord<'a> {
    action: OpAction,
    outcome: OpOutcome,
    path: &'a str,
    trash_entry: Option<&'a str>,
    reclamation_id: Option<&'a str>,
}

fn op_record_for_test(record: TestRecord<'_>) -> OpRecord {
    OpRecord {
        ts: "2000-01-01T00:00:00Z".to_string(),
        tool_version: "0.0.1".to_string(),
        command: "test".to_string(),
        action: record.action,
        path: PathBuf::from(record.path),
        bytes_allocated: 0,
        inodes: 0,
        trash_entry: record.trash_entry.map(PathBuf::from),
        reclamation_id: record.reclamation_id.map(str::to_string),
        expected_identity: None,
        destination_parent: None,
        outcome: record.outcome,
    }
}

fn selected_paths(records: &[OpRecord]) -> Vec<PathBuf> {
    select_undo_group(records)
        .unwrap_or_default()
        .into_iter()
        .map(|record| record.path)
        .collect()
}

#[test]
fn select_undo_group_legacy_singletons_interleave_with_id_groups() {
    let records = vec![
        trash_record_for_test("/run-a", "/trash/run-a", Some("run")),
        trash_record_for_test("/legacy-a", "/trash/legacy-a", None),
        trash_record_for_test("/run-b", "/trash/run-b", Some("run")),
        trash_record_for_test("/legacy-b", "/trash/legacy-b", None),
    ];

    assert_eq!(selected_paths(&records), vec![PathBuf::from("/legacy-b")]);
    assert_eq!(
        selected_paths(&records[..records.len() - 1]),
        vec![PathBuf::from("/run-b"), PathBuf::from("/run-a")]
    );
}

#[test]
fn ambiguous_pending_restore_blocks_older_undo_groups() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&original, "replacement").unwrap();
    std::fs::write(&entry, "staged").unwrap();
    let original = original.to_str().unwrap();
    let entry = entry.to_str().unwrap();
    let records = vec![
        trash_record_for_test("/older", "/trash/older", Some("older")),
        trash_record_for_test(original, entry, Some("latest")),
        op_record_for_test(TestRecord {
            action: OpAction::Restore,
            outcome: OpOutcome::Pending,
            path: original,
            trash_entry: Some(entry),
            reclamation_id: Some("latest"),
        }),
    ];

    let selection = select_actionable_undo_group(&records).unwrap();
    assert!(selection.targets.is_empty());
    assert_eq!(selection.ambiguous.len(), 1);
    assert_eq!(selection.reclamation_id.as_deref(), Some("latest"));
}

#[test]
fn failed_trash_with_an_entry_blocks_older_undo_as_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(&entry).unwrap();
    let entry = entry.to_str().unwrap();
    let records = vec![
        trash_record_for_test("/older", "/trash/older", Some("older")),
        pending_record_for_test("/latest", entry, Some("latest")),
        failed_record_for_test("/latest", entry, Some("latest")),
    ];

    let selection = select_actionable_undo_group(&records).unwrap();
    let recorded = reconciled_trash_info(&records);

    assert!(selection.targets.is_empty());
    assert_eq!(selection.ambiguous.len(), 1);
    assert_eq!(selection.reclamation_id.as_deref(), Some("latest"));
    assert_eq!(
        recorded[std::path::Path::new(entry)].original,
        PathBuf::from("/latest")
    );
    assert!(recorded[std::path::Path::new(entry)].ambiguous);
}

#[test]
fn replaced_ok_entry_is_ambiguous_for_undo_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "staged").unwrap();
    let mut record = trash_record_for_test("/original", entry.to_str().unwrap(), Some("run"));
    record.expected_identity = Some(degu_core::oplog::ObjectIdentity::capture(&entry).unwrap());
    std::fs::rename(&entry, dir.path().join("old-entry")).unwrap();
    std::fs::write(&entry, "replacement").unwrap();
    let records = [record];

    let selection = select_actionable_undo_group(&records).unwrap();
    let recorded = reconciled_trash_info(&records);

    assert!(selection.targets.is_empty());
    assert_eq!(selection.ambiguous.len(), 1);
    assert!(recorded[&entry].ambiguous);
    assert_eq!(
        trash_entry_expiry(&entry, &recorded),
        TrashEntryExpiry::Never
    );
}

#[test]
fn missing_newer_ok_entry_allows_the_older_group() {
    let dir = tempfile::tempdir().unwrap();
    let older_entry = dir.path().join("trash/0001-older");
    let newer_entry = dir.path().join("trash/0002-newer");
    std::fs::create_dir_all(older_entry.parent().unwrap()).unwrap();
    std::fs::write(&older_entry, "older").unwrap();
    std::fs::write(&newer_entry, "newer").unwrap();
    let mut older = trash_record_for_test("/older", older_entry.to_str().unwrap(), Some("older"));
    let mut newer = trash_record_for_test("/newer", newer_entry.to_str().unwrap(), Some("newer"));
    older.expected_identity =
        Some(degu_core::oplog::ObjectIdentity::capture(&older_entry).unwrap());
    newer.expected_identity =
        Some(degu_core::oplog::ObjectIdentity::capture(&newer_entry).unwrap());
    std::fs::rename(&newer_entry, dir.path().join("removed-newer")).unwrap();

    let selection = select_actionable_undo_group(&[older, newer]).unwrap();

    assert_eq!(selection.reclamation_id.as_deref(), Some("older"));
    assert_eq!(selection.targets.len(), 1);
    assert_eq!(selection.targets[0].path, PathBuf::from("/older"));
}
