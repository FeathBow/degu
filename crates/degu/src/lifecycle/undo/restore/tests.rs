use std::path::PathBuf;

use degu_core::oplog::{ObjectIdentity, OpAction, OpOutcome, OpRecord};

use super::failure::RestoreFailure;
use super::{restore_outcome, restore_selection_with_append};
use crate::lifecycle::identity::RenameFailure;
use crate::lifecycle::reconcile::active_trash_indices;
use crate::lifecycle::undo::selection::UndoSelection;

struct RestoreFixture {
    _dir: tempfile::TempDir,
    original: PathBuf,
    entry: PathBuf,
    selection: UndoSelection,
}

fn restore_fixture() -> RestoreFixture {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let entry = dir.path().join("trash/0001-cache");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "planned").unwrap();
    let target = trash_record(original.clone(), entry.clone());
    RestoreFixture {
        _dir: dir,
        original,
        entry,
        selection: UndoSelection {
            targets: vec![target],
            ambiguous: Vec::new(),
            reclamation_id: Some("run".to_string()),
        },
    }
}

fn trash_record(path: PathBuf, entry: PathBuf) -> OpRecord {
    let destination_parent = path
        .parent()
        .map(ObjectIdentity::capture)
        .transpose()
        .unwrap();
    let expected_identity = ObjectIdentity::capture(&entry).ok();
    OpRecord {
        ts: "2000-01-01T00:00:00Z".to_string(),
        tool_version: "0.0.1".to_string(),
        command: "clean".to_string(),
        action: OpAction::Trash,
        path,
        bytes_allocated: 7,
        inodes: 1,
        trash_entry: Some(entry),
        reclamation_id: Some("run".to_string()),
        expected_identity,
        destination_parent,
        outcome: OpOutcome::Ok,
    }
}

#[test]
fn restore_writes_pending_before_the_move_and_then_final() {
    let fixture = restore_fixture();
    let mut records = Vec::new();
    let report = restore_selection_with_append(fixture.selection, &mut |record| {
        records.push(record.clone());
        Ok(())
    })
    .unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].outcome, OpOutcome::Pending);
    assert!(records[0].expected_identity.is_some());
    assert_eq!(records[1].outcome, OpOutcome::Ok);
    assert!(records[1].expected_identity.is_none());
    assert_eq!(report.restored.len(), 1);
    assert!(report.failed.is_empty());
    assert_eq!(
        std::fs::read_to_string(&fixture.original).unwrap(),
        "planned"
    );
    assert!(!fixture.entry.exists());
}

#[test]
fn restore_does_not_overwrite_an_original_created_after_pending() {
    let fixture = restore_fixture();
    let original = fixture.original.clone();
    let mut records = Vec::new();
    let report = restore_selection_with_append(fixture.selection, &mut |record| {
        records.push(record.clone());
        if record.outcome == OpOutcome::Pending {
            std::fs::write(&original, "replacement").unwrap();
        }
        Ok(())
    })
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&fixture.original).unwrap(),
        "replacement"
    );
    assert_eq!(std::fs::read_to_string(&fixture.entry).unwrap(), "planned");
    assert!(report.restored.is_empty());
    assert_eq!(report.failed.len(), 1);
    // The Stable parent check tolerates the parent's ctime bump, so the
    // NOREPLACE rename is what refuses the pre-existing original; nothing moved
    // and the trash entry stays intact.
    assert!(
        report.failed[0]
            .reason
            .contains("inspect the trash source at")
    );
    assert!(
        report.failed[0]
            .reason
            .contains(&fixture.entry.display().to_string())
    );
    let OpOutcome::Failed { reason } = &records[1].outcome else {
        panic!("final restore record should fail");
    };
    assert!(reason.contains(&fixture.entry.display().to_string()));
}

#[test]
fn restore_rejects_an_entry_replaced_after_its_snapshot() {
    let fixture = restore_fixture();
    let entry = fixture.entry.clone();
    let preserved = fixture._dir.path().join("planned-moved-concurrently");
    let report = restore_selection_with_append(fixture.selection, &mut |record| {
        if record.outcome == OpOutcome::Pending {
            std::fs::rename(&entry, &preserved).unwrap();
            std::fs::write(&entry, "replacement").unwrap();
        }
        Ok(())
    })
    .unwrap();

    assert!(!fixture.original.exists());
    assert_eq!(
        std::fs::read_to_string(&fixture.entry).unwrap(),
        "replacement"
    );
    assert_eq!(std::fs::read_to_string(preserved).unwrap(), "planned");
    assert!(report.restored.is_empty());
    assert_eq!(report.failed.len(), 1);
}

#[test]
fn pending_append_failure_makes_no_filesystem_change() {
    let fixture = restore_fixture();
    let report = restore_selection_with_append(fixture.selection, &mut |_| {
        Err(std::io::Error::other("log full"))
    })
    .unwrap();

    assert!(!fixture.original.exists());
    assert_eq!(std::fs::read_to_string(&fixture.entry).unwrap(), "planned");
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.log_failures.len(), 1);
    assert!(!report.log_failures[0].restored);
}

#[test]
fn final_append_failure_reports_the_completed_restore() {
    let fixture = restore_fixture();
    let mut calls = 0;
    let mut persisted = Vec::new();
    let report = restore_selection_with_append(fixture.selection, &mut |record| {
        calls += 1;
        if calls == 1 {
            persisted.push(record.clone());
            Ok(())
        } else {
            Err(std::io::Error::other("log full"))
        }
    })
    .unwrap();

    assert_eq!(calls, 2);
    assert_eq!(
        std::fs::read_to_string(&fixture.original).unwrap(),
        "planned"
    );
    assert!(!fixture.entry.exists());
    assert_eq!(report.restored.len(), 1);
    assert!(report.failed.is_empty());
    assert_eq!(report.log_failures.len(), 1);
    assert!(report.log_failures[0].restored);
    assert!(report.has_failures());
    let records = vec![
        trash_record(fixture.original.clone(), fixture.entry.clone()),
        persisted.pop().unwrap(),
    ];
    assert!(active_trash_indices(&records).is_empty());
}

#[test]
fn restore_failure_keeps_the_location_reported_by_rename() {
    let trash_entry = PathBuf::from("/trash/0001-cache");
    let original = PathBuf::from("/cache");
    let in_trash = RestoreFailure::from_rename(
        &trash_entry,
        RenameFailure::Source(std::io::Error::other("move failed")),
    );
    let at_original = RestoreFailure::from_rename(
        &trash_entry,
        RenameFailure::UnverifiedDestination {
            destination: original.clone(),
            error: std::io::Error::other("rollback failed"),
        },
    );

    assert_eq!(in_trash.path(), trash_entry);
    assert!(in_trash.reason().contains("trash source"));
    assert_eq!(at_original.path(), original);
    assert!(at_original.reason().contains("could not be verified"));
    let outcome = restore_outcome(&Err(at_original));
    let OpOutcome::Failed { reason } = outcome else {
        panic!("unverified destination should fail");
    };
    assert!(reason.contains("/cache"));
}

#[test]
fn restore_rejects_a_replacement_planted_before_identity_capture() {
    let fixture = restore_fixture();
    let preserved = fixture._dir.path().join("displaced");
    std::fs::rename(&fixture.entry, &preserved).unwrap();
    std::fs::write(&fixture.entry, "replacement").unwrap();

    let mut records = Vec::new();
    let report = restore_selection_with_append(fixture.selection, &mut |record| {
        records.push(record.clone());
        Ok(())
    })
    .unwrap();

    assert!(!fixture.original.exists());
    assert_eq!(
        std::fs::read_to_string(&fixture.entry).unwrap(),
        "replacement"
    );
    assert_eq!(std::fs::read_to_string(preserved).unwrap(), "planned");
    assert!(report.restored.is_empty());
    assert!(report.failed.is_empty());
    assert_eq!(report.ambiguous.len(), 1, "fail closed as ambiguous");
    assert!(
        records.is_empty(),
        "not even a pending record may be written"
    );
}
