use super::super::execution::{CommittedStage, StageOutcome, StageRequest, stage_finding_with_log};
use super::super::purge::{apply_report, execute};
use super::{finding_for_test, noop_recheck};
use crate::lifecycle::trash::Trash;
use crate::lifecycle::{EntryIdentity, PurgeReport};
use degu_core::ecosystem::DetectCtx;
use std::path::PathBuf;

struct CommittedFixture {
    _dir: tempfile::TempDir,
    entry: PathBuf,
    staged: CommittedStage,
}

fn committed_fixture(bytes_allocated: u64, inodes: u64) -> CommittedFixture {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::write(&source, "cached").unwrap();
    let finding = finding_for_test(source.clone(), bytes_allocated, inodes);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();
    let mut append = |_: &degu_core::oplog::OpRecord| Ok(());
    let outcome = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &noop_recheck,
    );
    let StageOutcome::Committed(staged) = outcome else {
        panic!("fixture did not complete staging")
    };
    CommittedFixture {
        _dir: dir,
        entry,
        staged,
    }
}

#[test]
fn completed_purge_remains_complete_when_final_logging_fails() {
    let CommittedFixture {
        _dir,
        entry,
        staged,
    } = committed_fixture(4096, 1);
    let report = PurgeReport {
        purged: vec![entry.clone()],
        failed: vec![
            (
                entry.clone(),
                "operation log append failed: log full".to_string(),
            ),
            (entry, "audit mirror unavailable".to_string()),
        ],
    };

    let item = apply_report(staged, report);

    assert!(item.purged());
    let reason = item.failure_reason().expect("final log failure");
    assert!(reason.contains("operation log append failed"));
    assert!(reason.contains("audit mirror unavailable"));
    assert!(item.reported_as_cleaned(true));
    assert!(item.final_log_append_failed());
}

#[test]
fn purge_failure_retains_the_actual_claim_location() {
    let CommittedFixture {
        _dir,
        entry,
        staged,
    } = committed_fixture(0, 0);
    let claim = entry.parent().unwrap().join(".claims/1");
    let report = PurgeReport {
        purged: Vec::new(),
        failed: vec![(claim.clone(), "claim remains after failure".to_string())],
    };

    let item = apply_report(staged, report);

    assert!(item.has_trash_location());
    assert_eq!(item.trash_entry(), Some(claim.as_path()));
    let reason = item.failure_reason().expect("purge failure");
    assert!(reason.contains(&claim.display().to_string()));
    assert!(reason.contains("claim remains after failure"));
}

#[test]
fn identity_capture_failure_retains_the_staged_entry() {
    let CommittedFixture {
        _dir,
        entry,
        staged,
    } = committed_fixture(4096, 1);
    let moved = entry.with_extension("moved");
    std::fs::rename(&entry, &moved).unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let item = execute(&ctx, StageOutcome::Committed(staged));

    assert_eq!(item.state_label(), "purge_failed");
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert!(!item.reported_as_cleaned(true));
    assert!(moved.exists());
}

#[test]
fn a_replacement_at_the_staged_path_is_not_purged() {
    let CommittedFixture {
        _dir,
        entry,
        staged,
    } = committed_fixture(4096, 1);
    let displaced = entry.with_extension("displaced");
    std::fs::rename(&entry, &displaced).unwrap();
    std::fs::write(&entry, "replacement planted after staging").unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    let item = execute(&ctx, StageOutcome::Committed(staged));

    assert_eq!(item.state_label(), "purge_failed");
    assert!(!item.reported_as_cleaned(true));
    // The staged identity no longer matches the path, so neither the planted
    // replacement nor the displaced original may be deleted.
    assert_eq!(
        std::fs::read(&entry).unwrap(),
        b"replacement planted after staging"
    );
    assert!(displaced.exists());
}
