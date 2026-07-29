use std::path::PathBuf;

use crate::lifecycle::trash::Trash;
use degu_core::finding::{
    Finding, FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
    finalize_findings,
};
use degu_core::oplog::{OpOutcome, OpRecord};

use super::execution::{CleanFailure, StageOutcome, record_clean_failure};
use super::{CleanExecution, StageRequest, cleaned_resources, stage_finding_with_log};
use crate::lifecycle::EntryIdentity;
use crate::lifecycle::operation_log::OperationLog;

#[path = "tests/purge.rs"]
mod purge;

pub(super) fn noop_recheck(_: &Finding) -> Result<(), String> {
    Ok(())
}

pub(super) fn finding_for_test(path: PathBuf, bytes_allocated: u64, inodes: u64) -> Finding {
    let candidate = FindingCandidate {
        ecosystem: "test".to_string(),
        path,
        kind: FindingKind::PackageCache,
        bytes_apparent: 0,
        bytes_allocated,
        age_days: None,
        bytes_hardlinked: 0,
        inodes,
        skipped: 0,
        truncated: false,
        unvisited_dirs: 0,
        protected_boundaries: 0,
        protected_credential_boundaries: 0,
        recovery: Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        ownership: Ownership::Standalone,
        hazard: None,
        rationale: "test fixture".to_string(),
    };
    finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
        .pop()
        .expect("one finalized finding")
}

struct FinalAppendFailureFixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    entry: PathBuf,
    item: CleanExecution,
    appended: Vec<OpRecord>,
}

fn final_append_failure_fixture() -> FinalAppendFailureFixture {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("data"), b"cached").unwrap();
    let finding = finding_for_test(source.clone(), 4096, 2);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();
    let mut appended = Vec::new();
    let mut append = |record: &OpRecord| {
        let result = if record.outcome == OpOutcome::Pending {
            Ok(())
        } else {
            Err(std::io::Error::other("disk quota exceeded"))
        };
        appended.push(record.clone());
        result
    };
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
    let StageOutcome::Terminal(item) = outcome else {
        panic!("final stage log failure produced a purgeable stage")
    };
    FinalAppendFailureFixture {
        _dir: dir,
        source,
        entry,
        item,
        appended,
    }
}

#[test]
fn pending_final_append_failure_counts_successful_rename_as_staged() {
    let fixture = final_append_failure_fixture();
    let source = &fixture.source;
    let entry = &fixture.entry;
    let item = &fixture.item;
    let appended = &fixture.appended;

    assert!(entry.is_dir());
    assert!(!source.exists());
    assert!(
        item.failure_reason()
            .is_some_and(|reason| reason.contains("operation log append failed"))
    );
    assert!(item.final_log_append_failed());
    assert!(item.reported_as_cleaned(false));
    assert_eq!(
        cleaned_resources(std::slice::from_ref(item), false),
        (4096, 2)
    );
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert_eq!(appended.len(), 2);
    assert_eq!(appended[0].outcome, OpOutcome::Pending);
    assert_eq!(appended[1].outcome, OpOutcome::Ok);
    let pending_identity = appended[0].expected_identity.expect("pending identity");
    let final_identity = appended[1].expected_identity.expect("final identity");
    assert!(pending_identity.same_object(&final_identity));
    assert_eq!(
        final_identity,
        degu_core::oplog::ObjectIdentity::capture(entry).unwrap()
    );
    // The pre-rename parent snapshot goes into BOTH records, so a crash leaving
    // only the pending record still reconciles into an authenticated restore.
    let pending_parent = appended[0].destination_parent.expect("pending parent");
    let final_parent = appended[1].destination_parent.expect("final parent");
    assert_eq!(pending_parent, final_parent);
    let physical_parent =
        degu_core::oplog::ObjectIdentity::capture(source.parent().unwrap()).unwrap();
    assert!(pending_parent.same_object(&physical_parent));
}

#[test]
fn stage_does_not_flag_pending_append_failure_as_staged() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::create_dir_all(&source).unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();

    let mut append =
        |_: &OpRecord| -> std::io::Result<()> { Err(std::io::Error::other("disk quota exceeded")) };
    let item = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &noop_recheck,
    )
    .finish();

    assert!(source.exists());
    assert!(!entry.exists() && !dir.path().join("trash/.claims/0001").exists());
    assert!(item.failed());
    assert!(!item.final_log_append_failed());
    assert_eq!(item.trash_entry(), None);
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn stage_fails_closed_when_the_destination_parent_cannot_be_captured() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    // The cache lives in its own parent directory, which we make non-searchable
    // so opening it to capture the destination-parent identity fails.
    let parent = dir.path().join("locked");
    std::fs::create_dir_all(&parent).unwrap();
    let source = parent.join("cache");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("data"), b"cached").unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut appended = Vec::new();
    let outcome = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut |record: &OpRecord| {
            appended.push(record.clone());
            Ok(())
        },
        &noop_recheck,
    )
    .finish();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Fail closed: nothing was moved, no trash entry exists, and no record (not
    // even the pending one) was written, because the capture ran before both.
    assert!(source.exists());
    assert!(!entry.exists());
    assert!(appended.is_empty());
    assert!(item_failed_with_parent_reason(&outcome));
}

fn item_failed_with_parent_reason(item: &CleanExecution) -> bool {
    item.failure_reason()
        .is_some_and(|reason| reason.contains("could not record the restore destination parent"))
}

#[test]
fn stage_rejects_a_source_replaced_after_planning() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::write(&source, "planned").unwrap();
    let identity = EntryIdentity::capture(&source).unwrap();
    std::fs::rename(&source, dir.path().join("old-cache")).unwrap();
    std::fs::write(&source, "replacement").unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let entry = trash.reserve(&source).unwrap();
    let mut append = |_: &OpRecord| Ok(());

    let item = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &noop_recheck,
    )
    .finish();

    assert!(
        item.failure_reason()
            .is_some_and(|reason| reason.contains("identity changed"))
    );
    assert_eq!(std::fs::read_to_string(source).unwrap(), "replacement");
    assert!(!entry.exists() && !dir.path().join("trash/.claims/0001").exists());
}

#[test]
fn stage_never_overwrites_a_destination_that_appears_after_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::write(&source, "planned").unwrap();
    let identity = EntryIdentity::capture(&source).unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let entry = trash.reserve(&source).unwrap();
    std::fs::write(&entry, "existing trash data").unwrap();
    std::fs::write(dir.path().join("trash/.claims/0001"), "occupied").unwrap();
    let mut append = |_: &OpRecord| Ok(());

    let item = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &noop_recheck,
    )
    .finish();

    let reason = item.failure_reason().unwrap();
    assert!(reason.contains("reservation cleanup failed"));
    assert_eq!(std::fs::read_to_string(source).unwrap(), "planned");
    assert_eq!(
        std::fs::read_to_string(entry).unwrap(),
        "existing trash data"
    );
}

#[test]
fn staged_item_blocks_purge_when_reservation_cleanup_fails() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::write(&source, "planned").unwrap();
    let identity = EntryIdentity::capture(&source).unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let entry = trash.reserve(&source).unwrap();
    std::fs::write(dir.path().join("trash/.claims/0001"), "occupied").unwrap();
    let mut append = |_: &OpRecord| Ok(());

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
    let StageOutcome::Terminal(item) = outcome else {
        panic!("reservation cleanup failure produced a purgeable stage")
    };

    assert!(item.failed());
    assert_eq!(item.state_label(), "staged");
    assert!(item.has_trash_location());
    assert!(!item.final_log_append_failed());
    assert!(!source.exists());
    assert_eq!(std::fs::read_to_string(entry).unwrap(), "planned");
}

#[test]
fn record_failure_merges_an_operation_log_failure() {
    let dir = tempfile::tempdir().unwrap();
    let finding = finding_for_test(dir.path().join("cache"), 0, 0);
    let log = OperationLog::at(dir.path().to_path_buf());
    let item = record_clean_failure(CleanFailure {
        log: &log,
        finding: &finding,
        reason: "trash root unavailable".to_string(),
        reclamation_id: Some("run".to_string()),
    });

    let reason = item.failure_reason().expect("stage failure");
    assert!(reason.contains("trash root unavailable"));
    assert!(reason.contains("operation log append failed while recording stage failure"));
}

#[cfg(unix)]
#[test]
fn a_protected_alias_created_after_the_pending_append_stops_the_stage() {
    let home = tempfile::tempdir().unwrap();
    let trash = Trash::new(home.path().join("trash"));
    let source = home.path().join("cache");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("data"), b"cached").unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();
    let alias = home.path().join(".claude");

    let mut appended = Vec::new();
    let mut append = |record: &OpRecord| {
        if record.outcome == OpOutcome::Pending {
            std::os::unix::fs::symlink(&source, &alias).unwrap();
        }
        appended.push(record.clone());
        Ok(())
    };
    let recheck = |finding: &Finding| -> Result<(), String> {
        let guard =
            degu_core::safety::Guard::with_defaults(home.path()).map_err(|e| e.to_string())?;
        guard.check(finding.path()).map_err(|e| e.to_string())
    };
    let item = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &recheck,
    )
    .finish();

    assert!(source.join("data").exists(), "source must not be moved");
    assert!(!entry.exists(), "reservation must be released");
    assert!(
        item.failure_reason()
            .is_some_and(|reason| reason.contains("protection re-check failed")),
        "reason: {:?}",
        item.failure_reason()
    );
    assert!(
        appended
            .iter()
            .all(|record| record.outcome != OpOutcome::Ok)
    );
    assert_eq!(appended[0].outcome, OpOutcome::Pending);
    assert_eq!(appended.len(), 2);
}

// Order proof for the staging boundary: with the mount traversal failing, the
// recheck must never run -- together with the alias test above this pins the
// mount -> recheck -> rename sequence, so the traversal cannot reopen a window
// after the protection re-check.
#[cfg(unix)]
#[test]
fn the_protection_recheck_runs_after_the_mount_traversal() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    let sub = source.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let finding = finding_for_test(source.clone(), 0, 0);
    let identity = EntryIdentity::capture(&source).unwrap();
    let entry = trash.reserve(&source).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&sub).is_ok() {
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        return; // root ignores directory modes; the traversal cannot be made to fail
    }

    let mut appended = Vec::new();
    let mut append = |record: &OpRecord| {
        appended.push(record.clone());
        Ok(())
    };
    let recheck_calls = std::cell::Cell::new(0u32);
    let recheck = |_: &Finding| -> Result<(), String> {
        recheck_calls.set(recheck_calls.get() + 1);
        Ok(())
    };
    let item = stage_finding_with_log(
        StageRequest {
            trash: &trash,
            finding: &finding,
            identity: &identity,
            entry: entry.clone(),
            reclamation_id: "run",
        },
        &mut append,
        &recheck,
    )
    .finish();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(
        recheck_calls.get(),
        0,
        "recheck must not run before the mount traversal completes"
    );
    assert!(source.exists());
    assert!(
        item.failure_reason()
            .is_some_and(|reason| reason.contains("mount safety validation failed"))
    );
    assert!(
        appended
            .iter()
            .all(|record| record.outcome != OpOutcome::Ok)
    );
}
