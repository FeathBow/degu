use super::claim::{ClaimFailure, ClaimedTrashEntry, LocatedFailure};
use super::plan::PlannedTrashEntry;
use super::transaction::PurgeOperation;
use super::transaction::{failed_outcome, purge_claimed, report_claim_failure};
use crate::lifecycle::identity::RenameFailure;
use degu_core::oplog::OpOutcome;

fn claimed_fixture() -> (tempfile::TempDir, ClaimedTrashEntry, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let trash_root = dir.path().join("trash");
    std::fs::create_dir(&trash_root).unwrap();
    let entry = trash_root.join("0001-cache");
    std::fs::write(&entry, "cache").unwrap();
    let planned = PlannedTrashEntry::capture(entry.clone()).unwrap();
    let claimed = ClaimedTrashEntry::acquire(planned, &trash_root).unwrap();
    (dir, claimed, entry)
}

#[test]
fn pending_log_failure_restores_the_claim_without_deleting() {
    let (_dir, claimed, entry) = claimed_fixture();
    let operation = PurgeOperation::new("trash purge", entry.clone(), None);

    let report = purge_claimed(operation, claimed, |_, _| {
        Err(std::io::Error::other("log unavailable"))
    });

    assert_eq!(std::fs::read_to_string(&entry).unwrap(), "cache");
    assert!(report.purged.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert!(report.failed[0].1.contains("restored"));
}

#[test]
fn final_log_failure_reports_the_completed_deletion() {
    let (_dir, claimed, entry) = claimed_fixture();
    let operation = PurgeOperation::new("trash purge", entry.clone(), None);
    let mut appends = 0;

    let report = purge_claimed(operation, claimed, |_, outcome| {
        appends += 1;
        if appends == 1 {
            assert_eq!(outcome, OpOutcome::Pending);
            Ok(())
        } else {
            Err(std::io::Error::other("log full"))
        }
    });

    assert!(!entry.exists());
    assert_eq!(report.purged, vec![entry.clone()]);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, entry);
    assert!(report.failed[0].1.contains("operation log append failed"));
}

#[test]
fn failed_purge_record_uses_the_reported_location() {
    let original = std::path::PathBuf::from("/trash/0001-cache");
    let preserved = std::path::PathBuf::from("/trash/.claims/purge-token");
    let mut operation = PurgeOperation::new("trash purge", original, None);
    let failure = LocatedFailure::new(preserved.clone(), std::io::Error::other("deletion failed"));

    let outcome = failed_outcome(&mut operation, failure);

    assert_eq!(operation.entry, preserved);
    assert!(matches!(outcome, OpOutcome::Failed { .. }));
}

// (10) Purge rollback refuses when the trash root's ancestor symlink is swapped
// after the claim: the pinned parent identity no longer matches, so the claim is
// not moved back into the diverted directory.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the attack fixture swaps an ancestor symlink with a raw remove_file; the verified deletion engine is the subject under test"
)]
fn purge_rollback_refuses_a_swapped_trash_root_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let physical_root = dir.path().join("physical-trash");
    let evil_root = dir.path().join("evil-trash");
    std::fs::create_dir(&physical_root).unwrap();
    std::fs::create_dir(&evil_root).unwrap();
    // The trash root is reached through a symlink ancestor.
    let trash_root = dir.path().join("trash");
    std::os::unix::fs::symlink(&physical_root, &trash_root).unwrap();

    let entry = trash_root.join("0001-cache");
    std::fs::write(&entry, "cache").unwrap();
    let planned = PlannedTrashEntry::capture(entry.clone()).unwrap();
    let claimed = ClaimedTrashEntry::acquire(planned, &trash_root).unwrap();

    // Swap the ancestor symlink so the logical trash root now resolves to evil.
    std::fs::remove_file(&trash_root).unwrap();
    std::os::unix::fs::symlink(&evil_root, &trash_root).unwrap();

    let operation = PurgeOperation::new("trash purge", entry.clone(), None);
    // A failing pending append drives the rollback path (restore()).
    let report = purge_claimed(operation, claimed, |_, _| {
        Err(std::io::Error::other("log unavailable"))
    });

    assert!(report.purged.is_empty());
    assert_eq!(report.failed.len(), 1);
    // The rollback is refused: parent authentication catches the swapped
    // ancestor, so the entry is not moved into the diverted directory.
    assert!(report.failed[0].1.contains("destination parent"));
    assert!(!evil_root.join("0001-cache").exists());
    assert!(evil_root.join(".claims").read_dir().is_err());
    // The claim is still recoverable in the physical claims directory.
    let claims = physical_root.join(".claims");
    let survivors: Vec<_> = std::fs::read_dir(&claims)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(survivors.len(), 1);
    assert_eq!(std::fs::read_to_string(&survivors[0]).unwrap(), "cache");
}

#[test]
fn claim_failure_report_uses_the_unverified_destination() {
    let planned = std::path::PathBuf::from("/trash/0001-cache");
    let preserved = std::path::PathBuf::from("/trash/.claims/purge-token");
    let failure = ClaimFailure::from_rename(
        &planned,
        RenameFailure::UnverifiedDestination {
            destination: preserved.clone(),
            error: std::io::Error::other("verification failed"),
        },
    );
    let mut report = super::PurgeReport::default();

    report_claim_failure(planned, failure, &mut report);

    assert_eq!(report.failed[0].0, preserved);
    assert!(
        report.failed[0]
            .1
            .contains("identity changed after confirmation")
    );
    assert!(report.failed[0].1.contains("inspect the entry at"));
}
