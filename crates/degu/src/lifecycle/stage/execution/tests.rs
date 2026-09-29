use super::super::tests::finding_for_test;
use super::{CleanExecution, RestoreAuthority};
use std::path::PathBuf;

#[test]
fn production_stage_is_wal_governed_and_restorable_from_the_wal() {
    let entry = PathBuf::from("/trash/0001-cache");
    let finding = finding_for_test(PathBuf::from("/cache"), 4096, 2);
    let item = CleanExecution::production_staged(&finding, entry.clone(), None, None);

    assert!(!item.failed());
    assert_eq!(item.state_label(), "staged");
    assert!(item.reported_as_cleaned(false));
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert!(item.staged_under_seal_authority());
    assert_eq!(item.restore_authority(), RestoreAuthority::SealWal);
    assert!(!item.requires_manual_recovery());
}

#[test]
fn unverified_destination_reports_its_location_and_manual_recovery() {
    let entry = PathBuf::from("/trash/0001-cache");
    let finding = finding_for_test(PathBuf::from("/cache"), 0, 0);
    let item = CleanExecution::unverified_destination(
        &finding,
        entry.clone(),
        "restoration failed".into(),
    );

    assert!(item.failed());
    assert_eq!(item.state_label(), "unverified_destination");
    assert!(item.has_trash_location());
    assert!(!item.reported_as_cleaned(false));
    assert!(!item.reported_as_cleaned(true));
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert!(item.requires_manual_recovery());
}

/// `purge_failed` is the one state both lifecycles produce, so its name cannot say
/// which record would restore the entry it left staged. The sealed path's answer is
/// the WAL; the legacy path's is checked beside its own fixture.
#[test]
fn a_sealed_purge_admission_failure_is_restorable_from_the_wal() {
    let entry = PathBuf::from("/trash/0001-cache");
    let finding = finding_for_test(PathBuf::from("/cache"), 4096, 2);
    let item = CleanExecution::production_purge_admission_failed(
        &finding,
        entry.clone(),
        "purge admission failed".into(),
    );

    assert_eq!(item.state_label(), "purge_failed");
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert_eq!(item.restore_authority(), RestoreAuthority::SealWal);
}

/// A row that moved nothing and a row whose object is gone are both unrecoverable,
/// which is a third answer rather than a default one of the two authorities.
#[test]
fn a_row_with_nothing_to_restore_names_no_authority() {
    let finding = finding_for_test(PathBuf::from("/cache"), 4096, 2);
    let not_attempted = CleanExecution::not_attempted(&finding, "preflight rejected".into());
    let purged =
        CleanExecution::production_purged(&finding, PathBuf::from("/trash/0001-cache"), None);

    assert_eq!(not_attempted.restore_authority(), RestoreAuthority::None);
    assert_eq!(purged.restore_authority(), RestoreAuthority::None);
}
