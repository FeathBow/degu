use super::super::tests::finding_for_test;
use super::CleanExecution;
use std::path::PathBuf;

#[test]
fn production_stage_reports_sealed_staging_recovery_authority() {
    let entry = PathBuf::from("/trash/0001-cache");
    let finding = finding_for_test(PathBuf::from("/cache"), 4096, 2);
    let item = CleanExecution::production_staged(&finding, entry.clone(), None, None);

    assert!(!item.failed());
    assert_eq!(item.state_label(), "staged");
    assert!(item.reported_as_cleaned(false));
    assert_eq!(item.trash_entry(), Some(entry.as_path()));
    assert!(item.sealed_staging_has_recovery_authority());
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
