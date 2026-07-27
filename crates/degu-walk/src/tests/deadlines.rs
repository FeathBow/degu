use super::support::create_count_fixture;
use crate::{WalkOptions, measure};
use std::time::{Duration, Instant};

#[test]
fn elapsed_deadline_truncates_before_work_without_sleeping() {
    let dir = tempfile::tempdir().unwrap();
    create_count_fixture(dir.path());

    let stats = measure(
        dir.path(),
        &WalkOptions {
            deadline: Some(Instant::now()),
            ..Default::default()
        },
    )
    .unwrap();

    assert!(stats.truncated);
    assert!(stats.unvisited_dirs > 0);
}

#[test]
fn elapsed_deadline_does_not_hide_a_missing_root() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");

    let error = measure(
        &missing,
        &WalkOptions {
            deadline: Some(Instant::now()),
            ..Default::default()
        },
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn future_deadline_matches_unbudgeted_walk() {
    let dir = tempfile::tempdir().unwrap();
    create_count_fixture(dir.path());

    let unbudgeted = measure(dir.path(), &WalkOptions::default()).unwrap();
    let budgeted = measure(
        dir.path(),
        &WalkOptions {
            deadline: Some(Instant::now() + Duration::from_secs(3600)),
            ..Default::default()
        },
    )
    .unwrap();

    assert!(!budgeted.truncated);
    assert_eq!(budgeted.unvisited_dirs, 0);
    assert_eq!(budgeted, unbudgeted);
}
