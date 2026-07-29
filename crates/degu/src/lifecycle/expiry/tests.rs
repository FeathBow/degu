use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{TrashEntryExpiry, trash_entry_expiry};
use crate::lifecycle::reconcile::TrashOplogInfo;

fn oplog_info_for_test(staged_at: Option<&str>, original: &str, ambiguous: bool) -> TrashOplogInfo {
    TrashOplogInfo {
        staged_at: staged_at.map(|ts| ts.parse().unwrap()),
        original: PathBuf::from(original),
        ambiguous,
    }
}

#[test]
fn trash_entry_expiry_routes_by_reconciled_record_state() {
    let ts = "2000-01-01T00:00:00Z";
    let recorded = HashMap::from([
        (
            PathBuf::from("/trash/staged"),
            oplog_info_for_test(Some(ts), "/original", false),
        ),
        (
            PathBuf::from("/trash/ambiguous"),
            oplog_info_for_test(Some(ts), "/original", true),
        ),
        (
            PathBuf::from("/trash/corrupt-ts"),
            oplog_info_for_test(None, "/original", false),
        ),
    ]);

    assert_eq!(
        trash_entry_expiry(Path::new("/trash/staged"), &recorded),
        TrashEntryExpiry::StagedAt(ts.parse().unwrap())
    );
    assert_eq!(
        trash_entry_expiry(Path::new("/trash/ambiguous"), &recorded),
        TrashEntryExpiry::Never
    );
    assert_eq!(
        trash_entry_expiry(Path::new("/trash/corrupt-ts"), &recorded),
        TrashEntryExpiry::Fallback
    );
    assert_eq!(
        trash_entry_expiry(Path::new("/trash/foreign"), &recorded),
        TrashEntryExpiry::Fallback
    );
}
