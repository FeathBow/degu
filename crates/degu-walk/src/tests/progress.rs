use crate::{Progress, WalkOptions, measure};
use std::sync::Arc;

#[test]
fn progress_counts_accounted_entries_and_allocated_bytes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub/a.bin"), [0_u8; 4096]).unwrap();
    let progress = Arc::new(Progress::default());

    let stats = measure(
        dir.path(),
        &WalkOptions {
            progress: Some(Arc::clone(&progress)),
            ..Default::default()
        },
    )
    .unwrap();

    let snapshot = progress.snapshot();
    assert_eq!(snapshot.inodes, stats.inodes);
    assert_eq!(snapshot.bytes_allocated, stats.bytes_allocated);
    assert_eq!(snapshot.stat_ops, stats.stat_ops);
    assert_eq!(snapshot.readdir_ops, stats.readdir_ops);
}
