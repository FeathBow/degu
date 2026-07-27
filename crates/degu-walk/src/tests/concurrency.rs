use crate::{WalkOptions, WalkStats, measure};
use std::num::NonZeroUsize;

#[test]
fn concurrent_walk_matches_single_worker() {
    let dir = tempfile::tempdir().unwrap();
    create_fixture(dir.path());

    let single = measure(dir.path(), &options(NonZeroUsize::new(1))).unwrap();
    let concurrent = measure(dir.path(), &options(NonZeroUsize::new(4))).unwrap();
    let automatic = measure(dir.path(), &options(None)).unwrap();

    assert_accounting_matches(&concurrent, &single);
    assert_eq!(automatic, concurrent);
}

fn options(max_concurrency: Option<NonZeroUsize>) -> WalkOptions {
    WalkOptions {
        max_concurrency,
        ..Default::default()
    }
}

fn create_fixture(root: &std::path::Path) {
    for subdir in 0..3 {
        let subdir_path = root.join(format!("subdir-{subdir}"));
        std::fs::create_dir(&subdir_path).unwrap();
        for file in 0..4 {
            std::fs::write(
                subdir_path.join(format!("file-{file}.bin")),
                vec![file as u8; 1024 + subdir * 17 + file],
            )
            .unwrap();
        }
    }
}

fn assert_accounting_matches(actual: &WalkStats, expected: &WalkStats) {
    assert_eq!(actual.dirs, expected.dirs);
    assert_eq!(actual.files, expected.files);
    assert_eq!(actual.inodes, expected.inodes);
    assert_eq!(actual.bytes_apparent, expected.bytes_apparent);
    assert_eq!(actual.bytes_allocated, expected.bytes_allocated);
    assert_eq!(actual.bytes_hardlinked, expected.bytes_hardlinked);
    assert_eq!(actual.newest_mtime, expected.newest_mtime);
    assert_eq!(actual.stat_ops, expected.stat_ops);
    assert_eq!(actual.readdir_ops, expected.readdir_ops);
}
