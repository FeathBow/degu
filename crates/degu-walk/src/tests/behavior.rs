use super::support::create_count_fixture;
use super::support::{restore_readable, running_as_root};
use crate::accounting::SKIP_SAMPLE_CAP;
use crate::{WalkOptions, measure};
use std::io::Write;
use std::num::NonZeroUsize;

#[test]
fn records_shared_writable_directories_without_dropping_their_measurement() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::write(shared.join("data.bin"), [1_u8; 32]).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

    let stats = measure(root.path(), &WalkOptions::default()).unwrap();

    assert_eq!(stats.shared_writable_dirs, 2);
    assert_eq!(stats.dirs, 2);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.inodes, 3);
    assert_eq!(stats.skipped_total, 0);
}

#[test]
fn counts_files_dirs_and_inodes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let mut file = std::fs::File::create(dir.path().join("sub/a.bin")).unwrap();
    file.write_all(&[0_u8; 4096]).unwrap();

    let stats = measure(dir.path(), &WalkOptions::default()).unwrap();

    assert_eq!(stats.dirs, 2);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.inodes, 3);
    assert_eq!(stats.bytes_apparent, 4096);
    assert!(stats.bytes_allocated >= 4096);
    assert!(stats.newest_mtime.is_some());
}

#[test]
fn excludes_named_entries_and_records_the_boundary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("keep")).unwrap();
    std::fs::write(dir.path().join("keep/data.bin"), [0_u8; 1024]).unwrap();
    std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
    std::fs::write(dir.path().join(".codex/state.bin"), [0_u8; 4096]).unwrap();

    let stats = measure(
        dir.path(),
        &WalkOptions {
            excluded_entry_names: &[".codex"],
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(stats.excluded_entries, 1);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.dirs, 2);
}

#[test]
fn counts_metadata_and_readdir_ops_exactly() {
    let dir = tempfile::tempdir().unwrap();
    create_count_fixture(dir.path());

    let stats = measure(dir.path(), &WalkOptions::default()).unwrap();

    assert_eq!(stats.dirs, 3);
    assert_eq!(stats.files, 7);
    assert_eq!(stats.stat_ops, 10);
    assert_eq!(stats.readdir_ops, 3);
}

#[test]
fn counts_hardlinked_bytes_per_directory_entry() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("pkg");
    let linked = dir.path().join("env-copy");
    std::fs::write(&original, [0_u8; 4096]).unwrap();
    std::fs::hard_link(&original, &linked).unwrap();

    let stats = measure(dir.path(), &WalkOptions::default()).unwrap();

    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes_apparent, 8192);
    assert!(stats.bytes_allocated >= 8192);
    assert_eq!(stats.bytes_hardlinked, stats.bytes_allocated);
    assert!(stats.newest_mtime.is_some());
}

#[test]
fn does_not_follow_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("data"), [0_u8; 1024]).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();

    let stats = measure(dir.path(), &WalkOptions::default()).unwrap();

    assert_eq!(stats.files, 2);
    assert_eq!(stats.dirs, 2);
}

#[test]
fn records_unreadable_directories_as_skipped() {
    use std::os::unix::fs::PermissionsExt;

    assert!(
        !running_as_root(),
        "permission-denial coverage requires a non-root test process"
    );
    let dir = tempfile::tempdir().unwrap();
    let unreadable = dir.path().join("unreadable");
    std::fs::create_dir(&unreadable).unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let stats = measure(dir.path(), &WalkOptions::default()).unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(stats.skipped_total, 1);
    assert_eq!(stats.skipped.len(), 1);
    assert_eq!(stats.skipped[0].path, unreadable);
    assert!(!stats.skipped[0].reason.is_empty());
}

#[test]
fn caps_skipped_samples_while_counting_total() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        !running_as_root(),
        "permission-denial coverage requires a non-root test process"
    );
    let unreadable = create_unreadable_dirs(dir.path(), 1000);
    let stats = measure(
        dir.path(),
        &WalkOptions {
            max_concurrency: NonZeroUsize::new(4),
            ..Default::default()
        },
    )
    .unwrap();
    restore_readable(&unreadable);

    assert!(stats.skipped.len() <= SKIP_SAMPLE_CAP);
    assert_eq!(stats.skipped_total, unreadable.len() as u64);
    // Unreadable children fail at the verified open, before any enumeration, so
    // only the readable root issues a readdir.
    assert_eq!(stats.readdir_ops, 1);
}

fn create_unreadable_dirs(root: &std::path::Path, count: usize) -> Vec<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    (0..count)
        .map(|index| {
            let path = root.join(format!("unreadable-{index}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            path
        })
        .collect()
}
