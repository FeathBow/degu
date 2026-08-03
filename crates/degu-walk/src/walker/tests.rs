use super::*;
use crate::HEARTBEAT_INTERVAL;
use rustix::fs::Dir;
use std::ffi::CString;

const TOTAL_ENTRIES: u64 = 5;
const VISITED_ENTRIES: u64 = 3;

fn open_dir(path: &Path) -> OpenDir {
    let inspection = lstat(path).unwrap();
    let fd = open_root(path, inspection.identity).unwrap();
    OpenDir {
        fd: Arc::new(fd),
        path: path.to_path_buf(),
    }
}

fn entry_names(dir: &OpenDir) -> Vec<CString> {
    let entries = Dir::read_from(&dir.fd).unwrap();
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.unwrap();
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        names.push(entry.file_name().to_owned());
    }
    names
}

#[test]
fn measure_reuses_progress_heartbeat_across_roots() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let initial_heartbeat = Instant::now()
        .checked_sub(HEARTBEAT_INTERVAL)
        .expect("monotonic clock supports the heartbeat interval");
    let progress = std::sync::Arc::new(Progress {
        heartbeat: Heartbeat::new(initial_heartbeat),
        ..Progress::default()
    });
    let options = WalkOptions {
        max_concurrency: Some(std::num::NonZeroUsize::MIN),
        progress: Some(std::sync::Arc::clone(&progress)),
        ..WalkOptions::default()
    };

    measure(first_root.path(), &options).unwrap();
    let first_heartbeat = *progress.heartbeat.last.lock().unwrap();
    assert!(first_heartbeat > initial_heartbeat);

    measure(second_root.path(), &options).unwrap();
    assert_eq!(*progress.heartbeat.last.lock().unwrap(), first_heartbeat);
}

#[test]
fn deadline_stops_flat_directory_before_more_metadata_calls() {
    let dir = tempfile::tempdir().unwrap();
    for index in 0..TOTAL_ENTRIES {
        std::fs::write(dir.path().join(format!("entry-{index}")), [0_u8]).unwrap();
    }
    let options = WalkOptions::default();
    let open = open_dir(dir.path());
    let inspection = lstat(dir.path()).unwrap();
    let heartbeat = Heartbeat::default();
    let context = WorkerContext {
        root: dir.path(),
        root_device: root_device(&inspection.meta, options.one_filesystem),
        options: &options,
        heartbeat: &heartbeat,
    };
    let mut polls = 0_u64;
    let mut result = ScanResult::default();

    scan_dir(
        &open,
        &context,
        || {
            polls += 1;
            polls > VISITED_ENTRIES + 1
        },
        &mut result,
    );

    assert_eq!(polls, VISITED_ENTRIES + 2);
    assert_eq!(result.stats.files, VISITED_ENTRIES);
    assert_eq!(result.stats.stat_ops, VISITED_ENTRIES);
    assert!(result.stats.truncated);
    assert_eq!(result.stats.unvisited_dirs, 1);
}

#[test]
#[allow(clippy::disallowed_methods)]
fn entries_vanishing_after_enumeration_are_not_skips() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("kept"), [0_u8]).unwrap();
    std::fs::write(dir.path().join("doomed"), [0_u8]).unwrap();
    std::fs::create_dir(dir.path().join("doomed-dir")).unwrap();
    let options = WalkOptions::default();
    let open = open_dir(dir.path());
    let inspection = lstat(dir.path()).unwrap();
    let heartbeat = Heartbeat::default();
    let context = WorkerContext {
        root: dir.path(),
        root_device: root_device(&inspection.meta, options.one_filesystem),
        options: &options,
        heartbeat: &heartbeat,
    };
    let names = entry_names(&open);
    std::fs::remove_file(dir.path().join("doomed")).unwrap();
    std::fs::remove_dir(dir.path().join("doomed-dir")).unwrap();

    let mut result = ScanResult::default();
    let mut scanner = EntryScanner {
        context: &context,
        result: &mut result,
    };
    for name in &names {
        scanner.scan(&open, name);
    }

    assert_eq!(result.stats.skipped_total, 0);
    assert_eq!(result.stats.files, 1);
    assert!(result.dirs.is_empty());
}

#[test]
#[allow(clippy::disallowed_methods)]
fn directories_vanishing_after_enumeration_are_not_skips() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let options = WalkOptions::default();
    let open = open_dir(dir.path());
    let inspection = lstat(dir.path()).unwrap();
    let heartbeat = Heartbeat::default();
    let context = WorkerContext {
        root: dir.path(),
        root_device: root_device(&inspection.meta, options.one_filesystem),
        options: &options,
        heartbeat: &heartbeat,
    };
    let names = entry_names(&open);
    let mut result = ScanResult::default();
    let mut scanner = EntryScanner {
        context: &context,
        result: &mut result,
    };
    for name in &names {
        scanner.scan(&open, name);
    }
    let task = result.dirs.pop().unwrap();
    assert!(result.dirs.is_empty());
    // Remove the child after enqueue so its deferred open vanishes.
    std::fs::remove_dir(dir.path().join("sub")).unwrap();

    let consumed = consume_dir(task, &context, || false);

    assert_eq!(consumed.stats.skipped_total, 0);
    assert_eq!(consumed.stats.dirs, 0);
    assert!(consumed.dirs.is_empty());
}

#[test]
fn unreadable_directory_is_a_skip_not_a_dir_on_consume() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inner"), [0_u8]).unwrap();
    let options = WalkOptions::default();
    let open = open_dir(dir.path());
    let inspection = lstat(dir.path()).unwrap();
    let heartbeat = Heartbeat::default();
    let context = WorkerContext {
        root: dir.path(),
        root_device: root_device(&inspection.meta, options.one_filesystem),
        options: &options,
        heartbeat: &heartbeat,
    };
    // fstatat needs no child permission, so the child inspects fine but its open is denied.
    let names = entry_names(&open);
    let mut result = ScanResult::default();
    let mut scanner = EntryScanner {
        context: &context,
        result: &mut result,
    };
    for name in &names {
        scanner.scan(&open, name);
    }
    let task = result.dirs.pop().unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o0)).unwrap();

    let consumed = consume_dir(task, &context, || false);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(consumed.stats.skipped_total, 1);
    assert_eq!(consumed.stats.dirs, 0);
    assert_eq!(consumed.stats.skipped[0].path, locked);
}

#[test]
fn required_uid_excludes_foreign_entries_and_never_descends_into_foreign_directories() {
    let root = tempfile::tempdir().unwrap();
    let owned_file = root.path().join("owned.bin");
    let foreign_file = root.path().join("foreign.bin");
    let foreign_dir = root.path().join("foreign-dir");
    std::fs::write(&owned_file, [1_u8; 16]).unwrap();
    std::fs::write(&foreign_file, [2_u8; 32]).unwrap();
    std::fs::create_dir(&foreign_dir).unwrap();
    std::fs::write(foreign_dir.join("must-not-be-visited.bin"), [3_u8; 64]).unwrap();

    let required_uid = rustix::process::geteuid().as_raw();
    let foreign_uid = different_uid(required_uid);
    let overrides = std::collections::HashMap::from([
        (foreign_file.clone(), foreign_uid),
        (foreign_dir.clone(), foreign_uid),
    ]);
    let options = WalkOptions {
        required_uid: Some(required_uid),
        max_concurrency: Some(std::num::NonZeroUsize::MIN),
        uid_overrides: Some(std::sync::Arc::new(overrides)),
        ..WalkOptions::default()
    };

    let stats = measure(root.path(), &options).unwrap();

    assert_eq!(stats.dirs, 1, "only the owned root is counted");
    assert_eq!(stats.files, 1, "only the owned file is counted");
    assert_eq!(stats.inodes, 2);
    assert_eq!(stats.bytes_apparent, 16);
    assert_eq!(stats.skipped_total, 2);
    assert_eq!(stats.readdir_ops, 1, "foreign directory was not opened");
    assert_eq!(stats.stat_ops, 4, "foreign descendant was not inspected");
    let skipped = stats
        .skipped
        .iter()
        .map(|skip| skip.path.as_path())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        skipped,
        std::collections::HashSet::from([foreign_file.as_path(), foreign_dir.as_path()])
    );
    assert!(
        stats
            .skipped
            .iter()
            .all(|skip| skip.reason.contains("differs from required UID"))
    );
}

#[test]
fn required_uid_rejects_a_foreign_root_without_accounting_or_descent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("hidden.bin"), [1_u8; 16]).unwrap();
    let actual_uid = rustix::process::geteuid().as_raw();
    let options = WalkOptions {
        required_uid: Some(different_uid(actual_uid)),
        ..WalkOptions::default()
    };

    let stats = measure(root.path(), &options).unwrap();

    assert_eq!(stats.inodes, 0);
    assert_eq!(stats.bytes_apparent, 0);
    assert_eq!(stats.readdir_ops, 0);
    assert_eq!(stats.stat_ops, 1);
    assert_eq!(stats.skipped_total, 1);
    assert_eq!(stats.skipped[0].path, root.path());
}

fn different_uid(uid: u32) -> u32 {
    if uid == u32::MAX { uid - 1 } else { uid + 1 }
}

#[test]
fn vanished_root_is_reported_not_silently_complete() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let inspection = lstat(&root).unwrap();
    std::fs::rename(&root, parent.path().join("moved")).unwrap();

    let opened = open_root(&root, inspection.identity);
    assert_eq!(opened.unwrap_err().kind(), std::io::ErrorKind::NotFound);

    let error = measure(&root, &WalkOptions::default()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn deferred_open_refuses_a_symlink_swap_on_consume() {
    // The swap lands between enqueue and the deferred open, so only consume catches it.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let child = root.join("child");
    let external = temp.path().join("external");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&child).unwrap();
    std::fs::write(child.join("inside"), [0_u8]).unwrap();
    std::fs::create_dir(&external).unwrap();
    std::fs::write(external.join("stolen"), [0_u8]).unwrap();

    // one_filesystem off so the boundary check can't mask the no-follow guard under test.
    let options = WalkOptions {
        one_filesystem: false,
        ..WalkOptions::default()
    };
    let open = open_dir(&root);
    let inspection = lstat(&root).unwrap();
    let heartbeat = Heartbeat::default();
    let context = WorkerContext {
        root: &root,
        root_device: root_device(&inspection.meta, options.one_filesystem),
        options: &options,
        heartbeat: &heartbeat,
    };

    let mut result = ScanResult::default();
    let mut scanner = EntryScanner {
        context: &context,
        result: &mut result,
    };
    for name in &entry_names(&open) {
        scanner.scan(&open, name);
    }
    let task = result.dirs.pop().unwrap();
    assert!(result.dirs.is_empty());

    std::fs::rename(&child, root.join("moved-away")).unwrap();
    std::os::unix::fs::symlink(&external, &child).unwrap();

    let consumed = consume_dir(task, &context, || false);

    assert_eq!(
        consumed.stats.skipped_total, 1,
        "the refused swap must be recorded as a skip"
    );
    assert_eq!(
        consumed.stats.dirs, 0,
        "the swapped target must not be entered"
    );
    assert!(
        consumed.dirs.is_empty(),
        "no descent handle may be produced"
    );
}

#[test]
fn wide_directory_scans_completely_under_a_low_fd_limit() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    const SUBDIRS: usize = 256;
    const FD_LIMIT: u64 = 64;
    const FIXTURE: &str = "DEGU_WIDE_FIXTURE";
    const EXPECTED: &str = "DEGU_WIDE_EXPECTED";

    // Child leg: this process was re-executed with the fd limit already lowered.
    if let Ok(root) = std::env::var(FIXTURE) {
        let expected: u64 = std::env::var(EXPECTED).unwrap().parse().unwrap();
        let options = WalkOptions {
            max_concurrency: Some(std::num::NonZeroUsize::new(4).unwrap()),
            ..WalkOptions::default()
        };
        let stats = measure(Path::new(&root), &options).unwrap();
        assert_eq!(stats.skipped_total, 0);
        assert_eq!(stats.dirs, expected);
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    for index in 0..SUBDIRS {
        let child = dir.path().join(format!("child-{index}"));
        std::fs::create_dir(&child).unwrap();
        std::fs::create_dir(child.join("grandchild")).unwrap();
    }

    // Re-exec (not fork) with the fd limit lowered before the process starts.
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "walker::tests::wide_directory_scans_completely_under_a_low_fd_limit",
            "--exact",
            "--nocapture",
        ])
        .env(FIXTURE, dir.path())
        .env(EXPECTED, (SUBDIRS * 2 + 1).to_string());
    unsafe {
        command.pre_exec(|| {
            use rustix::process::{Resource, Rlimit, setrlimit};
            setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(FD_LIMIT),
                    maximum: Some(FD_LIMIT),
                },
            )
            .map_err(std::io::Error::from)
        });
    }
    assert!(
        command.status().unwrap().success(),
        "wide-directory scan was incomplete under the low fd limit"
    );
}

#[test]
fn root_symlink_with_trailing_slash_is_not_followed() {
    assert_root_symlink_not_followed("/");
}

#[test]
fn root_symlink_with_trailing_slash_dot_is_not_followed() {
    assert_root_symlink_not_followed("/.");
}

fn assert_root_symlink_not_followed(suffix: &str) {
    let temp = tempfile::tempdir().unwrap();
    let external = temp.path().join("external");
    let alias = temp.path().join("alias");
    std::fs::create_dir(&external).unwrap();
    std::fs::write(external.join("outside.bin"), [0_u8; 8]).unwrap();
    std::os::unix::fs::symlink(&external, &alias).unwrap();

    let root = PathBuf::from(format!("{}{suffix}", alias.display()));
    let stats = measure(&root, &WalkOptions::default()).unwrap();

    assert_eq!(
        stats.dirs, 0,
        "the symlink must not be entered as a directory"
    );
    assert_eq!(stats.files, 1, "only the symlink itself is recorded");
    assert_eq!(stats.inodes, 1, "the external file must never be counted");
}

#[test]
fn normalize_root_strips_trailing_dot_and_slash_but_keeps_relative_roots() {
    let cases = [
        ("alias/", "alias"),
        ("alias/.", "alias"),
        (".", "."),
        ("cache", "cache"),
        ("./cache", "cache"),
        ("a/b/c", "a/b/c"),
        ("/x/alias/", "/x/alias"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            normalize_root(Path::new(input)),
            Path::new(expected),
            "{input}"
        );
    }
}

#[test]
fn measure_reports_a_missing_relative_root_as_not_found_not_invalid_input() {
    let error = measure(
        Path::new("degu-nonexistent-relative-root"),
        &WalkOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}
