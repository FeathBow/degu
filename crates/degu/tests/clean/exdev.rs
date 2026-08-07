use crate::common::isolated_degu as degu;
use crate::oplog_records::oplog_records;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn assert_success(out: &std::process::Output) {
    assert!(
        out.status.success(),
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

struct ShmCache {
    root: tempfile::TempDir,
    cache: PathBuf,
}

impl ShmCache {
    fn new() -> Self {
        let root = tempfile::tempdir_in(Path::new("/dev/shm")).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let cache = root.path().join(".cache/pip");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("wheel.whl"), b"cached wheel").unwrap();
        crate::common::make_tree_non_shared_writable(root.path()).unwrap();
        Self { root, cache }
    }

    fn trash_root(&self) -> PathBuf {
        self.root.path().join(".degu-trash")
    }
}

fn clean_json(state: &tempfile::TempDir, shm: &ShmCache) -> serde_json::Value {
    let out = degu()
        .env("HOME", shm.root.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert_success(&out);
    assert!(!shm.cache.exists());
    serde_json::from_slice(&out.stdout).unwrap()
}

fn staged_entry(report: &serde_json::Value) -> PathBuf {
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0]["outcome"], "ok");
    PathBuf::from(executed[0]["trash_entry"].as_str().unwrap())
}

fn undo_and_assert_restored(state: &tempfile::TempDir, shm: &ShmCache, entry: &Path) {
    let out = degu()
        .env("HOME", shm.root.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["undo"])
        .output()
        .unwrap();
    assert_success(&out);
    assert!(shm.cache.is_dir());
    assert_eq!(
        std::fs::read_to_string(shm.cache.join("wheel.whl")).unwrap(),
        "cached wheel"
    );
    assert!(!entry.exists());
}

#[test]
fn clean_stages_cross_device_pip_cache_next_to_cache_and_undo_restores_it() {
    let state = tempfile::tempdir().unwrap();
    let shm = ShmCache::new();

    assert_ne!(
        std::fs::metadata(state.path()).unwrap().dev(),
        std::fs::metadata(&shm.cache).unwrap().dev()
    );

    let report = clean_json(&state, &shm);
    let trash_root = shm.trash_root();
    let trash_entry = staged_entry(&report);
    assert!(trash_entry.starts_with(&trash_root));
    assert_eq!(
        std::fs::metadata(shm.root.path()).unwrap().dev(),
        std::fs::metadata(&trash_entry).unwrap().dev()
    );

    let records = oplog_records(&state);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "trash");
    assert_eq!(records[0]["outcome"], "pending");
    assert_eq!(records[1]["action"], "trash");
    assert_eq!(records[1]["outcome"], "ok");
    assert_eq!(records[0]["trash_entry"], records[1]["trash_entry"]);

    let registry = std::fs::read_to_string(state.path().join("degu/trashroots")).unwrap();
    let registered = registry
        .lines()
        .map(serde_json::from_str::<PathBuf>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(registered, vec![trash_root]);

    undo_and_assert_restored(&state, &shm, &trash_entry);
}

#[test]
fn undo_restores_pending_staged_entry_on_second_trash_root() {
    // A real cross-device clean, then the final Ok record is dropped from
    // the log to simulate rename-succeeded + final-append-failed. The
    // pending record reconciles as Staged and restores from the trash root
    // next to the cache, not the state-dir root.
    let state = tempfile::tempdir().unwrap();
    let shm = ShmCache::new();

    clean_json(&state, &shm);

    let log_path = state.path().join("degu/ops.jsonl");
    let log = std::fs::read_to_string(&log_path).unwrap();
    let mut lines = log.lines();
    let pending = lines.next().unwrap();
    let record: serde_json::Value = serde_json::from_str(pending).unwrap();
    assert_eq!(record["outcome"], "pending");
    std::fs::write(&log_path, format!("{pending}\n")).unwrap();
    let trash_entry = PathBuf::from(record["trash_entry"].as_str().unwrap());
    assert!(trash_entry.starts_with(shm.trash_root()));

    undo_and_assert_restored(&state, &shm, &trash_entry);
}
