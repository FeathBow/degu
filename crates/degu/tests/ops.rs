#[path = "support/clean_run.rs"]
mod clean_run;
#[path = "support/mod.rs"]
mod common;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "support/pip_fixture.rs"]
mod pip_fixture;
#[path = "support/strip_sgr.rs"]
mod strip_sgr;
use clean_run::run as run_clean;
use common::isolated_degu as degu;
use pip_fixture::create as fake_pip_cache;
use std::os::unix::fs::PermissionsExt;
use strip_sgr::strip_sgr;

const STATE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn pending_record(home: &std::path::Path, state: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "ts": "2000-01-01T00:00:00Z",
        "tool_version": "0.0.1",
        "command": "clean",
        "action": "trash",
        "path": home.join("scratch/pip-cache"),
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": state.join("degu/trash/0001-pip-cache"),
        "outcome": "pending",
    })
}

fn write_records(path: &std::path::Path, records: &[serde_json::Value]) {
    let mut contents = records
        .iter()
        .map(|record| serde_json::to_string(record).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    contents.push('\n');
    std::fs::write(path, contents).unwrap();
}

#[test]
fn ops_renders_operation_log_in_json_and_human_formats() {
    let (home, state, _cache) = fake_pip_cache();
    run_clean(home.path(), state.path());

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["ops", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let records: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let records = records.as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "trash");
    assert_eq!(records[0]["outcome"], "pending");
    assert_eq!(records[1]["action"], "trash");
    assert_eq!(records[1]["outcome"], "ok");
    assert_eq!(records[0]["trash_entry"], records[1]["trash_entry"]);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("ops")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("trash"));
    // The ~-compressed default pip path is platform-specific.
    #[cfg(target_os = "macos")]
    let expected = "~/Library/Caches/pip";
    #[cfg(not(target_os = "macos"))]
    let expected = "~/.cache/pip";
    assert!(stdout.contains(expected));
}

#[test]
fn ops_renders_empty_state() {
    let empty_home = tempfile::tempdir().unwrap();
    let empty_state = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", empty_home.path())
        .env("XDG_STATE_HOME", empty_state.path())
        .arg("ops")
        .output()
        .unwrap();

    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "No operations recorded.\n"
    );
}

#[cfg(unix)]
#[test]
fn ops_rejects_fifo_state_without_hanging() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let state_dir = state.path().join("degu");
    std::fs::create_dir_all(&state_dir).unwrap();
    let log = state_dir.join("ops.jsonl");
    let status = std::process::Command::new("mkfifo")
        .arg(&log)
        .status()
        .unwrap();
    assert!(status.success());

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["ops", "--json"])
        .timeout(STATE_READ_TIMEOUT)
        .output()
        .expect("ops must reject a FIFO instead of timing out");

    assert!(!out.status.success());
    assert!(out.status.code().is_some(), "process was killed by timeout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ops.jsonl"), "stderr: {stderr}");
    assert!(stderr.contains("not a regular file"), "stderr: {stderr}");
}

#[test]
fn ops_color_always_strips_to_plain_bytes_and_never_colors_json() {
    let (home, state, _cache) = fake_pip_cache();
    run_clean(home.path(), state.path());

    let plain = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("ops")
        .output()
        .unwrap();
    let colored = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["--color", "always", "ops"])
        .output()
        .unwrap();
    let json = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["--color", "always", "ops", "--json"])
        .output()
        .unwrap();

    assert!(plain.status.success());
    assert!(colored.status.success());
    assert!(json.status.success());
    assert!(
        colored
            .stdout
            .windows(b"\x1b[".len())
            .any(|window| window == b"\x1b[")
    );
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
    assert!(!json.stdout.contains(&b'\x1b'));
    serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
}

#[test]
fn ops_renders_orphan_pending_record_as_interrupted() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let log_dir = state.path().join("degu");
    std::fs::create_dir_all(&log_dir).unwrap();
    let orphan = pending_record(home.path(), state.path());
    let mut settled_pending = orphan.clone();
    settled_pending["ts"] = "2000-01-01T00:00:01Z".into();
    settled_pending["reclamation_id"] = "later".into();
    let mut settled = settled_pending.clone();
    settled["ts"] = "2000-01-01T00:00:02Z".into();
    settled["outcome"] = "ok".into();
    write_records(
        &log_dir.join("ops.jsonl"),
        &[orphan, settled_pending, settled],
    );

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("ops")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.matches("interrupted").count(), 1);
}

/// One account whose store is really activated, so a purge takes the sealed path.
/// `isolated_degu` forces the legacy seam, which records a purge already.
struct SealedAccount {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    cache: std::path::PathBuf,
    anchor: std::path::PathBuf,
}

impl SealedAccount {
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().unwrap();
        common::require_sealed_fixture_backend(home.path())?;
        // A sealed store refuses an ancestor that grants foreign rename
        // authority, which a top-level temporary directory has.
        let state = tempfile::tempdir_in(home.path()).unwrap();
        // Directories only. A regular file carrying an extended attribute the
        // held-tree policy does not certify is refused, and some filesystems attach
        // one to every file a process writes -- which would stop these tests at the
        // clean or the purge admission, before the branch either one is about.
        let cache = common::platform_cache_dir(home.path(), "pip");
        std::fs::create_dir_all(cache.join("child")).unwrap();
        common::make_tree_non_shared_writable(home.path()).unwrap();
        let anchor = state.path().join("degu-integration-activation-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = std::fs::canonicalize(&anchor).unwrap();
        Some(Self {
            home,
            state,
            cache,
            anchor,
        })
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("XDG_CONFIG_HOME", common::isolated_config_home())
            .env("LOGNAME", common::isolated_config_home())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN: only a sealed
            // clean activates the store whose purge this test is about.
            .args(args)
            .output()
            .unwrap()
    }

    /// The same account reached through another spelling of its state directory.
    fn run_at(&self, state: &std::path::Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", state)
            .env("XDG_CONFIG_HOME", common::isolated_config_home())
            .env("LOGNAME", common::isolated_config_home())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            .args(args)
            .output()
            .unwrap()
    }

    fn history(&self) -> Vec<serde_json::Value> {
        let out = self.run(&["ops", "--json"]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

/// A purge that deleted has to be traceable through the documented history
/// command. The sealed engine keeps the authority in its WAL, which `ops` does not
/// read, so an unprojected sealed purge leaves the entry looking still staged.
#[test]
fn ops_records_a_sealed_purge_that_deleted() {
    let Some(account) = SealedAccount::new() else {
        return;
    };
    let staged = account.run(&["clean", "--yes", "--json"]);
    assert!(
        staged.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    assert!(!account.cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    let trash_entry = report["executed"][0]["trash_entry"].clone();
    assert!(
        trash_entry.is_string(),
        "the clean staged nothing: {report}"
    );
    assert!(
        account
            .state
            .path()
            .join("degu/sealed-staging/store.activation")
            .exists(),
        "the clean activated no store, so the purge would not be sealed"
    );

    let purged = account.run(&["trash", "purge", "--yes", "--json"]);
    assert!(
        purged.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&purged.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&purged.stdout).unwrap();
    assert_eq!(report["purged"].as_array().unwrap().len(), 1);
    assert!(report["failed"].as_array().unwrap().is_empty());

    let history = account.history();
    let purge = history
        .iter()
        .find(|record| record["action"] == "purge")
        .unwrap_or_else(|| panic!("the completed purge left no history: {history:#?}"));
    assert_eq!(purge["command"], "trash purge");
    assert_eq!(purge["outcome"], "ok");
    assert_eq!(purge["path"], trash_entry);
}

/// A deletion that happened is not a deletion to retry. When the reporting log
/// cannot be appended, the entry belongs in `purged` and in `unrecorded` — a gap to
/// inspect. Pairing the two halves of that answer by different spellings of the same
/// path loses the pairing and reports a completed deletion as a failure.
#[test]
fn a_sealed_purge_the_log_cannot_record_is_still_a_purge() {
    let Some(account) = SealedAccount::new() else {
        return;
    };
    let staged = account.run(&["clean", "--yes", "--json"]);
    assert!(
        staged.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    assert!(!account.cache.exists());

    // The only change is how this run spells the same state directory.
    let alias = account.home.path().join("state-alias");
    std::os::unix::fs::symlink(account.state.path(), &alias).unwrap();
    // Readable so planning still works, unwritable so only the append fails.
    let log = account.state.path().join("degu/ops.jsonl");
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o400)).unwrap();

    let purged = account.run_at(&alias, &["trash", "purge", "--yes", "--json"]);
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&purged.stdout).unwrap();
    assert!(
        purged.status.success(),
        "a completed deletion exited nonzero: {report} stderr: {}",
        String::from_utf8_lossy(&purged.stderr)
    );
    assert_eq!(
        report["purged"].as_array().unwrap().len(),
        1,
        "report: {report}"
    );
    assert_eq!(
        report["unrecorded"].as_array().unwrap().len(),
        1,
        "the unrecordable purge was not reported as a gap: {report}"
    );
    assert!(
        report["failed"].as_array().unwrap().is_empty(),
        "a completed deletion was reported as a purge to retry: {report}"
    );
}
