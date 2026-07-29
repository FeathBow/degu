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
