#[path = "support/mod.rs"]
mod common;
use common::isolated_degu as degu;

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
