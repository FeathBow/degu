use std::path::{Path, PathBuf};

#[path = "support/clean_run.rs"]
mod clean_run;
#[path = "support/mod.rs"]
mod common;
#[path = "support/oplog_records.rs"]
mod oplog_records;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "support/pip_fixture.rs"]
mod pip_fixture;
#[path = "support/private_degu_state.rs"]
mod private_degu_state;
use clean_run::run as clean_pip_cache;
use common::isolated_degu as degu;
use oplog_records::oplog_records;
use pip_fixture::create as fake_pip_cache;
use std::os::unix::fs::PermissionsExt;

#[path = "undo/fixtures.rs"]
mod fixtures;
#[path = "undo/order.rs"]
mod order;
#[path = "undo/parent_identity.rs"]
mod parent_identity;
#[path = "undo/pending.rs"]
mod pending;
#[path = "undo/restore.rs"]
mod restore;

fn run_undo(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    json: bool,
) -> std::process::Output {
    let mut command = degu();
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("undo");
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

fn fake_go_build_cache(home: &tempfile::TempDir) -> PathBuf {
    let cache = crate::common::platform_cache_dir(home.path(), "go-build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("artifact.a"), vec![0u8; 128 * 1024]).unwrap();
    cache
}

fn clean_all_caches(home: &tempfile::TempDir, state: &tempfile::TempDir) {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn ok_trash_records(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|record| record["action"] == "trash" && record["outcome"] == "ok")
        .collect()
}

fn restore_records(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|record| record["action"] == "restore" && record["outcome"] != "pending")
        .collect()
}

fn final_trash_entry(records: &[serde_json::Value]) -> PathBuf {
    ok_trash_records(records)
        .first()
        .map(|record| record_trash_entry(record))
        .unwrap()
}

fn record_path(record: &serde_json::Value) -> PathBuf {
    PathBuf::from(record["path"].as_str().unwrap())
}

fn record_trash_entry(record: &serde_json::Value) -> PathBuf {
    PathBuf::from(record["trash_entry"].as_str().unwrap())
}

fn record_reclamation_id(record: &serde_json::Value) -> &str {
    record["reclamation_id"].as_str().unwrap()
}

#[derive(Clone, Copy)]
enum TrashStatus<'a> {
    Ok(Option<&'a str>),
    Pending(Option<&'a str>),
}

fn trash_record(ts: &str, paths: (&Path, &Path), status: TrashStatus<'_>) -> serde_json::Value {
    let pending = matches!(status, TrashStatus::Pending(_));
    let (outcome, reclamation_id) = match status {
        TrashStatus::Ok(id) => ("ok", id),
        TrashStatus::Pending(id) => ("pending", id),
    };
    let mut record = serde_json::json!({
        "ts": ts,
        "tool_version": "0.0.1",
        "command": "clean",
        "action": "trash",
        "path": paths.0,
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": paths.1,
        "outcome": outcome,
    });
    if let Some(id) = reclamation_id {
        record["reclamation_id"] = serde_json::json!(id);
    }
    let mut identity = degu_core::oplog::ObjectIdentity::capture(paths.1);
    if pending && identity.is_err() {
        identity = degu_core::oplog::ObjectIdentity::capture(paths.0);
    }
    if let Ok(identity) = identity {
        record["expected_identity"] = serde_json::to_value(identity).unwrap();
    }
    // Record the restore-destination parent so undo can authenticate it; without
    // it the record is treated as legacy and restore refuses.
    if let Some(parent) = paths.0.parent()
        && let Ok(parent_identity) = degu_core::oplog::ObjectIdentity::capture(parent)
    {
        record["destination_parent"] = serde_json::to_value(parent_identity).unwrap();
    }
    record
}

fn write_oplog(state: &tempfile::TempDir, records: &[serde_json::Value]) {
    let state_dir = private_degu_state::create(state);
    let trash = state_dir.join("trash");
    if trash.exists() {
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    std::fs::write(state_dir.join("ops.jsonl"), format!("{jsonl}\n")).unwrap();
}

fn detach_fixture_dir(path: &Path) -> tempfile::TempDir {
    let detached = tempfile::tempdir().unwrap();
    std::fs::rename(path, detached.path().join("entry")).unwrap();
    detached
}
