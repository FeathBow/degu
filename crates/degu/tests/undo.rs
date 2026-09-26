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

/// One clean is one reclamation group, and the reader who wants an older group
/// back must be able to name it: `degu undo` on its own takes the newest.
#[test]
fn undo_restores_the_reclamation_group_it_is_given() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    let older = fake_go_build_cache(&home);
    clean_one(&home, &state, &older);
    // Deliberately the larger of the two: the trash listing is ordered by size, so
    // this puts the newer group first and a test that indexed into that listing
    // instead of naming its group would reach for the wrong one.
    let newer = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&newer).unwrap();
    std::fs::write(newer.join("wheel.bin"), vec![0u8; 512 * 1024]).unwrap();
    clean_one(&home, &state, &newer);

    let older_group = staged_group_for(&home, &state, &older);
    let newer_group = staged_group_for(&home, &state, &newer);
    assert_ne!(older_group, newer_group, "two cleans are two groups");

    let out = undo_reclamation(&home, &state, &older_group);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(older.exists(), "the named group should be restored");
    assert_eq!(
        staged_reclamation_ids(&home, &state),
        vec![newer_group],
        "the group that was not named should still be staged"
    );
}

/// Naming a group nothing can act on is a mistake, not an empty run: answering
/// "nothing to undo" would read as though that group had already come back.
#[test]
fn undo_refuses_a_reclamation_group_it_cannot_find() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    clean_one(&home, &state, &fake_go_build_cache(&home));

    let out = undo_reclamation(&home, &state, "no-such-group");

    assert!(!out.status.success(), "an unknown group must not exit zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no-such-group"), "{stderr}");
    let staged = staged_reclamation_ids(&home, &state);
    assert!(stderr.contains(&staged[0]), "{stderr}");
}

fn clean_one(home: &tempfile::TempDir, state: &tempfile::TempDir, path: &Path) {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--path"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn undo_reclamation(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    id: &str,
) -> std::process::Output {
    degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["undo", "--reclamation-id", id])
        .output()
        .unwrap()
}

/// The groups still staged, read the way the documentation tells a reader to find
/// them. The listing is ordered by size rather than by age, so a caller that wants
/// one particular group names it instead of indexing into this.
fn staged_reclamation_ids(home: &tempfile::TempDir, state: &tempfile::TempDir) -> Vec<String> {
    staged_rows(home, state)
        .iter()
        .filter_map(|row| row["reclamation_id"].as_str().map(str::to_owned))
        .collect()
}

/// The group that staged one cache. A staged entry is named after the directory it
/// came from, which is what ties a row back to the cache this test cleaned.
fn staged_group_for(home: &tempfile::TempDir, state: &tempfile::TempDir, cache: &Path) -> String {
    let suffix = format!("-{}", cache.file_name().unwrap().to_string_lossy());
    let rows = staged_rows(home, state);
    let row = rows
        .iter()
        .find(|row| row["entry"].as_str().is_some_and(|e| e.ends_with(&suffix)))
        .unwrap_or_else(|| panic!("no staged entry from {cache:?} in {rows:?}"));
    row["reclamation_id"]
        .as_str()
        .expect("a staged entry names its clean")
        .to_owned()
}

fn staged_rows(home: &tempfile::TempDir, state: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["trash", "list", "--json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    json["entries"].as_array().cloned().unwrap_or_default()
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
