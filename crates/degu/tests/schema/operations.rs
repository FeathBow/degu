use super::support::*;
use serde_json::Value;

#[test]
fn trash_list_json_schema_is_frozen() {
    let (home, state) = staged_cache();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["trash", "list", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, TRASH_LIST_REPORT_KEYS);
    assert_eq!(json["omitted"].as_u64().unwrap(), 0);
    for row in assert_non_empty_array(&json["entries"], "trash list rows") {
        assert_keys(row, TRASH_LIST_ROW_KEYS);
        assert!(row["age_days"].is_number());
        assert!(row["ambiguous"].is_boolean());
        assert!(row["interrupted_purge"].is_boolean());
        assert!(row["bytes_hardlinked"].is_number());
        assert!(row["lower_bound"].is_boolean());
    }
}

#[test]
fn trash_purge_json_schema_is_frozen() {
    let (home, state) = staged_cache();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["trash", "purge", "--yes", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, TRASH_PURGE_REPORT_KEYS);
    assert_non_empty_array(&json["purged"], "trash purge purged entries");
    json["failed"].as_array().unwrap();
}

#[test]
fn ops_json_schema_is_frozen() {
    let (home, state) = staged_cache();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["ops", "--json"])
            .output()
            .unwrap(),
    );
    for record in assert_non_empty_array(&json, "op records") {
        assert_op_record(record, true);
        // The destination_parent field is an on-disk-only addition; it must not
        // leak into the frozen `--json` schema.
        assert!(record.get("destination_parent").is_none());
    }
}

#[test]
fn on_disk_log_records_the_destination_parent_without_exposing_it_in_json() {
    let (home, state) = staged_cache();

    // The staged (ok) trash record carries the new on-disk field.
    let log = std::fs::read_to_string(state.path().join("degu/ops.jsonl")).unwrap();
    let staged_ok = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|record| record["action"] == "trash" && record["outcome"] == "ok")
        .expect("a staged trash record");
    assert!(
        staged_ok.get("destination_parent").is_some(),
        "staged record should record its destination parent"
    );

    // The `ops --json` schema stays frozen: no destination_parent key surfaces.
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["ops", "--json"])
            .output()
            .unwrap(),
    );
    for record in json.as_array().unwrap() {
        assert!(record.get("destination_parent").is_none());
    }
}

#[test]
fn undo_json_schema_is_frozen() {
    let (home, state) = staged_cache();
    let first = run_undo(&home, &state);
    assert!(first["reclamation_id"].is_string());
    let restored = assert_non_empty_array(&first["restored"], "undo restored entries");
    for entry in restored {
        assert_keys(entry, UNDO_ENTRY_KEYS);
    }
    assert_empty_undo_sections(&first);

    let second = run_undo(&home, &state);
    assert!(second["reclamation_id"].is_null());
    assert!(second["restored"].as_array().unwrap().is_empty());
    assert_empty_undo_sections(&second);
}

fn staged_cache() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    fake_pip_cache(&home);
    clean_pip_cache(&home, &state);
    (home, state)
}

fn run_undo(home: &tempfile::TempDir, state: &tempfile::TempDir) -> serde_json::Value {
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["undo", "--json"])
            .output()
            .unwrap(),
    );
    assert_keys(&json, UNDO_REPORT_KEYS);
    json
}

fn assert_empty_undo_sections(json: &serde_json::Value) {
    assert!(json["failed"].as_array().unwrap().is_empty());
    assert!(json["gone"].as_array().unwrap().is_empty());
    assert!(json["log_failures"].as_array().unwrap().is_empty());
    assert!(json["ambiguous"].as_array().unwrap().is_empty());
}
