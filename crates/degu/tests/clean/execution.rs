use super::support::*;

#[test]
fn clean_yes_json_trashes_default_pip_cache_and_writes_oplog() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--yes", "--json"]);

    assert!(out.status.success());
    assert!(!cache.exists());
    assert_eq!(
        visible_trash_entries(&state.path().join("degu/trash")).len(),
        1
    );
    let records = oplog_records(&state);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "trash");
    assert_eq!(records[0]["outcome"], "pending");
    assert_eq!(records[1]["action"], "trash");
    assert_eq!(records[1]["outcome"], "ok");
    assert_eq!(records[0]["trash_entry"], records[1]["trash_entry"]);
    assert!(records[0]["reclamation_id"].is_string());
    assert_eq!(records[0]["reclamation_id"], records[1]["reclamation_id"]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["state"], "staged");
}

#[test]
fn clean_yes_json_keeps_redirected_pip_cache_report_only() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = home.path().join("scratch/pip-cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
    let excluded = &report["excluded"][0];
    assert_eq!(excluded["ecosystem"], "pip");
    assert_eq!(excluded["disposition"]["mode"], "report_only");
    assert_eq!(excluded["confidence"], "unverified");
    assert_eq!(excluded["recovery"]["kind"], "regenerable");
    assert_eq!(
        excluded["disposition"]["reason"],
        "relocated via an environment variable degu cannot verify"
    );
}

#[test]
fn clean_purge_yes_json_releases_pip_cache_now_and_writes_purge_oplog() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--purge", "--yes", "--json"]);
    assert!(out.status.success());
    assert!(!cache.exists());
    assert!(visible_trash_entries(&state.path().join("degu/trash")).is_empty());
    let records = oplog_records(&state);
    assert_purge_sequence(&records);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["purged"], true);
    assert_eq!(report["executed"][0]["state"], "purged");
}

fn assert_purge_sequence(records: &[serde_json::Value]) {
    let sequence = records
        .iter()
        .map(|record| {
            (
                record["action"].as_str().unwrap(),
                record["outcome"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sequence,
        [
            ("trash", "pending"),
            ("trash", "ok"),
            ("purge", "pending"),
            ("purge", "ok")
        ]
    );
    assert_eq!(records[0]["trash_entry"], records[1]["trash_entry"]);
    assert_eq!(records[2]["path"], records[1]["trash_entry"]);
    assert_eq!(records[3]["path"], records[1]["trash_entry"]);
    let id = records[0]["reclamation_id"].as_str().unwrap();
    assert!(records.iter().all(|record| record["reclamation_id"] == id));
}

#[test]
fn clean_dry_run_needs_no_anchor_and_creates_no_state() {
    let home = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", "")
        .args(["clean", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(cache.join("wheel.whl")).unwrap(), [0u8; 2048]);
    assert!(!home.path().join(".local/state/degu").exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 1);
    assert!(report["executed"].as_array().unwrap().is_empty());
}
