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
fn clean_dry_run_json_reports_plan_without_mutating_or_logging() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--dry-run", "--json"]);
    assert!(out.status.success());
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 1);
    assert!(report["executed"].as_array().unwrap().is_empty());
}
