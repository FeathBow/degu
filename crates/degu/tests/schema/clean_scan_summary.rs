use super::support::*;

#[test]
fn clean_json_schema_is_frozen() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let _pip_cache = fake_pip_cache(&home);
    let _hf_home = fake_huggingface_cache(&home);
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["clean", "--yes", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, CLEAN_REPORT_KEYS);
    assert_eq!(json["completeness"], "complete");
    assert!(json["opt_in"].is_boolean());
    assert_keys(&json["expiry"], CLEAN_EXPIRY_KEYS);
    assert!(json["expiry"]["attempted"].is_boolean());
    assert!(json["expiry"]["retention_days"].is_number());
    assert!(json["expiry"]["planned"].is_array());
    assert!(json["expiry"]["purged"].is_array());
    for failure in json["expiry"]["failed"].as_array().unwrap() {
        assert_keys(failure, CLEAN_EXPIRY_FAILURE_KEYS);
    }
    for finding in assert_non_empty_array(&json["planned"], "clean planned findings") {
        assert_finding(finding);
    }
    for finding in assert_non_empty_array(&json["excluded"], "clean excluded findings") {
        assert_finding(finding);
    }
    for execution in assert_non_empty_array(&json["executed"], "clean executions") {
        assert_keys(execution, CLEAN_EXECUTION_KEYS);
        assert_clean_outcome(&execution["outcome"]);
    }
}

#[test]
fn scan_summary_json_schema_is_frozen() {
    let home = tempfile::tempdir().unwrap();
    let _pip_cache = fake_pip_cache(&home);
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--summary", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, SCAN_SUMMARY_REPORT_KEYS);
    assert_keys(&json["total"], SCAN_SUMMARY_TOTAL_KEYS);
    assert!(json["total"]["bytes_hardlinked"].is_number());
    assert!(json["total"]["lower_bound"].is_boolean());
    assert!(json["truncated"].is_boolean());
    assert_empty_runtime_block(&json);
    for row in assert_non_empty_array(&json["ecosystems"], "scan summary ecosystem rows") {
        assert_keys(row, SCAN_SUMMARY_ECOSYSTEM_KEYS);
        for field in ["bytes_allocated", "bytes_hardlinked", "inodes", "share"] {
            assert!(row[field].is_number());
        }
        assert!(row["ecosystem"].is_string());
        assert!(row["lower_bound"].is_boolean());
    }
}

fn assert_empty_runtime_block(json: &serde_json::Value) {
    assert_keys(&json["runtime"], SCAN_SUMMARY_RUNTIME_KEYS);
    assert_keys(&json["runtime"]["total"], SCAN_SUMMARY_TOTAL_KEYS);
    assert!(json["runtime"]["ecosystems"].as_array().unwrap().is_empty());
    assert_eq!(json["runtime"]["total"]["bytes_allocated"], 0);
    assert_eq!(json["runtime"]["total"]["bytes_hardlinked"], 0);
    assert_eq!(json["runtime"]["total"]["inodes"], 0);
    assert_eq!(json["runtime"]["total"]["lower_bound"], false);
}
