use super::support::*;
use serde_json::Value;

#[test]
fn scan_summary_runtime_block_carries_tmp_bytes_outside_the_top_level_total() {
    let home = tempfile::tempdir().unwrap();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    let tmp = fake_stale_tmpdir();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("TMPDIR", tmp.path())
            .args(["scan", "--summary", "--runtime", "--json"])
            .output()
            .unwrap(),
    );

    assert_runtime_partition(&json);
    assert_runtime_human_output(&home, &tmp);
}

fn assert_runtime_partition(json: &Value) {
    let runtime_rows = json["runtime"]["ecosystems"].as_array().unwrap();
    let tmp_row = runtime_rows
        .iter()
        .find(|entry| entry["ecosystem"] == "tmp")
        .unwrap_or_else(|| panic!("missing tmp runtime row in {json:#}"));
    let tmp_bytes = tmp_row["bytes_allocated"].as_u64().unwrap();
    let runtime_total = json["runtime"]["total"]["bytes_allocated"]
        .as_u64()
        .unwrap();
    let runtime_sum = allocated_sum(runtime_rows);
    assert!(tmp_bytes >= 4096);
    assert_eq!(runtime_total, runtime_sum);
    assert!(runtime_total >= tmp_bytes);

    let top_rows = json["ecosystems"].as_array().unwrap();
    assert!(
        top_rows
            .iter()
            .all(|entry| { entry["ecosystem"] != "tmp" && entry["ecosystem"] != "shm" })
    );
    let total_bytes = json["total"]["bytes_allocated"].as_u64().unwrap();
    assert_eq!(total_bytes, row(json, "pip")["bytes_allocated"]);
    assert_eq!(total_bytes, allocated_sum(top_rows));
    assert_block_shares_self_consistent(top_rows, total_bytes);
    assert_block_shares_self_consistent(runtime_rows, runtime_total);
}

fn allocated_sum(rows: &[Value]) -> u64 {
    rows.iter()
        .map(|entry| entry["bytes_allocated"].as_u64().unwrap())
        .sum()
}

fn assert_runtime_human_output(home: &tempfile::TempDir, tmp: &tempfile::TempDir) {
    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["scan", "--summary", "--runtime"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Detected storage by source:"));
    assert!(stdout.contains("node-runtime (Not managed) by source:"));
    assert!(stdout.contains("tmp"));
}
