use super::support::*;

#[test]
fn scan_summary_json_rolls_up_two_ecosystems_by_bytes_and_inodes() {
    let home = tempfile::tempdir().unwrap();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    let uv_cache = home.path().join(".cache/uv");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0u8; 1024]).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), vec![0u8; 128 * 1024]).unwrap();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--summary", "--json"])
            .output()
            .unwrap(),
    );

    assert_rollup(&json);
}

fn assert_rollup(json: &serde_json::Value) {
    let ecosystems = json["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 2);
    assert_eq!(ecosystems[0]["ecosystem"], "uv");
    assert_eq!(ecosystems[1]["ecosystem"], "pip");
    assert_eq!(json["truncated"], false);
    let uv_bytes = row(json, "uv")["bytes_allocated"].as_u64().unwrap();
    let pip_bytes = row(json, "pip")["bytes_allocated"].as_u64().unwrap();
    let uv_inodes = row(json, "uv")["inodes"].as_u64().unwrap();
    let pip_inodes = row(json, "pip")["inodes"].as_u64().unwrap();
    let total_bytes = json["total"]["bytes_allocated"].as_u64().unwrap();
    assert!(uv_bytes >= pip_bytes);
    assert!(uv_bytes >= 128 * 1024);
    assert!(pip_bytes >= 1024);
    assert_eq!((pip_inodes, uv_inodes), (2, 2));
    assert_eq!(total_bytes, pip_bytes + uv_bytes);
    assert_eq!(json["total"]["inodes"], pip_inodes + uv_inodes);
    let shares =
        row(json, "uv")["share"].as_f64().unwrap() + row(json, "pip")["share"].as_f64().unwrap();
    assert!((shares - 1.0).abs() < 0.000_001);
    let uv_share = row(json, "uv")["share"].as_f64().unwrap();
    assert!((uv_share - uv_bytes as f64 / total_bytes as f64).abs() < 0.000_001);
}

#[test]
fn scan_summary_includes_report_only_conda_environments() {
    let home = tempfile::tempdir().unwrap();
    let env = home.path().join("miniconda3/envs/myenv");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
    std::fs::write(env.join("python"), [0u8; 4096]).unwrap();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--summary", "--json"])
            .output()
            .unwrap(),
    );
    let conda = row(&json, "conda");
    assert!(conda["bytes_allocated"].as_u64().unwrap() >= 4096);
    assert!(conda["inodes"].as_u64().unwrap() >= 3);
}

#[test]
fn scan_summary_json_empty_case_is_zero_envelope() {
    let home = tempfile::tempdir().unwrap();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--summary", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(json["ecosystems"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"]["bytes_allocated"], 0);
    assert_eq!(json["total"]["bytes_hardlinked"], 0);
    assert_eq!(json["total"]["inodes"], 0);
    assert_eq!(json["truncated"], false);
}
