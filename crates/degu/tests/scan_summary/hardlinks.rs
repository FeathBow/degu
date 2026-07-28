use super::support::*;

#[test]
fn scan_summary_reports_hardlink_shared_bytes_in_json_and_human_footnote() {
    let home = tempfile::tempdir().unwrap();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    let uv_cache = home.path().join(".cache/uv");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::create_dir_all(&uv_cache).unwrap();
    let pip_file = pip_cache.join("shared.bin");
    std::fs::write(&pip_file, vec![0u8; 4096]).unwrap();
    std::fs::hard_link(&pip_file, uv_cache.join("shared.bin")).unwrap();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--summary", "--json"])
            .output()
            .unwrap(),
    );

    let total = assert_hardlink_totals(&json);
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--summary"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.starts_with("Of which "))
        .unwrap();
    let displayed = line
        .strip_prefix("Of which ")
        .unwrap()
        .strip_suffix(
            " is hardlink-shared; entries sharing links may sum above physical filesystem usage",
        )
        .unwrap();
    assert_human_bytes(displayed, total);
}

fn assert_hardlink_totals(json: &serde_json::Value) -> u64 {
    let pip = row(json, "pip")["bytes_hardlinked"].as_u64().unwrap();
    let uv = row(json, "uv")["bytes_hardlinked"].as_u64().unwrap();
    let total = json["total"]["bytes_hardlinked"].as_u64().unwrap();
    assert!(pip > 0);
    assert!(uv > 0);
    assert_eq!(total, pip + uv);
    total
}
