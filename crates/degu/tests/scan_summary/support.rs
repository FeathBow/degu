pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::human_bytes::assert_human_bytes;
pub(super) use crate::strip_sgr::strip_sgr;
use serde_json::Value;

pub(super) fn json_stdout(out: std::process::Output) -> Value {
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

pub(super) fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub(super) fn row<'a>(json: &'a Value, ecosystem: &str) -> &'a Value {
    json["ecosystems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["ecosystem"] == ecosystem)
        .unwrap_or_else(|| panic!("missing ecosystem {ecosystem} in {json:#}"))
}

pub(super) fn fake_stale_tmpdir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let stale_file = tmp.path().join("old.tmp");
    std::fs::write(&stale_file, [0u8; 4096]).unwrap();
    let age = std::time::Duration::from_secs(11 * 24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(&stale_file)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - age)
        .unwrap();
    tmp
}

pub(super) fn assert_block_shares_self_consistent(rows: &[Value], block_total: u64) {
    if rows.is_empty() {
        return;
    }
    let mut share_sum = 0.0;
    for entry in rows {
        let bytes = entry["bytes_allocated"].as_u64().unwrap();
        let share = entry["share"].as_f64().unwrap();
        assert!(
            (share - bytes as f64 / block_total as f64).abs() < 0.000_001,
            "share {share} inconsistent with {bytes}/{block_total}"
        );
        share_sum += share;
    }
    assert!(
        (share_sum - 1.0).abs() < 0.000_001,
        "shares within a block must sum to 1.0, got {share_sum}"
    );
}

pub(super) fn seed_pip_uv(home: &tempfile::TempDir) {
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    let uv_cache = home.path().join(".cache/uv");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), [0u8; 4096]).unwrap();
}
