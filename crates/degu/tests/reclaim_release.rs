use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::PathBuf;

/// Runs the real CLI and native release binary against an existing uv cache.
/// The caller supplies an audited binary and controls TMPDIR; no prune is run.
#[test]
#[ignore = "requires DEGU_TEST_UV_EXECUTABLE and DEGU_TEST_UV_CACHE_DIR for uv 0.12.3"]
fn official_uv_release_reaches_a_read_only_preview() {
    let executable = PathBuf::from(
        std::env::var_os("DEGU_TEST_UV_EXECUTABLE")
            .expect("set DEGU_TEST_UV_EXECUTABLE to the official uv 0.12.3 binary"),
    );
    let cache = PathBuf::from(
        std::env::var_os("DEGU_TEST_UV_CACHE_DIR")
            .expect("set DEGU_TEST_UV_CACHE_DIR to an existing uv cache"),
    );
    assert!(executable.is_absolute() && cache.is_absolute());
    let output = Command::cargo_bin("degu")
        .unwrap()
        .env("UV_CACHE_DIR", &cache)
        .args(["reclaim", "uv", "--executable"])
        .arg(&executable)
        .arg("--cache-dir")
        .arg(&cache)
        .args(["--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mode"], "dry_run");
    assert_eq!(report["probe"]["version"], "0.12.3");
    assert_eq!(report["probe"]["arguments"], json!(["-V"]));
    assert_eq!(report["probe"]["uses_private_temporary_snapshot"], true);
    assert_eq!(report["cache_prune"]["start"], "not_started");
    assert_eq!(report["cache_prune"]["status"], "dry_run");
}
