pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::next_command::assert_next_command;
pub(super) use crate::strip_sgr::strip_sgr;

pub(super) const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Parses a `scan --json` report and returns its `findings` member; scan
/// emits `{"findings": [...], "runtime": [...]}`.
pub(super) fn scan_findings(stdout: &[u8]) -> serde_json::Value {
    let report: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    report["findings"].clone()
}

pub(super) fn fake_cache(
    cache_subdir: &str,
    filename: &str,
    bytes: usize,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join(cache_subdir);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join(filename), vec![0u8; bytes]).unwrap();
    (home, cache)
}

pub(super) fn assert_redirected_adapter(env_key: &str, ecosystem: &str) {
    let (home, cache) = fake_cache(&format!("scratch/{ecosystem}-cache"), "artifact.bin", 4096);

    let out = degu()
        .env("HOME", home.path())
        .env(env_key, &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], ecosystem);
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["confidence"], "unverified");
    assert_eq!(arr[0]["recovery"]["kind"], "regenerable");
    assert_eq!(
        arr[0]["disposition"]["reason"],
        "relocated via an environment variable degu cannot verify"
    );
    assert_eq!(arr[0]["skipped"], 0);
    assert_eq!(arr[0]["age_days"], 0);
    assert_eq!(arr[0]["bytes_hardlinked"], 0);
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
    assert!(arr[0]["bytes_allocated"].as_u64().unwrap() >= 4096);
}
