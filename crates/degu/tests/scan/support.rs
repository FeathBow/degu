pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::human_bytes::{assert_human_bytes, parse_human_bytes};
pub(super) use crate::next_command::assert_next_command;
pub(super) use crate::sgr_assertion::assert_sgr_color;
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

pub(super) fn parse_summary_sizes(output: &str) -> (f64, f64, f64, f64) {
    (
        headline_size(output),
        group_header_size(output, "Ready to clean - "),
        group_header_size(output, "Needs review - "),
        group_header_size(output, "Not managed - "),
    )
}

fn headline_size(output: &str) -> f64 {
    let value = output
        .lines()
        .find_map(|line| line.split_once(" detected across").map(|(value, _)| value))
        .unwrap_or_else(|| panic!("missing detected-space headline in {output}"));
    parse_human_bytes(value)
}

/// Group headers read "<label> - <count> locations - <size>" under a pipe; a
/// group with no findings prints no header and counts as zero bytes.
fn group_header_size(output: &str, label: &str) -> f64 {
    output
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .and_then(|rest| rest.rsplit(" - ").next())
        .map_or(0.0, parse_human_bytes)
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

/// A TMPDIR fixture holding one stale (11 days old) file the tmp adapter
/// reports when node-runtime diagnostics are enabled. Returns the canonical
/// stale path because the tmp adapter canonicalizes its roots.
pub(super) fn fake_stale_tmpdir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let stale_file = tmp.path().join("old.tmp");
    std::fs::write(&stale_file, [0u8; 4096]).unwrap();
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(&stale_file)
        .unwrap()
        .set_modified(stale)
        .unwrap();
    (tmp, stale_file.canonicalize().unwrap())
}

pub(super) fn runtime_config_home(config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("degu")).unwrap();
    std::fs::write(dir.path().join("degu/config.toml"), config).unwrap();
    dir
}
