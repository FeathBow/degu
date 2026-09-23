use super::support::*;

#[test]
fn scan_json_schema_is_frozen() {
    let home = tempfile::tempdir().unwrap();
    let _cache = fake_pip_cache(&home);
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .args(["scan", "--json"])
            .output()
            .unwrap(),
    );

    assert_keys(&json, SCAN_REPORT_KEYS);
    for finding in assert_non_empty_array(&json["findings"], "scan findings") {
        assert_finding(finding);
    }
    assert_keys(&json["completeness"], SCAN_COMPLETENESS_KEYS);
    assert_eq!(json["completeness"]["findings"], "complete");
    assert_eq!(json["completeness"]["runtime"], "not_requested");
    assert!(json["runtime"].as_array().unwrap().is_empty());
}

#[test]
fn scan_runtime_json_schema_is_frozen() {
    let home = tempfile::tempdir().unwrap();
    let _cache = fake_pip_cache(&home);
    let tmp = stale_tmpdir();
    let json = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("TMPDIR", tmp.path())
            .args([
                "scan",
                "--runtime",
                "--only",
                "pip",
                "--only",
                "tmp",
                "--json",
            ])
            .output()
            .unwrap(),
    );

    assert_keys(&json, SCAN_REPORT_KEYS);
    for finding in assert_non_empty_array(&json["findings"], "scan findings") {
        assert_finding(finding);
    }
    for finding in assert_non_empty_array(&json["runtime"], "scan runtime findings") {
        assert_finding(finding);
    }
    assert_keys(&json["completeness"], SCAN_COMPLETENESS_KEYS);
    // The cache section only sees the fixture, so it is complete or the scan
    // is broken.
    assert_eq!(json["completeness"]["findings"], "complete");
    // The runtime section is not hermetic: degu reaches /tmp and /var/tmp
    // whatever TMPDIR says, so on a shared machine it meets directories it
    // cannot read and correctly reports an incomplete scan. What is frozen
    // here is the spelling, not which of them this host produces.
    assert_completeness(
        &json["completeness"]["runtime"],
        &["truncated", "incomplete", "complete"],
    );
}

fn stale_tmpdir() -> tempfile::TempDir {
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
