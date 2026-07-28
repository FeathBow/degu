//! A finding whose path is not valid UTF-8 must not fail the whole `scan --json`
//! report: it is omitted and its section marked incomplete, so every other
//! finding survives.
//!
//! Linux only: macOS/APFS rejects non-UTF-8 filenames with EILSEQ, so the bad
//! path cannot be created there.
#![cfg(target_os = "linux")]

use super::support::*;
use std::os::unix::ffi::OsStrExt;

#[test]
fn scan_json_omits_non_utf8_finding_and_marks_incomplete() {
    let home = tempfile::tempdir().unwrap();
    // A pip cache directory whose leaf name is valid on Unix but not UTF-8.
    let mut name = std::ffi::OsString::from("pip-cache-");
    name.push(std::ffi::OsStr::from_bytes(&[0xff]));
    let cache = home.path().join(name);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "one non-UTF-8 path must not crash the report; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["findings"].as_array().unwrap().is_empty(),
        "the unrepresentable finding must be omitted: {report}"
    );
    assert_eq!(
        report["completeness"]["findings"], "incomplete",
        "omitting a finding must mark the section incomplete: {report}"
    );
}
