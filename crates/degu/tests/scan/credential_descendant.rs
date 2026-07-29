//! A cleanable cache carrying a nested credential directory (`.ssh`, `.aws`,
//! `.gnupg`, ...) must be demoted to report-only and never planned, mirroring
//! the mixed-state AI tool descendant protection. See issue #245.

use super::support::*;
use degu_core::safety::{CREDENTIAL_DIR_NAMES, PROTECTED_CREDENTIAL_REASON};

#[test]
fn cache_with_nested_credential_dir_is_report_only_and_never_planned() {
    for name in CREDENTIAL_DIR_NAMES {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let cache = seed_tagged_pip_cache(home.path());
        seed_credential_dir(&cache.join("nested").join(name));

        let scan = degu()
            .env("HOME", home.path())
            .env("PIP_CACHE_DIR", &cache)
            .args(["scan", "--json"])
            .output()
            .unwrap();
        assert!(
            scan.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        let finding = pip_finding(&scan.stdout);
        assert_eq!(finding["disposition"]["mode"], "report_only", "{name}");
        assert_eq!(
            finding["disposition"]["reason"], PROTECTED_CREDENTIAL_REASON,
            "{name}"
        );
        assert!(
            finding["skipped"].as_u64().unwrap() > 0,
            "{name}: skipped must count the protected boundary"
        );

        let clean = degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .env("PIP_CACHE_DIR", &cache)
            .args(["clean", "--dry-run", "--json"])
            .output()
            .unwrap();
        assert!(
            clean.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&clean.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
        assert!(
            report["planned"].as_array().unwrap().is_empty(),
            "{name}: credential-bearing cache must not be planned: {report}"
        );
        assert!(report["executed"].as_array().unwrap().is_empty(), "{name}");
        assert!(cache.exists(), "{name}");
        assert!(
            !state.path().join("degu/trash").exists(),
            "{name}: nothing must be staged"
        );
    }
}

fn seed_tagged_pip_cache(home: &std::path::Path) -> std::path::PathBuf {
    let cache = home.join("cache/pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(cache.join("payload.bin"), [0_u8; 2048]).unwrap();
    cache
}

fn seed_credential_dir(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("secret"), [0_u8; 64]).unwrap();
}

fn pip_finding(stdout: &[u8]) -> serde_json::Value {
    let findings = scan_findings(stdout);
    findings
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap_or_else(|| panic!("missing pip cache in {findings}"))
        .clone()
}
