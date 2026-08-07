use super::support::*;

struct Fixture {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            state: tempfile::tempdir().unwrap(),
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn cache(&self) -> std::path::PathBuf {
        let cache = self.root.path().join("__pycache__");
        std::fs::create_dir_all(&cache).unwrap();
        cache
    }

    fn scan(&self) -> serde_json::Value {
        let output = degu()
            .env("HOME", self.home.path())
            .args(["scan", "--json", "--only", "artifacts"])
            .arg(self.root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        scan_findings(&output.stdout)
    }

    fn clean(&self) -> serde_json::Value {
        let output = degu()
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", self.state.path())
            .args(["clean", "--yes", "--purge", "--include-review", "--json"])
            .arg(self.root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn assert_report_only(finding: &serde_json::Value) {
    assert_eq!(finding["ecosystem"], "artifacts");
    assert_eq!(finding["kind"], "other");
    assert_eq!(finding["recovery"]["kind"], "unknown");
    assert_eq!(finding["ownership"], "unknown");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert!(
        finding["rationale"]
            .as_str()
            .unwrap()
            .contains("directory structure")
    );
    assert!(
        !finding["rationale"]
            .as_str()
            .unwrap()
            .contains("CACHEDIR.TAG")
    );
}

fn assert_never_staged(fixture: &Fixture, report: &serde_json::Value) {
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(!fixture.state.path().join("degu/ops.jsonl").exists());
    assert!(!fixture.state.path().join("degu/trash").exists());
}

#[test]
fn pycache_without_bytecode_is_report_only_and_never_staged() {
    let fixture = Fixture::new();
    let cache = fixture.cache();
    let important = cache.join("important.db");
    std::fs::write(&important, b"user-owned data").unwrap();

    let findings = fixture.scan();
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_report_only(&findings[0]);

    let report = fixture.clean();
    assert_never_staged(&fixture, &report);
    assert_eq!(std::fs::read(&important).unwrap(), b"user-owned data");
}

#[test]
fn mixed_pycache_is_report_only_and_never_staged() {
    let fixture = Fixture::new();
    let cache = fixture.cache();
    let important = cache.join("important.db");
    std::fs::write(cache.join("module.cpython-313.pyc"), b"bytecode").unwrap();
    std::fs::write(&important, b"user-owned data").unwrap();

    let findings = fixture.scan();
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_report_only(&findings[0]);

    let report = fixture.clean();
    assert_never_staged(&fixture, &report);
    assert_eq!(std::fs::read(&important).unwrap(), b"user-owned data");
}

#[test]
fn pycache_containing_only_bytecode_remains_eligible() {
    let fixture = Fixture::new();
    let cache = fixture.cache();
    std::fs::write(cache.join("module.cpython-313.pyc"), b"bytecode").unwrap();
    crate::common::make_tree_non_shared_writable(fixture.root.path()).unwrap();

    let findings = fixture.scan();
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["kind"], "build_artifact");
    assert_eq!(findings[0]["disposition"]["mode"], "eligible");

    let report = fixture.clean();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert!(!cache.exists());
}

// A protective-root failure refuses the whole run, so the refusal must name
// the failing path, the OS error, and a first step — not only the adapter id.
#[test]
fn protective_root_refusal_names_the_failing_path_error_and_remedy() {
    let fixture = Fixture::new();
    // Match the refusal's spelling: adapter roots derive from the
    // canonicalized HOME (macOS /var vs /private/var). Put the self-referential
    // symlink at the pip dir the scanner actually probes on this platform.
    let canonical_home = fixture.home.path().canonicalize().unwrap();
    let pip = crate::common::platform_cache_dir(&canonical_home, "pip");
    std::fs::create_dir_all(pip.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&pip, &pip).unwrap();

    let out = degu()
        .env("HOME", fixture.home.path())
        .args(["scan", "--only", "artifacts"])
        .arg(fixture.root.path())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to resolve protective roots for adapter \"pip\""),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("failed to probe cache root {}", pip.display())),
        "the refusal must name the failing path: {stderr}"
    );
    assert!(
        stderr.contains("(os error"),
        "the refusal must carry the OS error: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "fix or remove the symlink at {}, then rerun",
            pip.display()
        )),
        "the refusal must state a first step: {stderr}"
    );
}
