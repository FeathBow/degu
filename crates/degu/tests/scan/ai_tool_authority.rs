use super::support::*;
use degu_core::safety::{MIXED_STATE_AI_TOOL_REASON, PROTECTED_CREDENTIAL_REASON};

#[test]
fn well_known_cache_with_ai_state_descendant_is_report_only() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = default_pip_cache(&home);
    std::fs::create_dir_all(cache.join("sessions/.claude")).unwrap();
    std::fs::write(cache.join("sessions/.claude/state.json"), "{}").unwrap();

    assert_report_only_pip(&home, &cache);
    assert_never_planned(&home, &state, &cache);
}

#[cfg(unix)]
#[test]
fn home_ai_symlink_target_inside_cache_is_report_only() {
    let home = tempfile::tempdir().unwrap();
    let cache = default_pip_cache(&home);
    let state = cache.join("agent-state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("session.json"), "{}").unwrap();
    std::os::unix::fs::symlink(&state, home.path().join(".claude")).unwrap();

    assert_report_only_pip(&home, &cache);
}

#[cfg(unix)]
#[test]
fn clean_rejects_ai_roots_descendants_and_canonical_aliases_before_mutation() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let exact = home.path().join(".claude");
    let descendant = home.path().join(".codex/cache");
    std::fs::create_dir_all(&exact).unwrap();
    std::fs::create_dir_all(&descendant).unwrap();
    std::fs::write(exact.join("session.json"), "{}").unwrap();
    std::fs::write(descendant.join("index.json"), "{}").unwrap();

    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("memory.db"), "state").unwrap();
    std::os::unix::fs::symlink(target.path(), home.path().join(".hermes")).unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("agent-state");
    std::os::unix::fs::symlink(target.path(), &alias).unwrap();

    for root in [&exact, &descendant, &alias] {
        assert_clean_root_rejected(&home, &state, root);
    }
    assert!(exact.exists() && descendant.exists() && target.path().exists());
}

#[test]
fn protection_is_applied_per_huggingface_candidate() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    let protected = hub.join("models--org--protected");
    let ordinary = hub.join("models--org--ordinary");
    seed_huggingface_repo(&protected);
    seed_huggingface_repo(&ordinary);
    std::fs::create_dir_all(protected.join(".codex")).unwrap();
    std::fs::write(protected.join(".codex/session.json"), "{}").unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let protected = find_path_suffix(&findings, "models--org--protected");
    let ordinary = find_path_suffix(&findings, "models--org--ordinary");
    assert_eq!(protected["disposition"]["mode"], "report_only");
    assert_eq!(
        protected["disposition"]["reason"],
        MIXED_STATE_AI_TOOL_REASON
    );
    assert_eq!(ordinary["disposition"]["mode"], "opt_in");
}

#[test]
fn nested_credential_directory_strips_cache_cleanup_authority() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = default_pip_cache(&home);
    let fixture = cache.join("fixtures/.ssh");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("id_rsa"), "fixture").unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = scan_findings(&scan.stdout);
    let finding = findings
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap_or_else(|| panic!("missing pip finding in {findings}"));
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(
        finding["disposition"]["reason"],
        PROTECTED_CREDENTIAL_REASON
    );

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report = json(&clean.stdout);
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
}

fn default_pip_cache(home: &tempfile::TempDir) -> std::path::PathBuf {
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0_u8; 4096]).unwrap();
    cache
}

fn assert_report_only_pip(home: &tempfile::TempDir, cache: &std::path::Path) {
    let scan = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = scan_findings(&scan.stdout);
    let finding = findings
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap_or_else(|| panic!("missing pip finding in {findings}"));
    assert_eq!(
        finding["path"],
        cache.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(finding["disposition"]["reason"], MIXED_STATE_AI_TOOL_REASON);
}

fn assert_never_planned(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    cache: &std::path::Path,
) {
    for args in [
        &["clean", "--dry-run", "--json"][..],
        &["clean", "--yes", "--json"][..],
        &["clean", "--yes", "--include-review", "--json"][..],
        &["clean", "--yes", "--purge", "--json"][..],
    ] {
        let clean = degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            clean.status.success(),
            "{}",
            String::from_utf8_lossy(&clean.stderr)
        );
        let report = json(&clean.stdout);
        assert!(report["planned"].as_array().unwrap().is_empty());
        assert!(report["executed"].as_array().unwrap().is_empty());
        assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
        assert!(cache.exists());
        assert!(!state.path().join("degu/trash").exists());
        assert!(!state.path().join("degu/ops.jsonl").exists());
    }
}

fn assert_clean_root_rejected(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    root: &std::path::Path,
) {
    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .arg(root)
        .output()
        .unwrap();
    assert!(!clean.status.success());
    assert!(clean.stdout.is_empty());
    let stderr = String::from_utf8(clean.stderr).unwrap();
    assert!(stderr.contains("project root"), "{stderr}");
    assert!(stderr.contains(MIXED_STATE_AI_TOOL_REASON), "{stderr}");
    assert!(!stderr.contains("scan root"), "{stderr}");
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

fn seed_huggingface_repo(repo: &std::path::Path) {
    let snapshot = repo.join("snapshots/main");
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(snapshot.join("model.bin"), [0_u8; 4096]).unwrap();
}

fn find_path_suffix<'a>(findings: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    findings
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| {
            finding["ecosystem"] == "huggingface"
                && finding["path"].as_str().unwrap().ends_with(suffix)
        })
        .unwrap_or_else(|| panic!("missing {suffix} in {findings}"))
}

fn json(stdout: &[u8]) -> serde_json::Value {
    serde_json::from_slice(stdout).unwrap()
}
