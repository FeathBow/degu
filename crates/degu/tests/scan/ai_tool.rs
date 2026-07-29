use super::support::*;
use degu_core::safety::{MIXED_STATE_AI_TOOL_DIR_NAMES, MIXED_STATE_AI_TOOL_REASON};

#[test]
fn explicit_ai_state_roots_and_descendants_are_rejected() {
    let home = tempfile::tempdir().unwrap();
    for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
        let root = home.path().join(name);
        seed_mixed_state_tree(&root);
        for requested in [&root, &root.join("plugin")] {
            let out = degu()
                .env("HOME", home.path())
                .args(["scan", "--json"])
                .arg(requested)
                .output()
                .unwrap();
            assert_rejected_root(&out, requested);
        }
    }
}

#[test]
fn configured_ai_state_roots_are_rejected() {
    let home = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let roots = MIXED_STATE_AI_TOOL_DIR_NAMES
        .map(|name| {
            let root = home.path().join(name);
            seed_mixed_state_tree(&root);
            format!("\"{}\"", root.display())
        })
        .join(", ");
    write_config(&config, &format!("roots = [{roots}]\n"));

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains(MIXED_STATE_AI_TOOL_REASON));
}

#[test]
fn broader_project_scan_prunes_ai_state_subtrees_before_classification() {
    let home = tempfile::tempdir().unwrap();
    for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
        seed_mixed_state_tree(&home.path().join(name));
    }
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(home.path())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(scan_findings(&out.stdout).as_array().unwrap().is_empty());
}

#[test]
fn artifact_ancestor_cannot_claim_an_ai_state_subtree() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let project = home.path().join("project");
    let target = project.join("target");
    tagged_dir(&target);
    seed_mixed_state_tree(&target.join("nested/.codex"));

    let scan = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(&project)
        .output()
        .unwrap();
    assert!(scan.status.success());
    assert!(scan_findings(&scan.stdout).as_array().unwrap().is_empty());

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--json"])
        .arg(&project)
        .output()
        .unwrap();
    assert_empty_clean(&clean);
    assert!(target.exists());
    assert_no_mutation(&state);
}

#[cfg(unix)]
#[test]
fn external_symlink_spelling_is_rejected_for_explicit_and_config_roots() {
    let home = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    seed_mixed_state_tree(target.path());
    let alias = external.path().join(".claude");
    std::os::unix::fs::symlink(target.path(), &alias).unwrap();

    let explicit = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(&alias)
        .output()
        .unwrap();
    assert_rejected_root(&explicit, &alias);

    write_config(&config, &format!("roots = [\"{}\"]\n", alias.display()));
    let configured = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(!configured.status.success());
    assert!(String::from_utf8_lossy(&configured.stderr).contains(MIXED_STATE_AI_TOOL_REASON));
}

#[test]
fn precise_adapter_leaves_are_report_only_and_never_planned() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
        let cache = seed_tagged_pip_cache(&home.path().join(name));
        assert_report_only_pip_cache(&home, &cache);
        for args in [
            &["clean", "--dry-run", "--json"][..],
            &["clean", "--yes", "--json"][..],
            &["clean", "--yes", "--include-review", "--json"][..],
            &["clean", "--yes", "--purge", "--json"][..],
        ] {
            let clean = degu()
                .env("HOME", home.path())
                .env("XDG_STATE_HOME", state.path())
                .env("PIP_CACHE_DIR", &cache)
                .args(args)
                .output()
                .unwrap();
            assert_empty_clean(&clean);
            let report = json(&clean.stdout);
            assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
            assert_eq!(report["excluded"][0]["disposition"]["mode"], "report_only");
            assert!(cache.exists());
            assert_no_mutation(&state);
        }
    }
}

#[test]
fn redirected_adapter_ancestor_with_ai_state_is_report_only() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("redirected-pip");
    tagged_dir(&cache);
    seed_mixed_state_tree(&cache.join("nested/.hermes"));

    assert_report_only_pip_cache(&home, &cache);
}

#[test]
fn unrelated_local_cache_remains_cleanable() {
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join(".local/share/example-cache");
    let target = project.join("target");
    // Cargo evidence (a sibling `[package]` manifest and a build marker) earns
    // the `target` build-artifact eligibility beyond the bare cache tag.
    tagged_dir(&target);
    std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    let clean = degu()
        .env("HOME", home.path())
        .args(["clean", "--dry-run", "--json"])
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report = json(&clean.stdout);
    assert_eq!(report["planned"].as_array().unwrap().len(), 1);
    assert_eq!(report["planned"][0]["disposition"]["mode"], "eligible");
}

fn seed_mixed_state_tree(root: &std::path::Path) {
    tagged_dir(root);
    tagged_dir(&root.join("plugin/target"));
    let checkpoints = root.join("checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    std::fs::write(checkpoints.join("epoch-1.pt"), [0_u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0_u8; 1024]).unwrap();
}

fn seed_tagged_pip_cache(root: &std::path::Path) -> std::path::PathBuf {
    let cache = root.join("cache/pip");
    tagged_dir(&cache);
    cache
}

fn tagged_dir(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(
        path.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(path.join("payload.bin"), [0_u8; 2048]).unwrap();
}

fn assert_report_only_pip_cache(home: &tempfile::TempDir, cache: &std::path::Path) {
    let scan = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", cache)
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
        .unwrap_or_else(|| panic!("missing pip cache in {findings}"));
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(finding["disposition"]["reason"], MIXED_STATE_AI_TOOL_REASON);
}

fn assert_rejected_root(output: &std::process::Output, root: &std::path::Path) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(MIXED_STATE_AI_TOOL_REASON), "{stderr}");
    assert!(stderr.contains(&root.display().to_string()), "{stderr}");
}

fn assert_empty_clean(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json(&output.stdout);
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
}

fn assert_no_mutation(state: &tempfile::TempDir) {
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

fn write_config(config: &tempfile::TempDir, content: &str) {
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    std::fs::write(config.path().join("degu/config.toml"), content).unwrap();
}

fn json(stdout: &[u8]) -> serde_json::Value {
    serde_json::from_slice(stdout).unwrap()
}
