use super::*;

#[test]
fn disabled_runtime_enumerator_does_not_claim_project_roots() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["tmp"]);
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let target = project.join("target");
    eligible_cargo_target(&target);
    crate::common::make_tree_non_shared_writable(tmp.path()).unwrap();
    let canonical_target = target.canonicalize().unwrap();

    let scan = degu(home.path(), config.path())
        .env("TMPDIR", tmp.path())
        .args(["scan", "--runtime", "--json"])
        .arg(&project)
        .output()
        .unwrap();
    assert!(scan.status.success());
    let report = json_stdout(&scan);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["path"], canonical_target.display().to_string());
    assert_eq!(findings[0]["disposition"]["mode"], "eligible");
    assert!(report["runtime"].as_array().unwrap().is_empty());
}

#[test]
fn disabled_claim_does_not_lower_checkpoint_safety() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["uv"]);
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let checkpoints = root.path().join("run/checkpoints");
    let uv_cache = checkpoints.join("uv-cache");
    tagged_cache(&uv_cache);
    std::fs::create_dir_all(checkpoints.join("node_modules")).unwrap();
    std::fs::write(checkpoints.join("package.json"), "{}").unwrap();
    std::fs::write(checkpoints.join("node_modules/module.js"), [0_u8; 4096]).unwrap();
    std::fs::write(checkpoints.join("epoch-1.pt"), [0_u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0_u8; 1024]).unwrap();
    let canonical_checkpoints = checkpoints.canonicalize().unwrap();

    let command = || {
        let mut cmd = degu(home.path(), config.path());
        cmd.env("XDG_STATE_HOME", state.path())
            .env("UV_CACHE_DIR", &uv_cache);
        cmd
    };
    let scan = command()
        .args(["scan", "--json"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(scan.status.success());
    let findings = json_stdout(&scan)["findings"].as_array().unwrap().clone();
    assert!(findings.is_empty());

    let clean = command()
        .args(["clean", "--dry-run", "--include-review", "--json"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(clean.status.success());
    let report = json_stdout(&clean);
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["excluded"].as_array().unwrap().is_empty());
    assert!(canonical_checkpoints.exists());
}
