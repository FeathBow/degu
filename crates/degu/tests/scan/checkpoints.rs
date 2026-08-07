use super::support::*;

fn checkpoint_cluster_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let checkpoints = root.join("training/checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    std::fs::write(checkpoints.join("epoch-1.ckpt"), [0u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0u8; 2048]).unwrap();
    std::fs::write(checkpoints.join("epoch-3.safetensors"), [0u8; 4096]).unwrap();
    let run = root.join("run-a");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("model-1.pt"), [0u8; 1024]).unwrap();
    std::fs::write(run.join("model-2.PT"), [0u8; 1024]).unwrap();
    std::fs::write(run.join("analysis.py"), [0u8; 128 * 1024]).unwrap();
    let single = root.join("single");
    std::fs::create_dir_all(&single).unwrap();
    std::fs::write(single.join("released.pt"), [0u8; 1024]).unwrap();
    (root_temp, root, run, single)
}

#[test]
fn scan_json_reports_scoped_checkpoint_clusters() {
    let home = tempfile::tempdir().unwrap();
    let (_root_temp, root, run, single) = checkpoint_cluster_fixture();
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let checkpoint_findings = arr
        .iter()
        .filter(|finding| finding["ecosystem"] == "checkpoints")
        .collect::<Vec<_>>();
    assert_eq!(checkpoint_findings.len(), 2);
    assert!(
        checkpoint_findings
            .iter()
            .all(|finding| finding["kind"] == "checkpoint")
    );
    assert!(
        checkpoint_findings
            .iter()
            .all(|finding| finding["disposition"]["mode"] == "report_only")
    );
    assert!(checkpoint_findings.iter().all(|finding| {
        finding["rationale"]
            .as_str()
            .unwrap()
            .contains("degu never deletes training output")
    }));

    let run_finding = checkpoint_findings
        .iter()
        .find(|finding| finding["path"] == run.display().to_string())
        .unwrap();
    assert!(
        run_finding["rationale"]
            .as_str()
            .unwrap()
            .contains("size counts the checkpoint files only, not the directory")
    );
    assert!(run_finding["bytes_apparent"].as_u64().unwrap() < 128 * 1024);
    assert!(
        checkpoint_findings
            .iter()
            .all(|finding| finding["path"] != single.display().to_string())
    );
}

#[test]
fn scan_only_project_source_is_applied_during_discovery() {
    let home = tempfile::tempdir().unwrap();
    let (_root_temp, root, _, _) = checkpoint_cluster_fixture();
    let target = root.join("project/target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.parent().unwrap().join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("artifact.bin"), [0u8; 1024]).unwrap();

    for (source, found, artifacts, checkpoints) in [
        ("checkpoints", "checkpoints", 0, 2),
        ("artifacts", "artifacts", 1, 0),
    ] {
        let out = degu()
            .env("HOME", home.path())
            .args(["-vv", "scan", "--only", source, "--json"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let findings = report["findings"].as_array().unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|finding| finding["ecosystem"] == found));
        assert_eq!(report["completeness"]["findings"], "complete");
        assert_eq!(report["completeness"]["runtime"], "not_requested");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.contains(&format!("artifacts_found={artifacts}")),
            "{stderr}"
        );
        assert!(
            stderr.contains(&format!("checkpoints_found={checkpoints}")),
            "{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn scan_only_project_source_does_not_open_unselected_claims() {
    use std::os::unix::fs::PermissionsExt;

    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "permission-denial coverage requires a non-root test process"
    );
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let checkpoint = root.join("checkpoints");
    std::fs::create_dir(&checkpoint).unwrap();
    std::fs::write(checkpoint.join("model.pt"), [0u8; 1024]).unwrap();
    let artifact = root.join("target");
    std::fs::create_dir(&artifact).unwrap();
    std::fs::write(artifact.join("output"), [0u8; 1024]).unwrap();
    let uv_cache = artifact.join("uv-cache");
    std::fs::create_dir(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive"), [0u8; 1024]).unwrap();
    for path in [&checkpoint, &uv_cache] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }

    let out = degu()
        .env("HOME", home.path())
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--only", "artifacts", "--json"])
        .arg(&root)
        .output()
        .unwrap();
    for path in [&checkpoint, &uv_cache] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    assert!(findings.as_array().unwrap().is_empty());
}

#[test]
fn scan_json_counts_checkpoints_inside_artifact_root_once() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let checkpoint_payload = 1024 + 2048;

    let target = root.join("proj/target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.parent().unwrap().join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("epoch-1.pt"), [0u8; 1024]).unwrap();
    std::fs::write(target.join("epoch-2.pt"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(&root).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(&root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "build_artifact");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert_eq!(arr[0]["path"], target.display().to_string());
    assert!(arr.iter().all(|finding| {
        finding["ecosystem"] != "checkpoints" && finding["kind"] != "checkpoint"
    }));

    let artifact_bytes = arr[0]["bytes_allocated"].as_u64().unwrap();
    let total_bytes = arr
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    assert!(artifact_bytes >= checkpoint_payload);
    assert_eq!(total_bytes, artifact_bytes);
}

#[test]
fn named_checkpoint_claim_precedes_nested_artifact_and_counts_once() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    let checkpoints = root.join("runs/checkpoints");
    std::fs::create_dir_all(checkpoints.join("node_modules")).unwrap();
    std::fs::write(
        checkpoints.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(checkpoints.join("package.json"), "{}").unwrap();
    std::fs::write(checkpoints.join("node_modules/lib.js"), [0u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-1.pt"), [0u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(&root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "checkpoints");
    assert_eq!(arr[0]["kind"], "checkpoint");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], checkpoints.display().to_string());
    assert!(arr.iter().all(|finding| {
        finding["ecosystem"] != "artifacts" && finding["kind"] != "build_artifact"
    }));
}

#[test]
fn bare_scan_reports_no_checkpoints() {
    let home = tempfile::tempdir().unwrap();
    let checkpoints = home.path().join("runs/checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    std::fs::write(checkpoints.join("epoch-1.pt"), [0u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    assert!(findings.as_array().unwrap().iter().all(|finding| {
        finding["ecosystem"] != "checkpoints" && finding["kind"] != "checkpoint"
    }));
}

#[test]
fn scan_summary_json_includes_scoped_checkpoints() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let checkpoints = root.join("run/checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    std::fs::write(checkpoints.join("epoch-1.pt"), [0u8; 1024]).unwrap();
    std::fs::write(checkpoints.join("epoch-2.pt"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--summary", "--json"])
        .arg(&root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ecosystems = report["ecosystems"].as_array().unwrap();
    assert!(
        ecosystems
            .iter()
            .any(|row| row["ecosystem"] == "checkpoints")
    );
}
