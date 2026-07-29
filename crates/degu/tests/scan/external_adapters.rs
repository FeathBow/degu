use super::support::*;

#[test]
fn clean_never_plans_vscode_server_state() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = home.path().canonicalize().unwrap().join(".vscode-server");
    let settings = root.join("data/Machine/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, r#"{"remote.setting":true}"#).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--include-review", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
    let finding = &report["excluded"][0];
    assert_eq!(finding["ecosystem"], "vscode");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(
        finding["disposition"]["reason"],
        "user asset: degu cannot recreate it"
    );
    assert_eq!(finding["recovery"]["kind"], "user_asset");
    assert_eq!(finding["ownership"], "tool_coordinated");
    assert_eq!(finding["hazard"], "active_use");
    assert_eq!(finding["path"], root.display().to_string());
    let rationale = finding["rationale"].as_str().unwrap();
    assert!(rationale.contains("settings") && rationale.contains("extension data"));
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        r#"{"remote.setting":true}"#
    );
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn scan_json_reports_redirected_podman_storage_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let data_home = home.path().join("data");
    std::fs::create_dir_all(&data_home).unwrap();
    let data_home = data_home.canonicalize().unwrap();
    let root = data_home.join("containers/storage");
    std::fs::create_dir_all(root.join("overlay")).unwrap();
    std::fs::write(root.join("overlay/payload"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "podman");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["ownership"], "tool_coordinated");
    assert_eq!(arr[0]["path"], root.display().to_string());
    assert!(
        !arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("relocated via an environment variable degu cannot verify")
    );
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
}

#[test]
fn scan_human_report_only_table_prints_disclaimer_once() {
    let home = tempfile::tempdir().unwrap();
    let data_home = home.path().join("data");
    std::fs::create_dir_all(&data_home).unwrap();
    let data_home = data_home.canonicalize().unwrap();
    let root = data_home.join("containers/storage");
    std::fs::create_dir_all(root.join("overlay")).unwrap();
    std::fs::write(root.join("overlay/payload"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .args(["scan"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Not managed"));
    assert_eq!(
        stdout
            .matches("Reported only; degu never cleans these locations.")
            .count(),
        1
    );
}

#[test]
fn scan_json_reports_docker_desktop_data_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let root = home
        .path()
        .join("Library/Containers/com.docker.docker/Data");
    std::fs::create_dir_all(root.join("vms/0")).unwrap();
    std::fs::write(root.join("vms/0/data.img"), [0u8; 4096]).unwrap();
    let root = home
        .path()
        .canonicalize()
        .unwrap()
        .join("Library/Containers/com.docker.docker/Data");

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "docker");
    assert_eq!(arr[0]["kind"], "container_cache");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["ownership"], "tool_coordinated");
    assert_eq!(arr[0]["path"], root.display().to_string());
    assert!(
        arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("docker system prune")
    );
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
}

#[test]
fn scan_json_reports_rootless_docker_data_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join(".local/share/docker");
    std::fs::create_dir_all(root.join("overlay2")).unwrap();
    std::fs::write(root.join("overlay2/payload"), [0u8; 4096]).unwrap();
    let root = home
        .path()
        .canonicalize()
        .unwrap()
        .join(".local/share/docker");

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "docker");
    assert_eq!(arr[0]["kind"], "container_cache");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["ownership"], "tool_coordinated");
    assert_eq!(arr[0]["path"], root.display().to_string());
    assert!(
        arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("docker system prune")
    );
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
}

#[test]
fn scan_json_reports_orbstack_data_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let root = home
        .path()
        .join("Library/Group Containers/HUAQ24HBR6.dev.orbstack/data");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("machine.img"), [0u8; 4096]).unwrap();
    let root = home
        .path()
        .canonicalize()
        .unwrap()
        .join("Library/Group Containers/HUAQ24HBR6.dev.orbstack/data");

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "orbstack");
    assert_eq!(arr[0]["kind"], "container_cache");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["ownership"], "tool_coordinated");
    assert_eq!(arr[0]["path"], root.display().to_string());
    assert!(
        arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("prune from inside orbstack")
    );
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
}

#[test]
fn scan_json_stays_complete_without_container_storage() {
    let home = tempfile::tempdir().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["ecosystem"] != "docker" && finding["ecosystem"] != "orbstack")
    );
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "complete");
}

#[test]
fn scan_json_reports_local_jax_cache_and_ignores_remote_cache_url() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("jax-cache");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("compiled.bin"), [0u8; 4096]).unwrap();
    let root = root.canonicalize().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("JAX_COMPILATION_CACHE_DIR", &root)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "jax");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], root.display().to_string());

    let out = degu()
        .env("HOME", home.path())
        .env("JAX_COMPILATION_CACHE_DIR", "gs://bucket/jax-cache")
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = &report["findings"];
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["ecosystem"] != "jax")
    );
    assert_eq!(report["completeness"]["findings"], "complete");
    assert!(out.stderr.is_empty());
}

#[test]
fn scan_json_reports_redirected_helm_cache() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("helm-cache");
    std::fs::create_dir_all(root.join("repository")).unwrap();
    std::fs::write(root.join("repository/index.yaml"), [0u8; 4096]).unwrap();
    let root = root.canonicalize().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("HELM_CACHE_HOME", &root)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "helm");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], root.display().to_string());
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
}
