use super::support::*;

#[test]
fn clean_never_enables_runtime_adapters_even_with_config_runtime_true() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let pip = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), [0u8; 2048]).unwrap();
    let (tmp, _stale_file) = fake_stale_tmpdir();
    let config_home = runtime_config_home("runtime = true\n");

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!report["planned"].as_array().unwrap().is_empty());
    for member in ["planned", "excluded"] {
        assert!(
            report[member]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["ecosystem"] != "tmp" && finding["ecosystem"] != "shm")
        );
    }
}

#[test]
fn only_runtime_adapter_requires_runtime_on_scan_and_always_errors_on_clean() {
    let home = tempfile::tempdir().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "tmp", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tmp is a node-runtime adapter; enable it with --runtime (scan only)"));

    let config_home = runtime_config_home("runtime = true\n");
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .args(["clean", "--only", "tmp", "--dry-run"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tmp is a node-runtime adapter; enable it with --runtime (scan only)"));
}

#[test]
fn runtime_only_selection_omits_unrequested_cache_findings() {
    let home = tempfile::tempdir().unwrap();
    let json = degu()
        .env("HOME", home.path())
        .env("SLURM_JOB_ID", "123")
        .args(["scan", "--runtime", "--only", "tmp", "--json"])
        .output()
        .unwrap();

    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["completeness"]["findings"], "not_requested");
    assert!(report["findings"].as_array().unwrap().is_empty());

    let human = degu()
        .env("HOME", home.path())
        .env("SLURM_JOB_ID", "123")
        .args(["scan", "--runtime", "--only", "tmp"])
        .output()
        .unwrap();
    assert!(human.status.success());
    let stdout = String::from_utf8(strip_sgr(&human.stdout)).unwrap();
    assert!(stdout.contains("No node-runtime locations detected."));
    assert!(!stdout.contains("No locations matched the selected sources"));
    assert!(!stdout.contains("No storage detected by degu"));
}

#[test]
fn cache_only_selection_does_not_report_or_scan_runtime() {
    let home = tempfile::tempdir().unwrap();
    let pip = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), [0u8; 2048]).unwrap();
    let (tmp, _stale_file) = fake_stale_tmpdir();

    let human = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["scan", "--runtime", "--only", "pip"])
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(
        !String::from_utf8(human.stdout)
            .unwrap()
            .contains("node-runtime")
    );

    let json = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["-v", "scan", "--runtime", "--only", "pip", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["completeness"]["runtime"], "not_requested");
    assert!(report["runtime"].as_array().unwrap().is_empty());
    let stderr = String::from_utf8(json.stderr).unwrap();
    assert!(!stderr.contains(tmp.path().to_str().unwrap()), "{stderr}");
}

#[test]
fn disabled_runtime_adapter_beats_the_runtime_flag() {
    let home = tempfile::tempdir().unwrap();
    let (tmp, _stale_file) = fake_stale_tmpdir();
    let config_home = runtime_config_home("disable = [\"tmp\"]\n");

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .args(["scan", "--runtime", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["runtime"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["ecosystem"] != "tmp")
    );
}
