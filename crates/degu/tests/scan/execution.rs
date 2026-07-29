use super::support::*;

#[test]
fn budgeted_scan_preserves_completion_evidence() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--budget", "1h", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
    assert_eq!(arr[0]["truncated"], false);

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip", "--budget", "0s"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let normalized = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized.contains("Scan incomplete: results may be missing."),
        "{stdout}"
    );
    assert!(
        normalized.contains(
            "budget exhausted: results are incomplete. Rerun without --budget or use a longer duration."
        ),
        "{stdout}"
    );
}

#[test]
fn scan_json_honors_disabled_pip_adapter() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let config_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config_home.path().join("degu")).unwrap();
    std::fs::write(
        config_home.path().join("degu/config.toml"),
        "disable = [\"pip\"]\n",
    )
    .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .env("XDG_CONFIG_HOME", config_home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    assert_eq!(findings.as_array().unwrap().len(), 0);
}

#[test]
fn scan_empty_home_finds_nothing() {
    let home = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);
    assert_eq!(report["runtime"].as_array().unwrap().len(), 0);
}

#[test]
fn scan_with_root_keeps_stderr_clean_when_not_tty() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(root.path())
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
}

#[cfg(unix)]
#[test]
fn scan_json_validates_native_unix_environment_values() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let (home, cache) = fake_cache("pip-cache", "wheel.whl", 4096);
    let tmp = home.path().join("tmp");
    let inductor = tmp.join("torchinductor_degu-user");
    std::fs::create_dir_all(&inductor).unwrap();
    std::fs::write(inductor.join("kernel.so"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .env("TMPDIR", &tmp)
        .env("LOGNAME", OsString::from_vec(vec![0xff]))
        .env("USER", "degu-user")
        .env("DEGU_INVALID_ENV", OsString::from_vec(vec![0xff]))
        .env(OsString::from_vec(b"DEGU_\xff".to_vec()), "value")
        .args(["scan", "--json", "--only", "pip", "--only", "inductor"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert_eq!(report["completeness"]["findings"], "incomplete");
}

#[cfg(target_os = "linux")]
#[test]
fn scan_uses_native_linux_environment_path() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join(OsString::from_vec(b"pip-\xff".to_vec()));
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("detected across 1 location"), "{stdout}");
}

#[test]
fn non_directory_adapter_root_is_incomplete_and_cannot_enter_a_clean_plan() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = home.path().join("pip-cache");
    std::fs::write(&cache, "not a directory").unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip", "--json"])
        .output()
        .unwrap();
    assert!(scan.status.success());
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "incomplete");

    let summary = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip", "--summary"])
        .output()
        .unwrap();
    assert!(summary.status.success());
    let summary = String::from_utf8(summary.stdout).unwrap();
    assert!(summary.contains("scan incomplete"), "{summary}");
    assert!(!summary.contains("budget exhausted"), "{summary}");

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["clean", "--only", "pip", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(clean.status.success());
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(report["completeness"], "incomplete");
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(String::from_utf8_lossy(&clean.stderr).contains("cache root is not a directory"));
    assert!(cache.is_file());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn relative_environment_roots_are_incomplete_and_never_cleaned() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cases = [
        ("PIP_CACHE_DIR", "relative-pip", "relative-pip"),
        ("PIP_CACHE_DIR", "~/pip", "~/pip"),
        ("XDG_CACHE_HOME", "relative-xdg", "relative-xdg/pip"),
    ];

    for (variable, value, cache) in cases {
        let cache = workspace.path().join(cache);
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        let payload = cache.join("wheel.whl");
        std::fs::write(&payload, [0_u8; 4096]).unwrap();

        let clean = degu()
            .current_dir(workspace.path())
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .env(variable, value)
            .args(["clean", "--yes", "--json"])
            .output()
            .unwrap();

        assert!(
            clean.status.success(),
            "{}",
            String::from_utf8_lossy(&clean.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
        assert_eq!(report["completeness"], "incomplete");
        assert!(report["planned"].as_array().unwrap().is_empty());
        assert!(report["executed"].as_array().unwrap().is_empty());
        let stderr = String::from_utf8_lossy(&clean.stderr);
        assert_eq!(stderr.matches(variable).count(), 1, "{stderr}");
        assert!(stderr.contains("absolute"), "{stderr}");
        assert!(payload.is_file());
    }

    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}
