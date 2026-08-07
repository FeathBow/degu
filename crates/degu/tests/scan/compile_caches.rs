use super::support::*;

#[test]
fn scan_json_keeps_default_torch_cache_opt_in() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join(".cache/torch");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("model.pt"), [0u8; 8192]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "torch");
    assert_eq!(arr[0]["disposition"]["mode"], "opt_in");
    assert_eq!(arr[0]["recovery"]["kind"], "regenerable");
    assert_eq!(arr[0]["recovery"]["cost"], "costly");
    assert!(
        !arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("relocated via an environment variable degu cannot verify")
    );
}

#[test]
fn scan_json_reports_redirected_vllm_cache() {
    assert_redirected_adapter("VLLM_CACHE_ROOT", "vllm");
}

#[test]
fn scan_json_reports_redirected_triton_cache() {
    assert_redirected_adapter("TRITON_CACHE_DIR", "triton");
}

#[test]
fn scan_json_reports_redirected_torch_cache() {
    assert_redirected_adapter("TORCH_HOME", "torch");
}

#[test]
fn scan_json_reports_unlocked_torchext_version_dirs() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("scratch/torch-extensions");
    let clean = cache.join("py311_cu121/clean_ext");
    let locked = cache.join("py310_cu118/busy_ext");
    std::fs::create_dir_all(&clean).unwrap();
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(clean.join("artifact.so"), [0u8; 4096]).unwrap();
    std::fs::write(locked.join("lock"), []).unwrap();
    std::fs::write(locked.join("artifact.so"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("TORCH_EXTENSIONS_DIR", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "torchext");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["skipped"], 0);
    assert_eq!(arr[0]["age_days"], 0);
    assert_eq!(arr[0]["bytes_hardlinked"], 0);
    assert!(arr[0]["path"].as_str().unwrap().ends_with("py311_cu121"));
}

#[test]
fn scan_json_reports_redirected_cuda_computecache() {
    assert_redirected_adapter("CUDA_CACHE_PATH", "computecache");
}

#[test]
fn scan_json_reports_redirected_ccache() {
    assert_redirected_adapter("CCACHE_DIR", "ccache");
}

#[test]
fn cache_specific_config_does_not_redirect_ccache_root() {
    let home = tempfile::tempdir().unwrap();
    let cache_home = home.path().join("cache-home");
    // ccache honors XDG_CACHE_HOME on every platform (macOS included), so with it
    // set the default cache is $XDG_CACHE_HOME/ccache.
    let default_cache = cache_home.join("ccache");
    let configured_cache = home.path().join("configured-ccache");
    std::fs::create_dir_all(&default_cache).unwrap();
    std::fs::create_dir_all(&configured_cache).unwrap();
    std::fs::write(default_cache.join("default.o"), [0_u8; 2048]).unwrap();
    std::fs::write(configured_cache.join("configured.o"), [0_u8; 4096]).unwrap();
    let config = home.path().join(".config/ccache");
    std::fs::create_dir_all(&config).unwrap();
    let config = config.join("ccache.conf");
    std::fs::write(
        &config,
        format!("cache_dir = {}\n", configured_cache.display()),
    )
    .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("CCACHE_CONFIGPATH", &config)
        .args(["scan", "--only", "ccache", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        std::path::Path::new(arr[0]["path"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        default_cache.canonicalize().unwrap()
    );
}

#[test]
fn scan_json_reports_redirected_sccache() {
    assert_redirected_adapter("SCCACHE_DIR", "sccache");
}

#[test]
fn scan_json_reports_redirected_inductor_cache() {
    assert_redirected_adapter("TORCHINDUCTOR_CACHE_DIR", "inductor");
}

#[test]
fn scan_json_uses_the_first_python_temp_candidate_and_sanitizes_username() {
    let home = tempfile::tempdir().unwrap();
    let primary_temp = home.path().join("primary-temp");
    let fallback_temp = home.path().join("fallback-temp");
    let cache_name = "torchinductor_probe_.._.._victim";
    let cache = primary_temp.join(cache_name);
    let fallback_cache = fallback_temp.join(cache_name);
    let escaped = home.path().join("victim");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&fallback_cache).unwrap();
    std::fs::create_dir_all(primary_temp.join("torchinductor_probe")).unwrap();
    std::fs::create_dir_all(&escaped).unwrap();
    std::fs::write(cache.join("kernel.so"), [0_u8; 4096]).unwrap();
    std::fs::write(fallback_cache.join("kernel.so"), [0_u8; 4096]).unwrap();
    std::fs::write(escaped.join("user-data"), [0_u8; 8192]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", "")
        .env("TEMP", &primary_temp)
        .env("TMP", &fallback_temp)
        .env("LOGNAME", "")
        .env("USER", "probe/../../victim")
        .args(["scan", "--json", "--only", "inductor"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "inductor");
    assert_eq!(arr[0]["confidence"], "verified");
    assert_eq!(arr[0]["disposition"]["mode"], "opt_in");
    assert_eq!(
        std::path::Path::new(arr[0]["path"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        cache.canonicalize().unwrap()
    );
}

#[test]
fn scan_json_reports_redirected_spack_cache() {
    let home = tempfile::tempdir().unwrap();
    let base = home.path().join("scratch/spack");
    let cache = base.join("cache");
    let bootstrap = base.join("bootstrap");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&bootstrap).unwrap();
    std::fs::write(cache.join("index.json"), [0_u8; 4096]).unwrap();
    std::fs::write(bootstrap.join("clingo"), [0_u8; 8192]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("SPACK_USER_CACHE_PATH", &base)
        .args(["scan", "--only", "spack", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "spack");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], cache.display().to_string());
}
