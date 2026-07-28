use super::support::*;

#[test]
fn scan_json_reports_redirected_pip_cache() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(
        arr[0]["disposition"]["reason"],
        "relocated via an environment variable degu cannot verify"
    );
    assert_eq!(arr[0]["inodes"], 2);
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 2048);
    assert!(arr[0]["bytes_allocated"].as_u64().unwrap() >= 2048);
}

#[test]
fn scan_json_keeps_default_pip_cache_eligible() {
    let home = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert_eq!(arr[0]["recovery"]["kind"], "regenerable");
    assert_eq!(arr[0]["recovery"]["cost"], "cheap");
    assert_eq!(arr[0]["confidence"], "verified");
    assert!(
        !arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("relocated via an environment variable degu cannot verify")
    );
}

#[test]
fn scan_json_keeps_env_derived_xdg_cache_pip_verified_and_eligible() {
    // Pins the XDG well-known boundary: `XDG_CACHE_HOME` is a cache base by
    // spec, so a fixed ecosystem subdirectory beneath an env-set, absolute
    // base stays verified and eligible even with no CACHEDIR.TAG. Relocating
    // the cache this way (`XDG_CACHE_HOME=/scratch/$USER/cache`) is the
    // sanctioned HPC pattern; gating well-known bases on a marker they never
    // write would silently demote it to report_only and stop degu from
    // cleaning the caches its users most want cleaned.
    let home = tempfile::tempdir().unwrap();
    let xdg = home.path().join("scratch-cache");
    let cache = xdg.join("pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", &xdg)
        .args(["scan", "--only", "pip", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
    assert_eq!(arr[0]["confidence"], "verified");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert!(
        !arr[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("relocated via an environment variable degu cannot verify")
    );
}

#[test]
fn scan_json_keeps_default_go_build_cache_eligible() {
    let home = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "go-build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("artifact.a"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "go-build");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert_eq!(arr[0]["kind"], "build_artifact");
}

#[test]
fn scan_json_reports_redirected_go_build_cache_as_report_only_without_cachedir_tag() {
    assert_redirected_adapter("GOCACHE", "go-build");
}

#[test]
fn scan_json_reports_redirected_pixi_cache() {
    assert_redirected_adapter("PIXI_CACHE_DIR", "pixi");
}

// When both exist, pixi's precedence is $XDG_CACHE_HOME/pixi first, so degu must
// report only that -- reporting the rattler default too would misstate the cache.
#[test]
fn scan_json_prefers_xdg_pixi_cache_over_rattler_default() {
    let home = tempfile::tempdir().unwrap();
    let xdg = home.path().join("xdg-cache");
    let pixi_cache = xdg.join("pixi");
    #[cfg(target_os = "macos")]
    let rattler_cache = home.path().join("Library/Caches/rattler/cache");
    #[cfg(not(target_os = "macos"))]
    let rattler_cache = xdg.join("rattler/cache");
    std::fs::create_dir_all(&pixi_cache).unwrap();
    std::fs::create_dir_all(&rattler_cache).unwrap();
    std::fs::write(pixi_cache.join("repodata.json"), [0_u8; 4096]).unwrap();
    std::fs::write(rattler_cache.join("package.conda"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", &xdg)
        .args(["scan", "--only", "pixi", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let paths = arr
        .iter()
        .map(|finding| {
            std::path::Path::new(finding["path"].as_str().unwrap())
                .canonicalize()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(arr.len(), 1);
    assert!(paths.contains(&pixi_cache.canonicalize().unwrap()));
    assert!(!paths.contains(&rattler_cache.canonicalize().unwrap()));
}

#[test]
fn scan_json_falls_back_to_rattler_default_without_xdg_pixi() {
    let home = tempfile::tempdir().unwrap();
    let rattler_cache = crate::common::platform_cache_dir(home.path(), "rattler/cache");
    std::fs::create_dir_all(&rattler_cache).unwrap();
    std::fs::write(rattler_cache.join("package.conda"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .args(["scan", "--only", "pixi", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        std::path::Path::new(arr[0]["path"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        rattler_cache.canonicalize().unwrap()
    );
}

// Even without XDG_CACHE_HOME set, pixi uses the platform-default `pixi` dir
// before the rattler default, so degu must report only the former.
#[test]
fn scan_json_prefers_native_pixi_cache_over_rattler_without_xdg() {
    let home = tempfile::tempdir().unwrap();
    let pixi_cache = crate::common::platform_cache_dir(home.path(), "pixi");
    let rattler_cache = crate::common::platform_cache_dir(home.path(), "rattler/cache");
    std::fs::create_dir_all(&pixi_cache).unwrap();
    std::fs::create_dir_all(&rattler_cache).unwrap();
    std::fs::write(pixi_cache.join("repodata.json"), [0_u8; 4096]).unwrap();
    std::fs::write(rattler_cache.join("package.conda"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .args(["scan", "--only", "pixi", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let paths = arr
        .iter()
        .map(|finding| {
            std::path::Path::new(finding["path"].as_str().unwrap())
                .canonicalize()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(arr.len(), 1);
    assert!(paths.contains(&pixi_cache.canonicalize().unwrap()));
    assert!(!paths.contains(&rattler_cache.canonicalize().unwrap()));
}

#[test]
fn scan_json_pixi_cache_dir_takes_precedence_over_rattler_cache_dir() {
    let home = tempfile::tempdir().unwrap();
    let pixi_cache = home.path().join("scratch/pixi-cache");
    let rattler_cache = home.path().join("scratch/rattler-cache");
    std::fs::create_dir_all(&pixi_cache).unwrap();
    std::fs::create_dir_all(&rattler_cache).unwrap();
    std::fs::write(pixi_cache.join("pixi.conda"), [0u8; 4096]).unwrap();
    std::fs::write(rattler_cache.join("rattler.conda"), [0u8; 8192]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIXI_CACHE_DIR", &pixi_cache)
        .env("RATTLER_CACHE_DIR", &rattler_cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pixi");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], pixi_cache.display().to_string());
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096);
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() < 8192);
}

#[test]
fn scan_json_reports_redirected_npm_cache() {
    let (home, cache) = fake_cache("npm-cache", "pkg.tgz", 2048);

    let out = degu()
        .env("HOME", home.path())
        .env("npm_config_cache", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "npm");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["inodes"], 2);
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 2048);
}

#[test]
fn scan_json_reports_uppercase_redirected_npm_cache() {
    assert_redirected_adapter("NPM_CONFIG_CACHE", "npm");
}

#[cfg(unix)]
#[test]
fn conflicting_npm_cache_spellings_are_reported_without_dropping_roots() {
    let home = tempfile::tempdir().unwrap();
    let lowercase = home.path().join("lowercase-cache");
    let uppercase = home.path().join("uppercase-cache");
    std::fs::create_dir_all(&lowercase).unwrap();
    std::fs::create_dir_all(&uppercase).unwrap();
    std::fs::write(lowercase.join("lowercase.tgz"), [0_u8; 2048]).unwrap();
    std::fs::write(uppercase.join("uppercase.tgz"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("npm_config_cache", &lowercase)
        .env("NPM_CONFIG_CACHE", &uppercase)
        .args(["scan", "--only", "npm", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["completeness"]["findings"], "incomplete");
    let paths = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["path"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(lowercase.to_str().unwrap()));
    assert!(paths.contains(uppercase.to_str().unwrap()));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("npm_config_cache") && stderr.contains("NPM_CONFIG_CACHE"));
}
