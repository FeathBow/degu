use super::support::*;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

#[cfg(unix)]
#[test]
fn clean_purge_unlinks_descendant_symlink_without_touching_its_target() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let (cache, _) = fake_pip_cache(&home, ".cache/pip");
    let victim = external.path().join("keep.txt");
    std::fs::write(&victim, "must survive").unwrap();
    std::os::unix::fs::symlink(external.path(), cache.join("external-link")).unwrap();

    let out = run_clean(&home, &state, &["clean", "--purge", "--yes", "--json"]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!cache.exists());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "must survive");
}

#[cfg(unix)]
#[test]
fn clean_rejects_canonical_alias_overlap_before_mutation() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let cache = home.path().join("shared-cache");
    let alias_parent = aliases.path().join("home-alias");
    let alias = alias_parent.join("shared-cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    let payload = cache.join("payload");
    std::fs::write(&payload, [0_u8; 4096]).unwrap();
    std::os::unix::fs::symlink(home.path(), &alias_parent).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", &cache)
        .env("TORCH_HOME", &alias)
        .args(["clean", "--include-review", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("overlap after canonicalization"),
        "{stderr}"
    );
    assert!(stderr.contains(&cache.display().to_string()), "{stderr}");
    assert!(stderr.contains(&alias.display().to_string()), "{stderr}");
    assert!(cache.exists() && payload.exists());
    assert!(alias.exists());
    let alias_metadata = std::fs::symlink_metadata(&alias_parent).unwrap();
    assert!(alias_metadata.file_type().is_symlink());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(unix)]
#[test]
fn final_symlink_adapter_root_is_incomplete_and_never_cleaned() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let alias = home.path().join("pip-cache");
    std::fs::write(
        target.path().join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    let payload = target.path().join("payload");
    std::fs::write(&payload, [0_u8; 4096]).unwrap();
    std::os::unix::fs::symlink(target.path(), &alias).unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &alias)
        .args(["scan", "--only", "pip", "--json"])
        .output()
        .unwrap();
    assert!(scan.status.success());
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "incomplete");

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", &alias)
        .args(["clean", "--only", "pip", "--purge", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(clean.status.success());
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(report["completeness"], "incomplete");
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(String::from_utf8_lossy(&clean.stderr).contains("symlink adapter root refused"));
    let alias_metadata = std::fs::symlink_metadata(&alias).unwrap();
    assert!(alias_metadata.file_type().is_symlink());
    assert!(payload.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(unix)]
#[test]
fn clean_stages_a_cache_beneath_a_symlinked_xdg_parent() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let real_cache_home = tempfile::tempdir().unwrap();
    let alias_parent = tempfile::tempdir().unwrap();
    let cache_alias = alias_parent.path().join("cache");
    std::os::unix::fs::symlink(real_cache_home.path(), &cache_alias).unwrap();
    let cache = real_cache_home.path().join("pip");
    std::fs::create_dir(&cache).unwrap();
    let expected = [7_u8; 2048];
    std::fs::write(cache.join("wheel.whl"), expected).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", &cache_alias)
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!cache.exists());
    let entries = visible_trash_entries(&state.path().join("degu/trash"));
    assert_eq!(entries.len(), 1);
    assert_eq!(
        std::fs::read(entries[0].join("wheel.whl")).unwrap(),
        expected
    );
}

#[test]
fn clean_guard_abort_rejects_protected_paths_before_mutation_or_logging() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = home.path().join(".ssh/project");
    let target = root.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("artifact.o"), [0u8; 2048]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(target.exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn relative_xdg_config_home_cannot_bypass_home_protection() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    let cache_subdir = "Library/Caches/pip";
    #[cfg(not(target_os = "macos"))]
    let cache_subdir = ".cache/pip";
    let (cache, _) = fake_pip_cache(&home, cache_subdir);
    std::fs::create_dir_all(home.path().join(".config/degu")).unwrap();
    std::fs::write(
        home.path().join(".config/degu/config.toml"),
        format!("protect = [\"{cache_subdir}\"]\n"),
    )
    .unwrap();

    let out = degu()
        .current_dir(work.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "relative-missing")
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(cache.exists());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("protected"),
        "expected protected-path refusal, got: {stderr}"
    );
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn clean_config_protect_rejects_cache_before_mutation_or_logging() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    // The protect config must name the pip dir the scanner actually probes here.
    #[cfg(target_os = "macos")]
    let cache_subdir = "Library/Caches/pip";
    #[cfg(not(target_os = "macos"))]
    let cache_subdir = ".cache/pip";
    let (cache, _) = fake_pip_cache(&home, cache_subdir);
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    std::fs::write(
        config.path().join("degu/config.toml"),
        format!("protect = [\"{cache_subdir}\"]\n"),
    )
    .unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(cache.exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(unix)]
#[test]
fn clean_rejects_symlink_spelling_protected_cache_before_mutation_or_logging() {
    let real_home = tempfile::tempdir().unwrap();
    let link_parent = tempfile::tempdir().unwrap();
    let home_link = link_parent.path().join("home-link");
    std::os::unix::fs::symlink(real_home.path(), &home_link).unwrap();
    // Seed and protect the pip dir the scanner probes on this platform.
    #[cfg(target_os = "macos")]
    let cache_subdir = "Library/Caches/pip";
    #[cfg(not(target_os = "macos"))]
    let cache_subdir = ".cache/pip";
    let cache = home_link.join(cache_subdir);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    std::fs::create_dir_all(real_home.path().join(".config/degu")).unwrap();
    std::fs::write(
        real_home.path().join(".config/degu/config.toml"),
        format!("protect = [\"{cache_subdir}\"]\n"),
    )
    .unwrap();
    let out = degu()
        .env("HOME", &home_link)
        .env("XDG_CONFIG_HOME", real_home.path().join(".config"))
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(cache.exists());
    assert!(!real_home.path().join(".local/state/degu/trash").exists());
    assert!(
        !real_home
            .path()
            .join(".local/state/degu/ops.jsonl")
            .exists()
    );
}

#[test]
fn clean_rejects_invalid_protect_entry_before_mutation_or_logging() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (cache, _) = fake_pip_cache(&home, ".cache/pip");
    std::fs::create_dir_all(home.path().join(".config/degu")).unwrap();
    std::fs::write(
        home.path().join(".config/degu/config.toml"),
        "protect = [\"..\"]\n",
    )
    .unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("\"..\""));
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}
