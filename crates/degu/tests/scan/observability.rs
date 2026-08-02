use super::support::*;

#[test]
fn verbose_scan_keeps_json_clean_and_reports_adapter_and_profile_counters() {
    let (home, cache) = fake_cache("scratch/uv-cache", "archive.zip", 4096);

    let out = degu()
        .env("HOME", home.path())
        .env("UV_CACHE_DIR", &cache)
        .args(["-v", "scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "uv");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["inodes"], 2);
    assert!(arr[0]["bytes_allocated"].as_u64().unwrap() >= 4096);
    let finding = arr[0].as_object().unwrap();
    assert!(!finding.contains_key("elapsed_ms"));
    assert!(!finding.contains_key("max_rss_bytes"));

    let stderr = String::from_utf8(out.stderr).unwrap();
    let adapter = stderr
        .lines()
        .find(|line| line.contains("scan complete") && !line.contains("scan phase complete"))
        .unwrap();
    assert!(adapter.contains("ecosystem=\"uv\""), "{adapter}");
    for field in ["findings=1", "inodes=2", "bytes_allocated="] {
        assert!(adapter.contains(field), "{adapter}");
    }
    let profile = stderr
        .lines()
        .find(|line| line.contains(" INFO degu: scan phase complete"))
        .unwrap();
    let fields = profile.split_ascii_whitespace().collect::<Vec<_>>();
    assert!(fields.contains(&"roots=1"), "{profile}");
    assert!(fields.contains(&"findings=1"), "{profile}");
    assert!(fields.contains(&"total_inodes=2"), "{profile}");
    assert!(fields.iter().any(|field| field.starts_with("elapsed_ms=")));
    assert!(
        fields
            .iter()
            .any(|field| field.starts_with("max_rss_bytes="))
    );
}

/// A skip count alone is not actionable: -vv must name each sampled skipped
/// path with its reason so the reported scan warnings can be resolved.
#[cfg(unix)]
#[test]
fn debug_scan_names_each_sampled_skipped_path_with_its_reason() {
    use std::os::unix::fs::PermissionsExt;

    // Mode 0o000 does not bar root, so the fixture cannot produce a skip.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let (home, cache) = fake_cache("scratch/uv-cache", "archive.zip", 4096);
    let unreadable = cache.join("unreadable");
    std::fs::create_dir(&unreadable).unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("UV_CACHE_DIR", &cache)
        .args(["-vv", "scan", "--json"])
        .output()
        .unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let skip = stderr
        .lines()
        .find(|line| line.contains("scan skipped a path"))
        .unwrap_or_else(|| panic!("no skipped-path event in stderr: {stderr}"));
    assert!(
        skip.contains(&unreadable.display().to_string()),
        "skipped-path event names no path: {skip}"
    );
    assert!(
        skip.contains("Permission denied"),
        "skipped-path event names no reason: {skip}"
    );
}

#[test]
fn tilde_root_cannot_escape_home_with_a_second_slash() {
    let home = tempfile::tempdir().unwrap();
    let config = runtime_config_home("roots = [\"~//tmp/unintended\"]\n");

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("~/ must be followed by a HOME-relative path"),
        "{stderr}"
    );
}

#[test]
fn excessive_configured_concurrency_fails_before_scanning() {
    let home = tempfile::tempdir().unwrap();
    let config = runtime_config_home("max_concurrency = 257\n");

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("max_concurrency must not exceed 256"),
        "{stderr}"
    );
}

// The TOML parse error must render as a block indented under the `error:`
// prefix, never flattened to one line with a literal "\n".
#[test]
fn malformed_config_errors_keep_their_multi_line_shape() {
    let home = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    let config_path = config.path().join("degu/config.toml");
    std::fs::write(&config_path, "not = valid = toml\n").unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .arg("scan")
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let expected = format!(
        "error: failed to parse {}: TOML parse error at line 1, column 13\n         \
         |\n       \
         1 | not = valid = toml\n         \
         |             ^\n       \
         unexpected key or value, expected newline, `#`\n",
        config_path.display()
    );
    assert_eq!(String::from_utf8(out.stderr).unwrap(), expected);
}

#[test]
fn invalid_rust_log_fails_loudly() {
    let home = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("RUST_LOG", "degu=notalevel")
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("invalid RUST_LOG directive"), "{stderr}");
    assert!(stderr.contains("notalevel"), "{stderr}");
}

#[test]
fn scan_fails_closed_on_a_corrupt_trash_registry() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let state_dir = state.path().join("degu");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("trashroots"),
        b"\"/external/.degu-trash\"TRUNCATED\n",
    )
    .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("scan")
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("trashroots"), "stderr: {stderr}");
    assert!(
        stderr.contains("corrupt trash registry line 1"),
        "stderr: {stderr}"
    );
}
