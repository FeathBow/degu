use super::support::*;

mod dispositions;

#[test]
fn scan_color_always_styles_human_hierarchy_and_never_json() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let plain = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan"])
        .output()
        .unwrap();
    let colored = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .env("NO_COLOR", "1")
        .args(["--color", "always", "scan"])
        .output()
        .unwrap();
    let json = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["--color", "always", "scan", "--json"])
        .output()
        .unwrap();

    assert!(plain.status.success());
    assert!(colored.status.success());
    assert!(json.status.success());
    assert!(!plain.stdout.contains(&b'\x1b'));
    let colored_text = String::from_utf8_lossy(&colored.stdout);
    assert!(colored_text.contains("\x1b[1msource"), "{colored_text:?}");
    assert!(colored_text.contains("\x1b[2mtoday"), "{colored_text:?}");
    assert!(!colored_text.contains("\x1b[38;5;9mNot managed"));
    assert!(!colored_text.contains("\x1b[2mNot managed"));
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
    assert!(!json.stdout.contains(&b'\x1b'));
    serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
}

#[test]
fn scan_headline_carries_elapsed_only_on_terminals() {
    use crate::pty::{PtyRun, run as run_pty};

    let home = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    let state = tempfile::tempdir().unwrap();
    let terminal = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 24 columns 80; exec "$DEGU_BIN" --color never scan}
"#,
        home: home.path(),
        config_home: crate::common::isolated_config_home(),
        state_home: state.path(),
        extra_env: &[],
    });
    assert!(
        terminal.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&terminal.stderr)
    );
    let stdout = String::from_utf8(terminal.stdout).unwrap();
    crate::elapsed::assert_elapsed_suffix(headline(&stdout));

    let piped = degu()
        .env("HOME", home.path())
        .arg("scan")
        .output()
        .unwrap();
    assert!(piped.status.success());
    let stdout = String::from_utf8(piped.stdout).unwrap();
    let headline = headline(&stdout);
    crate::elapsed::assert_no_elapsed_suffix(headline);
    assert!(headline.contains(" ready to clean"), "{headline}");
}

fn headline(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|line| line.contains(" detected across "))
        .unwrap_or_else(|| panic!("missing headline: {stdout}"))
}

#[test]
fn scan_human_compresses_default_home_roots_to_tilde() {
    // Default-root fixture on purpose: env-redirected roots are used
    // verbatim and may not match the canonicalized HOME (macOS /var vs
    // /private/var), so only the platform default pip dir can pin `~` rendering.
    let home = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The ~-compressed default pip path is platform-specific.
    #[cfg(target_os = "macos")]
    let expected = "~/Library/Caches/pip";
    #[cfg(not(target_os = "macos"))]
    let expected = "~/.cache/pip";
    assert!(
        stdout.contains(expected),
        "findings table must show the ~-compressed path: {stdout}"
    );
}

#[test]
fn scan_details_human_table_shows_kind_and_rationale() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(hub.join("snapshots/main")).unwrap();
    std::fs::write(hub.join("snapshots/main/model.bin"), [0u8; 8192]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--details"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("kind"));
    assert!(stdout.contains("rationale"));
    assert!(stdout.contains("cleanup reason"));
    assert!(stdout.contains("model_cache"));
    assert!(stdout.contains("HuggingFace hub repo"));
    assert!(stdout.contains("costly to regenerate"));
}

#[test]
fn scan_default_human_table_omits_rationale() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("rationale"));
    assert!(!stdout.contains("pip download cache; rebuilt automatically on next install"));
}

#[test]
fn scan_json_ignores_details_flag_byte_for_byte() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let default = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();
    let details = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json", "--details"])
        .output()
        .unwrap();

    assert!(default.status.success());
    assert!(details.status.success());
    assert_eq!(details.stdout, default.stdout);
}

#[test]
fn scan_summary_json_ignores_details_flag_byte_for_byte() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let summary = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json", "--summary"])
        .output()
        .unwrap();
    let summary_details = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--json", "--summary", "--details"])
        .output()
        .unwrap();

    assert!(summary.status.success());
    assert!(summary_details.status.success());
    assert_eq!(summary_details.stdout, summary.stdout);
}

#[test]
fn scan_human_details_and_summary_remain_mutually_exclusive() {
    let home = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--summary", "--details"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--details cannot be used with --summary unless --json is also set")
    );
}

#[test]
fn scan_table_shows_units_and_total() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    std::fs::hard_link(cache.join("wheel.whl"), cache.join("wheel-link.whl")).unwrap();
    let output = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .arg("scan")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "pip",
        "KiB",
        "detected across 1 location",
        "is hardlink-shared; reclaimed space may be lower.",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}: {stdout}");
    }
}
