use assert_cmd::Command;
use std::process::Output;

fn run(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::cargo_bin("degu")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("LOGNAME", "degu-test")
        .env("DEGU_ALLOW_ROOT", "1")
        .args(args)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn closed_json_stdout_stops_before_version_probe_or_mutation_transition() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let home = tempfile::tempdir().unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
        .env_clear()
        .env("HOME", home.path())
        .env("LOGNAME", "degu-test")
        .env("DEGU_ALLOW_ROOT", "1")
        .args([
            "reclaim",
            "uv",
            "--executable",
            "/definitely/missing/uv",
            "--cache-dir",
            "/definitely/missing/cache",
            "--yes",
            "--json",
        ])
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
}

#[test]
fn mutating_reclaim_with_yes_enters_only_the_bounded_preflight_for_a_missing_binary() {
    let output = run(&[
        "reclaim",
        "uv",
        "--executable",
        "/definitely/missing/uv",
        "--cache-dir",
        "/definitely/missing/cache",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("execution is not available in this build"),
        "{stderr}"
    );
    assert!(!stderr.contains("Type 'prune'"), "{stderr}");
}

#[test]
fn non_dry_run_without_yes_still_fails_before_any_prompt_or_probe() {
    let output = run(&[
        "reclaim",
        "uv",
        "--executable",
        "/definitely/missing/uv",
        "--cache-dir",
        "/definitely/missing/cache",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires --yes when stdin is not a terminal"),
        "{stderr}"
    );
    assert!(!stderr.contains("Type 'prune'"), "{stderr}");
    assert!(
        !stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
}

#[test]
fn json_mutation_requires_yes_before_any_preflight() {
    let output = run(&[
        "reclaim",
        "uv",
        "--executable",
        "/definitely/missing/uv",
        "--cache-dir",
        "/definitely/missing/cache",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--json requires --yes or --dry-run"),
        "{stderr}"
    );
    assert!(!stderr.contains("Type 'prune'"), "{stderr}");
    assert!(
        !stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
}

#[test]
fn explicit_paths_are_lexically_validated_without_path_lookup() {
    let relative_executable = run(&[
        "reclaim",
        "uv",
        "--executable",
        "uv",
        "--cache-dir",
        "/cache/uv",
        "--yes",
    ]);
    assert_eq!(relative_executable.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&relative_executable.stderr);
    assert!(
        stderr.contains("executable selection is not absolute"),
        "{stderr}"
    );

    let relative_root = run(&[
        "reclaim",
        "uv",
        "--executable",
        "/opt/uv/bin/uv",
        "--cache-dir",
        "cache/uv",
        "--yes",
    ]);
    assert_eq!(relative_root.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&relative_root.stderr);
    assert!(
        stderr.contains("cache root selection is not absolute"),
        "{stderr}"
    );
}

#[test]
fn disabled_uv_adapter_blocks_preview_before_executable_probe() {
    let home = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let degu_config = config_home.path().join("degu");
    std::fs::create_dir(&degu_config).unwrap();
    std::fs::write(degu_config.join("config.toml"), "disable = [\"uv\"]\n").unwrap();
    let output = Command::cargo_bin("degu")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("LOGNAME", "degu-test")
        .env("DEGU_ALLOW_ROOT", "1")
        .args([
            "reclaim",
            "uv",
            "--executable",
            "/definitely/missing/uv",
            "--cache-dir",
            "/definitely/missing/cache",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("disabled by configuration"), "{stderr}");
    assert!(
        !stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
}

#[test]
fn dry_run_attempts_only_the_bounded_preview_preflight() {
    let output = run(&[
        "reclaim",
        "uv",
        "--executable",
        "/definitely/missing/uv",
        "--cache-dir",
        "/definitely/missing/cache",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to inspect selected uv executable"),
        "{stderr}"
    );
    assert!(!stderr.contains("cache prune"), "{stderr}");
}
