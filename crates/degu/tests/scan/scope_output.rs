use super::support::*;
use crate::pty::{PtyRun, run as run_pty};

#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;

#[test]
fn bare_scan_discloses_that_project_builds_are_out_of_scope() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .arg("scan")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(
            "Scan build artifacts under this project, or any parent directory: degu scan ."
        ),
        "stdout: {stdout}"
    );
}

#[test]
fn source_limited_scan_does_not_suggest_an_unselected_project_scope() {
    let (home, cache) = fake_cache("scratch/pip-cache", "wheel.whl", 2048);
    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &cache)
        .args(["scan", "--only", "pip"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("Scan build artifacts under this project"));
}

#[cfg(unix)]
#[test]
fn truncated_interactive_scan_prioritizes_completion_over_existing_trash() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let state_root = state.path().join("degu");
    let trash_entry = state_root.join("trash/staged");
    std::fs::create_dir_all(&trash_entry).unwrap();
    // create_dir_all inherits the process umask; pin every created level so the
    // trash tamper guard passes under group-writable defaults (umask 002).
    for dir in [&state_root, &state_root.join("trash"), &trash_entry] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
    }
    std::fs::write(trash_entry.join("cache.bin"), b"staged cache").unwrap();
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    std::fs::write(config.path().join("degu/config.toml"), "").unwrap();

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never scan --only pip --only artifacts --older-than 7 --min-size 1024 --top 3 --runtime --budget 0s
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The budget expired before the trash walk, so the summary reports an
    // unmeasured size rather than running the unbounded walk it once did.
    assert!(
        stdout.contains("Trash size unknown (scan budget reached)."),
        "stdout: {stdout}"
    );
    assert_next_command(
        &stdout,
        "Rerun to complete the scan:",
        "degu scan --only pip --only artifacts --older-than 7 --min-size 1024 --top 3 --runtime",
    );
    assert!(
        !stdout.contains("Scan build artifacts under this project"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.lines().any(|line| line.trim_end() == "Next:"),
        "stdout: {stdout}"
    );
}

#[test]
fn empty_interactive_scan_prints_the_project_command_once() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    std::fs::write(config.path().join("degu/config.toml"), "").unwrap();
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never scan
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.matches("degu scan .").count(), 1, "stdout: {stdout}");
    assert_next_command(&stdout, "Next:", "degu scan .");
}

#[cfg(unix)]
#[test]
fn incomplete_interactive_scan_does_not_promote_project_scope_as_next() {
    use std::os::unix::fs::symlink;

    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let alias = home.path().join("pip-cache");
    symlink(cache.path(), &alias).unwrap();
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    std::fs::write(config.path().join("degu/config.toml"), "").unwrap();
    let extra_env = [("PIP_CACHE_DIR", alias.as_os_str())];

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never scan
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &extra_env,
    });

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.matches("degu scan .").count(), 1, "stdout: {stdout}");
    assert!(
        !stdout.lines().any(|line| line.trim_end() == "Next:"),
        "stdout: {stdout}"
    );
}
