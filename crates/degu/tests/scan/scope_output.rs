use super::support::*;
use crate::pty::{PtyRun, run as run_pty};

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
