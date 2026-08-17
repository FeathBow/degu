use assert_cmd::Command;

fn degu() -> Command {
    Command::cargo_bin("degu").unwrap()
}

#[test]
fn init_accepts_no_uid_path_or_initial_override() {
    degu().args(["init"]).assert().failure().stdout("");
    for args in [
        vec!["init", "--initial", "--uid", "1000"],
        vec!["init", "--initial", "--anchor-path", "/tmp/caller-selected"],
        vec!["init", "--initial", "/tmp/caller-selected"],
    ] {
        let output = degu().args(&args).output().unwrap();
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(output.stdout.is_empty(), "unexpected stdout: {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "unexpected stderr for {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn root_cannot_enter_self_managed_initialization_even_with_test_root_bypass() {
    if !rustix::process::geteuid().is_root() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    degu()
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("DEGU_ALLOW_ROOT", "1")
        .args(["init", "--initial", "--json"])
        .assert()
        .failure()
        .stdout("");
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    assert!(std::fs::read_dir(state.path()).unwrap().next().is_none());
}
