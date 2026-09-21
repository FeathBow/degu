use assert_cmd::Command;

fn degu() -> Command {
    Command::cargo_bin("degu").unwrap()
}

/// `init` derives everything from the account database, so a caller cannot
/// point it anywhere. Each of these is refused by argument parsing, before any
/// provisioning could run — which is also why the bare command is not exercised
/// here: it would provision whoever runs the suite.
#[test]
fn init_accepts_no_uid_or_path_selector() {
    for args in [
        vec!["init", "--uid", "1000"],
        vec!["init", "--anchor-path", "/tmp/caller-selected"],
        vec!["init", "/tmp/caller-selected"],
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
        .args(["init", "--json"])
        .assert()
        .failure()
        .stdout("");
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    assert!(std::fs::read_dir(state.path()).unwrap().next().is_none());
}
