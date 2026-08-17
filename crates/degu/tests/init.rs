use assert_cmd::Command;

fn degu() -> Command {
    Command::cargo_bin("degu").unwrap()
}

#[test]
fn init_accepts_no_uid_path_or_initial_override() {
    for args in [
        vec!["init"],
        vec!["init", "--uid", "1000"],
        vec!["init", "--anchor-path", "/tmp/caller-selected"],
        vec!["init", "/tmp/caller-selected"],
    ] {
        degu().args(&args).assert().failure().stdout("");
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
