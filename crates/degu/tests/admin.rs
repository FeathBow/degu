use assert_cmd::Command;

fn degu() -> Command {
    let mut command = Command::cargo_bin("degu").unwrap();
    command.env_remove("RUST_LOG");
    command
}

#[test]
fn parser_requires_decimal_nonzero_uid_and_initial_assertion() {
    for args in [
        vec!["admin", "setup", "--uid", "name", "--initial"],
        vec!["admin", "setup", "--uid", "-1", "--initial"],
        vec!["admin", "setup", "--uid", "0", "--initial"],
        vec!["admin", "setup", "--uid", "4294967295", "--initial"],
        vec!["admin", "setup", "--uid", "4294967296", "--initial"],
        vec!["admin", "setup", "--uid", "1000"],
    ] {
        let output = degu().args(&args).output().unwrap();
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(output.stdout.is_empty(), "unexpected stdout: {args:?}");
    }
}

#[test]
fn setup_exposes_only_the_fixed_locator_inputs() {
    let help = degu().args(["admin", "setup", "--help"]).output().unwrap();
    assert!(help.status.success());
    let stdout = String::from_utf8(help.stdout).unwrap();
    for required in ["--uid", "--initial", "--json", "effective UID 0"] {
        assert!(stdout.contains(required), "missing {required:?}: {stdout}");
    }
    for forbidden in [
        "--path",
        "--user",
        "--username",
        "SUDO_UID",
        "DEGU_ALLOW_ROOT",
        "activation-anchor",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "leaked {forbidden:?}: {stdout}"
        );
    }
}

#[test]
fn unpublished_protocol_command_path_is_not_retained() {
    let output = degu()
        .args(["admin", "activation-anchor", "provision", "--help"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn non_root_execution_is_refused_without_using_generic_root_override() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let output = degu()
        .env("DEGU_ALLOW_ROOT", "1")
        .args(["admin", "setup", "--uid", "1000", "--initial", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("account setup requires effective UID 0")
    );
}
