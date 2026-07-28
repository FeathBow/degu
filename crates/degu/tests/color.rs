use assert_cmd::Command;

#[path = "support/strip_sgr.rs"]
mod strip_sgr;
use strip_sgr::strip_sgr;

fn degu() -> Command {
    let mut command = Command::cargo_bin("degu").unwrap();
    command.env_clear();
    command.env("TERM", "xterm-256color");
    command
}

fn has_ansi(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|window| window == b"\x1b[")
}

#[test]
fn explicit_color_never_overrides_force_for_help() {
    let output = degu()
        .env("CLICOLOR_FORCE", "1")
        .args(["--color", "never", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!has_ansi(&output.stdout), "{:?}", output.stdout);
}

#[test]
fn explicit_color_controls_parse_errors() {
    let colored = degu()
        .args(["--color", "always", "unknown-command"])
        .output()
        .unwrap();
    let plain = degu()
        .env("CLICOLOR_FORCE", "1")
        .args(["--color", "never", "unknown-command"])
        .output()
        .unwrap();

    assert_eq!(colored.status.code(), Some(2));
    assert_eq!(plain.status.code(), Some(2));
    assert!(has_ansi(&colored.stderr), "{:?}", colored.stderr);
    assert!(!has_ansi(&plain.stderr), "{:?}", plain.stderr);
}

#[test]
fn no_color_wins_over_force_in_automatic_mode() {
    let output = degu()
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!has_ansi(&output.stdout), "{:?}", output.stdout);
}

#[test]
fn colored_help_strips_to_the_never_colored_contract() {
    let colored = degu().args(["--color=always", "--help"]).output().unwrap();
    let plain = degu().args(["--color=never", "--help"]).output().unwrap();

    assert!(colored.status.success());
    assert!(plain.status.success());
    assert!(has_ansi(&colored.stdout), "{:?}", colored.stdout);
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
}
