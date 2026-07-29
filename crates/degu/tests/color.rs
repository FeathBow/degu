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
fn explicit_color_controls_runtime_error_prefixes() {
    let colored = degu()
        .args(["--color", "always", "quota", "/degu-missing-color-target"])
        .output()
        .unwrap();
    let plain = degu()
        .env("CLICOLOR_FORCE", "1")
        .args(["--color", "never", "quota", "/degu-missing-color-target"])
        .output()
        .unwrap();

    assert!(!colored.status.success());
    assert!(!plain.status.success());
    assert!(has_ansi(&colored.stderr), "{:?}", colored.stderr);
    assert!(!has_ansi(&plain.stderr), "{:?}", plain.stderr);
    assert_eq!(strip_sgr(&colored.stderr), plain.stderr);
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
fn force_color_styles_help_and_human_output_in_pipes() {
    let help = degu()
        .env("CLICOLOR_FORCE", "1")
        .arg("--help")
        .output()
        .unwrap();
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("pip-cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    let scan = degu()
        .env("CLICOLOR_FORCE", "1")
        .env("HOME", home.path())
        .env("LOGNAME", home.path())
        .env("PIP_CACHE_DIR", cache)
        .arg("scan")
        .output()
        .unwrap();

    assert!(help.status.success());
    assert!(scan.status.success());
    assert!(has_ansi(&help.stdout), "{:?}", help.stdout);
    assert!(has_ansi(&scan.stdout), "{:?}", scan.stdout);
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
