//! The interactive review decides what to clean, so what it offers must be
//! what a clean could act on. These drive the real binary over a PTY.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod common;
#[path = "support/pty.rs"]
mod pty;

use pty::{PtyRun, run as run_pty};
use std::path::Path;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";
const CACHE_BYTES: usize = 2 * 1024 * 1024;
const ARTIFACT_BYTES: usize = 7 * 1024 * 1024;

/// A well-known cache degu cleans without being asked, plus a project whose
/// build artifacts are reachable only through a project root.
fn fixture(home: &Path) -> std::path::PathBuf {
    let cache = platform_cache(home, "go-build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("blob.bin"), vec![0u8; CACHE_BYTES]).unwrap();

    let project = home.join("proj");
    std::fs::create_dir_all(project.join("target")).unwrap();
    std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        project.join("target/CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(project.join("target/.rustc_info.json"), "{}").unwrap();
    std::fs::write(project.join("target/debug.bin"), vec![0u8; ARTIFACT_BYTES]).unwrap();
    project
}

fn platform_cache(home: &Path, name: &str) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Caches").join(name)
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".cache").join(name)
    }
}

/// `docs/usage.md`: configured roots never authorize cleanup. A review that
/// offered one would turn read-only discovery into a cleanup authority the
/// reader never granted, and a keystroke would be enough to act on it.
#[test]
fn a_configured_root_is_not_offered_to_the_interactive_review() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[&project]);

    let stdout = review(home.path(), config.path(), "");

    assert!(
        stdout.contains("go-build"),
        "the well-known cache is still offered: {stdout}"
    );
    assert!(
        !stdout.contains("proj/target"),
        "a configured root reached the clean plan: {stdout}"
    );
    assert!(
        !stdout.contains(&project.display().to_string()),
        "a configured root was passed as a cleanup authority: {stdout}"
    );
}

/// The same project, named on the command line, is authorized exactly as it is
/// for `degu clean PATH`. Refusing it here would be a different defect.
#[test]
fn a_root_named_on_the_command_line_is_offered() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[]);

    let stdout = review(
        home.path(),
        config.path(),
        &format!(" {}", shell_word(&project)),
    );

    assert!(
        stdout.contains("proj/target"),
        "an explicit root was not offered: {stdout}"
    );
}

/// `degu scan` reports rather than cleans, so the configured root stays part of
/// its read-only discovery. The review's narrower authority must not have
/// narrowed the report too.
#[test]
fn a_configured_root_is_still_discovered_by_scan() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[&project]);
    let state = tempfile::tempdir().unwrap();

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never scan
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("artifacts"),
        "scan stopped discovering the configured root: {stdout}"
    );
}

/// Open the review, preview the plan it would run, then decline to reopen it.
/// The preview is a dry run, so nothing is staged and the printed plan is the
/// exact set of locations the review offered.
fn review(home: &Path, config_home: &Path, args: &str) -> String {
    let state = tempfile::tempdir().unwrap();
    // A default-sized PTY renders nothing the interface can be recognized by,
    // so pin the geometry; then wait for the alternate screen rather than for
    // any drawn text, which arrives interleaved with escape sequences.
    let body = format!(
        r#"
spawn -noecho sh -c {{stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui{args}}}
expect -ex "\033\[?1049h"
sleep 1
send "p"
expect "Dry run"
expect "Proceed?"
send "n\r"
"#
    );
    let out = run_pty(PtyRun {
        body: &body,
        home,
        config_home,
        state_home: state.path(),
        extra_env: &[],
    });
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn config_home_with_roots(roots: &[&Path]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("degu")).unwrap();
    let entries = roots
        .iter()
        .map(|root| format!("{:?}", root.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.path().join("degu/config.toml"),
        format!("roots = [{entries}]\n"),
    )
    .unwrap();
    dir
}

fn shell_word(path: &Path) -> String {
    path.display().to_string()
}

/// The review draws its own screen, so `scan`'s output options have nothing to
/// act on. Accepting them would promise a rendering this command never makes.
#[test]
fn the_review_refuses_scan_output_options() {
    for flag in ["--json", "--details", "--summary"] {
        let out = common::isolated_degu()
            .args(["tui", flag])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{flag} was accepted");
        assert!(stderr.contains("unexpected argument"), "{flag}: {stderr}");
    }
}

/// Everything that selects or bounds the scan still belongs to it.
#[test]
fn the_review_keeps_the_scan_selection_options() {
    for args in [
        vec!["tui", "--only", "pip"],
        vec!["tui", "--older-than", "7"],
        vec!["tui", "--min-size", "1M"],
        vec!["tui", "--top", "3"],
        vec!["tui", "--runtime"],
        vec!["tui", "--budget", "5s"],
    ] {
        let out = common::isolated_degu().args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "{args:?} was rejected: {stderr}"
        );
    }
}
