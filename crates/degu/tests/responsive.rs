//! End-to-end shapes of human output on narrow terminals: prose wraps,
//! group stats split into indented lines, and suggested commands keep a
//! full line of their own.

#[path = "support/pty.rs"]
mod pty;

use pty::{PtyRun, run as run_pty};
use std::path::Path;

const PIP_CACHE_BYTES: usize = 112 * 1024;
const NPM_CACHE_BYTES: usize = 4 * 1024;
const HF_MODEL_BYTES: usize = 512 * 1024;

// The pip cache dir the scanner probes on the current platform.
fn platform_pip_cache(home: &Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Caches/pip")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".cache/pip")
    }
}

#[test]
fn narrow_scan_splits_group_stats_and_keeps_the_next_command_whole() {
    let home = tempfile::tempdir().unwrap();
    let pip = platform_pip_cache(home.path());
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), vec![0u8; PIP_CACHE_BYTES]).unwrap();
    let npm = home.path().join(".npm");
    std::fs::create_dir_all(&npm).unwrap();
    std::fs::write(npm.join("payload.bin"), vec![0u8; NPM_CACHE_BYTES]).unwrap();

    let stdout = scan_at_width(24, "scan", home.path());

    let lines = trimmed_lines(&stdout);
    let start = position(&lines, "Ready to clean", &stdout);
    assert_eq!(lines[start + 1], "  2 locations", "stdout: {stdout}");
    let size = lines[start + 2];
    assert!(
        size.starts_with("  1") && size.ends_with(" KiB"),
        "expected a third stats line with the size, got {size:?}: {stdout}"
    );
    assert_consecutive_lines(&stdout, &["Next:", "  degu clean --dry-run"]);
}

#[test]
fn scan_filtered_to_empty_reports_sources_on_an_indented_line() {
    let home = tempfile::tempdir().unwrap();

    let stdout = scan_at_width(32, "scan --only pip", home.path());

    assert_consecutive_lines(&stdout, &["No matching locations", "  Sources: pip"]);
}

#[test]
fn narrow_clean_dry_run_with_an_empty_plan_wraps_every_message() {
    let home = tempfile::tempdir().unwrap();

    let stdout = scan_at_width(32, "clean --dry-run", home.path());

    assert_consecutive_lines(&stdout, &["Dry run", "  no changes will be made."]);
    assert_consecutive_lines(&stdout, &["No locations are selected for", "this clean."]);
}

#[test]
fn narrow_scan_wraps_the_unavailable_preview_reason() {
    let home = tempfile::tempdir().unwrap();
    let model = home
        .path()
        .join(".cache/huggingface/hub/models--org--line\nbreak/snapshots/main");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(model.join("model.bin"), vec![0u8; HF_MODEL_BYTES]).unwrap();

    let stdout = scan_at_width(32, "scan", home.path());

    assert_consecutive_lines(
        &stdout,
        &[
            "Preview the largest Needs review",
            "location (no changes):",
            "  Preview unavailable: this path",
            "  cannot be represented safely",
            "  as a shell command.",
        ],
    );
}

fn scan_at_width(columns: u16, args: &str, home: &Path) -> String {
    let config = config_home();
    let state = tempfile::tempdir().unwrap();
    let body = format!(
        r#"
spawn -noecho sh -c {{stty rows 24 columns {columns}; exec "$DEGU_BIN" --color never {args}}}
"#
    );
    let out = run_pty(PtyRun {
        body: &body,
        home,
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn config_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("degu")).unwrap();
    std::fs::write(dir.path().join("degu/config.toml"), "").unwrap();
    dir
}

fn trimmed_lines(stdout: &str) -> Vec<&str> {
    stdout.lines().map(str::trim_end).collect()
}

fn position(lines: &[&str], expected: &str, stdout: &str) -> usize {
    lines
        .iter()
        .position(|line| *line == expected)
        .unwrap_or_else(|| panic!("missing line {expected:?} in stdout: {stdout}"))
}

fn assert_consecutive_lines(stdout: &str, expected: &[&str]) {
    let lines = trimmed_lines(stdout);
    let start = position(&lines, expected[0], stdout);
    assert_eq!(
        &lines[start..start + expected.len()],
        expected,
        "stdout: {stdout}"
    );
}

// Past ten rows a tier folds its tail; at forty columns the fold line
// follows the Headline narrow rules instead of wrapping mid-phrase.
#[test]
fn narrow_fold_line_moves_its_stats_to_an_indented_line() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    for index in 0..12 {
        let snapshots = hub.join(format!("models--org--model-{index:02}/snapshots/main"));
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(snapshots.join("model.bin"), vec![0u8; HF_MODEL_BYTES]).unwrap();
    }

    let stdout = scan_at_width(40, "scan", home.path());

    let lines = trimmed_lines(&stdout);
    let start = position(&lines, "... and 2 more locations", &stdout);
    let stats = lines[start + 1];
    assert!(
        stats.starts_with("  ") && stats.contains(" - ") && stats.ends_with(" inodes"),
        "expected an indented stats line under the fold label, got {stats:?}: {stdout}"
    );
}

// At forty columns the headline drops its " in <elapsed>" suffix instead of
// wrapping mid-phrase.
#[test]
fn narrow_headline_drops_the_duration_instead_of_wrapping() {
    let home = tempfile::tempdir().unwrap();
    let pip = platform_pip_cache(home.path());
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), vec![0u8; PIP_CACHE_BYTES]).unwrap();

    let stdout = scan_at_width(40, "scan", home.path());

    let lines = trimmed_lines(&stdout);
    let headline = lines
        .iter()
        .find(|line| line.contains("detected across"))
        .unwrap_or_else(|| panic!("missing headline: {stdout}"));
    assert_eq!(
        *headline, "112.0 KiB detected across 1 location",
        "stdout: {stdout}"
    );
}
