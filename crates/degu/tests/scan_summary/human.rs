use super::support::*;

#[test]
fn scan_summary_human_output_has_table_total_caveat_and_clean_stderr_under_pipe() {
    let home = tempfile::tempdir().unwrap();
    seed_pip_uv(&home);
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--summary"])
        .output()
        .unwrap();

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for label in [
        "source",
        "on disk",
        "inodes",
        "share",
        "pip",
        "uv",
        "Total",
        "locations detected by this scan",
    ] {
        assert!(stdout.contains(label), "missing {label:?} in {stdout}");
    }
    assert!(!stdout.contains("hardlink-shared"));
    assert_ecosystem_bars(&stdout);
    assert_total_has_no_bar(&stdout);
}

// Piped output is ASCII, so share bars render with '#' and '-' cells.
fn assert_ecosystem_bars(stdout: &str) {
    let bar_lines = stdout
        .lines()
        .filter(|line| line.contains('#'))
        .collect::<Vec<_>>();
    assert_eq!(bar_lines.len(), 2, "stdout: {stdout}");
    for line in bar_lines {
        assert!(
            line.contains('%'),
            "share cell must lead with a percent: {line}"
        );
        let cells = line
            .chars()
            .filter(|character| matches!(character, '#' | '-'))
            .count();
        assert_eq!(cells, 10, "bar must span exactly 10 cells: {line}");
    }
}

fn assert_total_has_no_bar(stdout: &str) {
    let total = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Total"))
        .unwrap_or_else(|| panic!("missing Total row in {stdout}"));
    assert!(total.contains("100.0%"));
    assert!(!total.contains('#'));
    assert!(!total.contains('-'));
}

#[test]
fn scan_summary_color_always_strips_to_plain_bytes_and_never_colors_json() {
    let home = tempfile::tempdir().unwrap();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    let plain = run_summary(&home, &["scan", "--summary"]);
    let colored = run_summary(&home, &["--color", "always", "scan", "--summary"]);
    let json = run_summary(&home, &["--color", "always", "scan", "--summary", "--json"]);

    assert!(plain.status.success());
    assert!(colored.status.success());
    assert!(json.status.success());
    assert!(colored.stdout.windows(2).any(|window| window == b"\x1b["));
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
    assert!(!json.stdout.contains(&b'\x1b'));
    serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
}

fn run_summary(home: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    degu().env("HOME", home.path()).args(args).output().unwrap()
}
