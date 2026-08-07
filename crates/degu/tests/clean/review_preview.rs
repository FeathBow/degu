#![cfg(unix)]

use super::support::*;
use std::path::{Path, PathBuf};

fn seed_review_finding(home: &tempfile::TempDir) -> PathBuf {
    let repo = home.path().join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
    std::fs::write(repo.join("snapshots/main/model.bin"), [0u8; 8192]).unwrap();
    repo
}

struct NpmCaches<'a> {
    lowercase: &'a Path,
    uppercase: Option<&'a Path>,
}

fn run_npm_scan(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    caches: NpmCaches<'_>,
) -> std::process::Output {
    let mut command = degu();
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("npm_config_cache", caches.lowercase)
        .args(["scan", "--only", "huggingface", "--only", "npm"]);
    if let Some(uppercase) = caches.uppercase {
        command.env("NPM_CONFIG_CACHE", uppercase);
    }
    command.output().unwrap()
}

fn successful_stdout(output: std::process::Output) -> String {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn assert_preview_withheld(stdout: &str) {
    assert!(
        stdout.contains("Scan incomplete"),
        "fixture no longer produces an incomplete scan; stdout: {stdout}"
    );
    assert!(!stdout.contains("degu clean"), "stdout: {stdout}");
}

#[test]
fn scan_review_preview_executes_with_mixed_cache_and_runtime_sources() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let repo = seed_review_finding(&home);
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "scan",
            "--runtime",
            "--only",
            "huggingface",
            "--only",
            "tmp",
        ])
        .output()
        .unwrap();
    let scan_stdout = successful_stdout(scan);
    let preview_args = review_preview_args(
        &scan_stdout,
        "degu clean --details --dry-run --include-review --only huggingface --path ~/.cache/huggingface/hub/models--org--name",
        home.path(),
    );
    let preview = run_clean(
        &home,
        &state,
        &preview_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );

    assert!(
        preview.status.success(),
        "generated preview was refused: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(repo.join("snapshots/main/model.bin").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// The incompleteness sits at a recorded, disjoint region, so the previewed
/// --path clean can prove its selection safe and must stay executable.
#[test]
fn scan_review_preview_command_runs_despite_unrelated_incomplete_source() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let repo = seed_review_finding(&home);
    let pip = crate::common::platform_cache_dir(home.path(), "pip");
    let unreadable = pip.join("unreadable");
    std::fs::create_dir_all(&unreadable).unwrap();
    std::fs::write(pip.join("wheel.whl"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    set_mode(&unreadable, 0o000);

    let scan = run_clean(&home, &state, &["scan"]);
    let scan_stdout = successful_stdout(scan);
    let preview_args = review_preview_args(
        &scan_stdout,
        "degu clean --details --dry-run --include-review --path ~/.cache/huggingface/hub/models--org--name",
        home.path(),
    );
    let preview = run_clean(
        &home,
        &state,
        &preview_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    set_mode(&unreadable, 0o755);

    assert!(
        scan_stdout.contains("Scan incomplete: totals marked"),
        "fixture no longer produces an incomplete scan; stdout: {scan_stdout}"
    );
    let preview_stdout = successful_stdout(preview);
    let unwrapped: String = preview_stdout
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(
        unwrapped.contains("models--org--name"),
        "stdout: {preview_stdout}"
    );
    assert!(repo.join("snapshots/main/model.bin").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// An incompleteness event with no recorded location means no clean --path
/// can prove its selection disjoint from what was missed — so no preview.
#[test]
fn scan_withholds_the_review_preview_when_executing_it_would_be_refused() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    seed_review_finding(&home);
    let lowercase = home.path().join("lowercase-cache");
    let uppercase = home.path().join("uppercase-cache");
    std::fs::create_dir_all(&lowercase).unwrap();
    std::fs::create_dir_all(&uppercase).unwrap();
    std::fs::write(lowercase.join("lowercase.tgz"), [0u8; 2048]).unwrap();
    std::fs::write(uppercase.join("uppercase.tgz"), [0u8; 4096]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    let mismatched = run_npm_scan(
        &home,
        &state,
        NpmCaches {
            lowercase: &lowercase,
            uppercase: Some(&uppercase),
        },
    );
    let mismatched_stdout = successful_stdout(mismatched);
    assert_preview_withheld(&mismatched_stdout);

    let single_spelling = run_npm_scan(
        &home,
        &state,
        NpmCaches {
            lowercase: &lowercase,
            uppercase: None,
        },
    );
    let single_stdout = successful_stdout(single_spelling);
    let preview_args = review_preview_args(
        &single_stdout,
        "degu clean --details --dry-run --include-review --only huggingface --only npm --path ~/.cache/huggingface/hub/models--org--name",
        home.path(),
    );
    let preview = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("npm_config_cache", &lowercase)
        .args(&preview_args)
        .output()
        .unwrap();
    let _ = successful_stdout(preview);
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}
