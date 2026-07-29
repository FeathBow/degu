use super::support::*;
use unicode_width::UnicodeWidthStr;

#[cfg(unix)]
#[test]
fn closed_stdout_stops_clean_before_mutation() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};

    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let output = Command::new(assert_cmd::cargo::cargo_bin("degu"))
        .env_clear()
        .env("HOME", home.path())
        .env("LOGNAME", home.path())
        .env("XDG_CONFIG_HOME", test_config_home())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--only", "pip", "--yes"])
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn clean_yes_human_reports_staged_trash_and_quota_note() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--yes"]);
    assert!(out.status.success());
    assert!(!cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_mechanism_line(&stdout, &state, false);
    let staged = staged_summary_line(&stdout);
    assert!(staged.contains("1 location - "), "{staged}");
    crate::elapsed::assert_no_elapsed_suffix(staged);
    assert!(stdout.contains("Still counts against quota while staged; restore with 'degu undo'."));
}

fn staged_summary_line(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|line| line.starts_with("Staged ") && line.contains(" into the trash"))
        .unwrap_or_else(|| panic!("missing staged summary: {stdout}"))
}

#[test]
fn clean_purge_yes_human_prints_not_restorable_mechanism_line() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--purge", "--yes"]);
    assert!(out.status.success());
    assert!(!cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_mechanism_line(&stdout, &state, true);
    assert!(stdout.contains("Purged "));
}

#[test]
fn clean_purge_dry_run_discloses_permanent_mode_without_mutating() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--purge", "--dry-run"]);

    assert!(out.status.success());
    assert!(cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Would permanently delete"));
    assert!(stdout.contains("Not restorable."));
    assert!(!stdout.contains("Would move"));
    assert!(!state.path().join("degu/trash").exists());
}

#[test]
fn clean_purge_preview_labels_the_restorable_continuation() {
    use crate::pty::{PtyRun, run as run_pty};

    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (cache, _) = fake_pip_cache(&home, ".cache/pip");
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never clean --purge --dry-run
"#,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &[],
    });

    assert!(out.status.success());
    assert!(cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_next_command(
        &stdout,
        "Safer next (current locations stage to trash):",
        "degu clean",
    );
    assert!(
        !stdout.lines().any(|line| line.trim_end() == "Next:"),
        "stdout: {stdout}"
    );
}

#[test]
fn clean_purge_color_marks_dry_run_and_irreversible_language() {
    let home = tempfile::tempdir().unwrap();
    let (_cache, state) = fake_pip_cache(&home, ".cache/pip");
    let plain = run_clean(
        &home,
        &state,
        &["--color", "never", "clean", "--purge", "--dry-run"],
    );
    let colored = run_clean(
        &home,
        &state,
        &["--color", "always", "clean", "--purge", "--dry-run"],
    );

    assert!(plain.status.success() && colored.status.success());
    let colored_text = String::from_utf8_lossy(&colored.stdout);
    assert_sgr_color(&colored_text, "Dry run", "38;5;14");
    assert_sgr_color(&colored_text, "Would permanently delete", "38;5;9");
    assert_sgr_color(&colored_text, "Not restorable", "38;5;9");
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
}

#[test]
fn clean_purge_rejects_generic_permanent_confirmation_as_non_success() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_interactive_clean_purge(home.path(), state.path(), "y");

    assert!(!out.status.success());
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    let transcript = String::from_utf8(out.stdout).unwrap();
    assert!(transcript.contains("Staged then purged immediately; not restorable."));
    assert!(transcript.contains("Canceled; no clean or purge changes made."));
}

#[test]
fn clean_interactive_prompt_prints_plan_block_first() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_interactive_clean(home.path(), state.path());
    assert!(out.status.success());
    assert!(!cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_plan_block(&stdout, &state);
    assert!(stdout.find("Plan:").unwrap() < stdout.find("Proceed? [y/N]").unwrap());
    assert_eq!(stdout.matches("Next:").count(), 1);
    assert_next_command(&stdout, "Next:", "degu trash list");
    crate::elapsed::assert_elapsed_suffix(staged_summary_line(&stdout));
}

#[test]
fn clean_details_human_table_shows_kind_and_rationale() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let out = run_clean(&home, &state, &["clean", "--dry-run", "--details"]);
    assert!(out.status.success());
    assert!(cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for value in [
        "kind",
        "rationale",
        "package_cache",
        "pip download cache",
        "automatically on next install",
    ] {
        assert!(stdout.contains(value));
    }
}

#[test]
fn clean_human_dry_run_explicitly_reports_no_mutation() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let model = home
        .path()
        .join(".cache/huggingface/hub/models--org--name/snapshots/main");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(model.join("model.bin"), [0u8; 4096]).unwrap();
    let out = run_clean(&home, &state, &["clean", "--dry-run"]);

    assert!(out.status.success());
    assert!(cache.exists());
    let stdout = String::from_utf8(out.stdout).unwrap().to_ascii_lowercase();
    assert!(stdout.contains("dry run"), "{stdout}");
    assert!(stdout.contains("no changes"), "{stdout}");
    for prefix in ["would move ", "excluded:"] {
        let line = stdout
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing {prefix:?}:\n{stdout}"));
        assert!(UnicodeWidthStr::width(line) <= 40, "{line:?}");
    }
    assert!(stdout.contains("to degu trash"), "{stdout}");
    assert!(
        stdout.contains("undoable; quota is unchanged until degu trash is purged."),
        "{stdout}"
    );
    assert!(
        stdout.contains("quota can change only after permanent deletion:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("run this preview in a terminal to receive a next command"),
        "{stdout}"
    );
    assert!(!stdout.contains("if the preview looks right"), "{stdout}");
    assert!(
        stdout.contains("review details: degu clean --details --dry-run"),
        "{stdout}"
    );
}

#[test]
fn clean_include_review_keeps_review_authority_visible_in_the_plan() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let repo = home.path().join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
    std::fs::write(repo.join("snapshots/main/model.bin"), [0_u8; 4096]).unwrap();

    let out = run_clean(&home, &state, &["clean", "--dry-run", "--include-review"]);

    assert!(out.status.success());
    assert!(cache.exists() && repo.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Ready to clean - 1 location - "),
        "{stdout}"
    );
    assert!(
        stdout.contains("Needs review (included by --include-review) - 1 location - "),
        "{stdout}"
    );
    assert!(stdout.contains("costly to regenerate"), "{stdout}");
    assert!(!stdout.contains("Selected locations:"), "{stdout}");
}

#[test]
fn clean_human_report_only_excluded_table_prints_disclaimer_once() {
    let home = tempfile::tempdir().unwrap();
    let (_cache, state) = fake_pip_cache(&home, ".cache/pip");
    let data_home = home.path().join("data");
    std::fs::create_dir_all(data_home.join("containers/storage/overlay")).unwrap();
    std::fs::write(
        data_home.join("containers/storage/overlay/payload"),
        [0u8; 4096],
    )
    .unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", data_home.canonicalize().unwrap())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Not managed - 1 location - "));
    assert_eq!(
        stdout
            .matches("Reported only; degu never cleans these locations.")
            .count(),
        1
    );
}

#[test]
fn clean_json_ignores_details_flag_and_omits_human_only_lines() {
    let home = tempfile::tempdir().unwrap();
    let (_cache, state) = fake_pip_cache(&home, ".cache/pip");
    let default = run_clean(&home, &state, &["clean", "--json", "--dry-run"]);
    let details = run_clean(
        &home,
        &state,
        &["clean", "--json", "--dry-run", "--details"],
    );
    assert!(default.status.success());
    assert!(details.status.success());
    assert_eq!(details.stdout, default.stdout);
    let stdout = String::from_utf8(details.stdout).unwrap();
    assert!(!stdout.contains("Plan: move"));
    assert!(!stdout.contains("View-only findings are informational"));
}

// Unattended recipes toggle --dry-run while keeping --yes, so the
// combination stays accepted and earns only a stderr notice.
#[test]
fn dry_run_with_yes_notices_on_stderr_and_keeps_the_dry_run_unchanged() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");

    let with_yes = run_clean(&home, &state, &["clean", "--dry-run", "--yes"]);
    let without_yes = run_clean(&home, &state, &["clean", "--dry-run"]);

    assert!(with_yes.status.success());
    assert!(
        String::from_utf8(with_yes.stderr)
            .unwrap()
            .contains("warning: --yes has no effect in a dry run."),
    );
    assert!(without_yes.status.success());
    assert!(without_yes.stderr.is_empty());
    assert_eq!(with_yes.stdout, without_yes.stdout);
    assert!(cache.exists(), "a dry run must not stage anything");
    assert!(!state.path().join("degu/trash").exists());
}
