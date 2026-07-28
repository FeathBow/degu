use super::support::*;
use crate::pty::{PtyRun, run as run_pty};
use std::path::Path;

const STATE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn run_interactive_list(home: &Path, state: &Path) -> std::process::Output {
    let body = r#"
spawn -noecho $env(DEGU_BIN) trash list
"#;
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &[],
    })
}

#[cfg(unix)]
#[test]
fn trash_list_rejects_fifo_registry_without_hanging() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let state_dir = state.path().join("degu");
    std::fs::create_dir_all(&state_dir).unwrap();
    let registry = state_dir.join("trashroots");
    let status = std::process::Command::new("mkfifo")
        .arg(&registry)
        .status()
        .unwrap();
    assert!(status.success());

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["trash", "list", "--json"])
        .timeout(STATE_READ_TIMEOUT)
        .output()
        .expect("trash list must reject a FIFO instead of timing out");

    assert!(!out.status.success());
    assert!(out.status.code().is_some(), "process was killed by timeout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("trashroots"), "stderr: {stderr}");
    assert!(stderr.contains("not a regular file"), "stderr: {stderr}");
}

#[test]
fn scan_summary_counts_an_interrupted_purge_claim() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    seed_interrupted_purge_claim(&state);

    let out = run(&home, &state, &["scan"]);

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Trash holds"));
    assert!(stdout.contains("across 1 entry"));
}

#[test]
fn trash_list_reconciles_pending_rows_and_marks_ambiguous_entries() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (staged_original, staged_entry, ambiguous_entry) = seed_pending_fixture(&home, &state);

    let out = run(&home, &state, &["trash", "list", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["omitted"], 0);
    let rows = report["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let staged_row = rows
        .iter()
        .find(|row| row["entry"] == staged_entry.to_string_lossy().as_ref())
        .unwrap();
    assert_eq!(
        staged_row["original"],
        staged_original.to_string_lossy().as_ref()
    );
    assert_eq!(staged_row["ambiguous"], false);
    assert!(staged_row["age_days"].as_u64().unwrap() > 3650);
    let ambiguous_row = rows
        .iter()
        .find(|row| row["entry"] == ambiguous_entry.to_string_lossy().as_ref())
        .unwrap();
    assert_eq!(ambiguous_row["ambiguous"], true);

    let out = run(&home, &state, &["trash", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("(ambiguous)"), "stdout: {stdout}");
    assert!(
        stdout.contains("unverified operation state or recorded identity"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("operation history"), "stdout: {stdout}");
    assert!(!stdout.contains("degu trash purge"), "stdout: {stdout}");

    let out = run_interactive_list(home.path(), state.path());
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("Choose one outcome:"), "stdout: {stdout}");
    assert!(!stdout.contains("degu trash purge"), "stdout: {stdout}");
    assert_next_command(&stdout, "Next:", "degu ops");
}

#[cfg(target_os = "linux")]
#[test]
fn trash_list_json_survives_a_non_utf8_entry_and_counts_it_omitted() {
    use std::os::unix::ffi::OsStringExt;

    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let trash = private_trash_root(&state);
    let normal = trash.join("0001-normal");
    std::fs::create_dir_all(&normal).unwrap();
    std::fs::write(normal.join("data"), b"normal data").unwrap();
    let non_utf8 = trash.join(std::ffi::OsString::from_vec(b"0002-bad-\xff".to_vec()));
    std::fs::write(&non_utf8, b"must survive").unwrap();

    let out = run(&home, &state, &["trash", "list", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0]["entry"]
            .as_str()
            .unwrap()
            .ends_with("0001-normal")
    );
    assert!(report["omitted"].as_u64().unwrap() >= 1);
    assert_eq!(std::fs::read(&non_utf8).unwrap(), b"must survive");

    let human = run(&home, &state, &["trash", "list"]);
    assert!(human.status.success());
}
