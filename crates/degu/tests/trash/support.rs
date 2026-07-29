use crate::pty::{PtyRun, run as run_pty};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(super) use crate::clean_run::run as clean_pip_cache;
pub(super) use crate::common::isolated_config_home as test_config_home;
pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::next_command::assert_next_command;
pub(super) use crate::pip_fixture::create as fake_pip_cache;
pub(super) use crate::private_degu_state::create as private_degu_state;
pub(super) use crate::strip_sgr::strip_sgr;

pub(super) fn run(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    args: &[&str],
) -> std::process::Output {
    degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(args)
        .output()
        .unwrap()
}

pub(super) fn run_interactive_purge(
    home: &Path,
    state: &Path,
    response: &str,
) -> std::process::Output {
    let body = r#"
spawn $env(DEGU_BIN) --color always trash purge
expect -exact {Type 'purge' to permanently delete this plan: }
send "$env(RESPONSE)\r"
"#;
    let extra_env = [("RESPONSE", OsStr::new(response))];
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &extra_env,
    })
}

pub(super) fn run_purge_with_late_entry(
    home: &Path,
    state: &Path,
    late_entry: &Path,
) -> std::process::Output {
    let body = r#"
spawn $env(DEGU_BIN) trash purge
expect -exact {Type 'purge' to permanently delete this plan: }
file mkdir $env(LATE_ENTRY)
send "purge\r"
"#;
    let extra_env = [("LATE_ENTRY", late_entry.as_os_str())];
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &extra_env,
    })
}

pub(super) fn run_purge_with_replaced_entry(
    home: &Path,
    state: &Path,
    planned_entry: &Path,
) -> std::process::Output {
    let body = r#"
spawn $env(DEGU_BIN) trash purge
expect -exact {Type 'purge' to permanently delete this plan: }
file delete -force -- $env(PLANNED_ENTRY)
file mkdir $env(PLANNED_ENTRY)
set replacement [open [file join $env(PLANNED_ENTRY) replacement.txt] w]
puts -nonewline $replacement {replacement data}
close $replacement
send "purge\r"
"#;
    let extra_env = [("PLANNED_ENTRY", planned_entry.as_os_str())];
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &extra_env,
    })
}

pub(super) fn seed_interrupted_purge_claim(state: &tempfile::TempDir) -> PathBuf {
    let claims = private_trash_root(state).join(".claims");
    let claim = claims.join("purge-interrupted");
    std::fs::create_dir_all(&claim).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(claim.join("cache.bin"), b"preserved cache").unwrap();
    claim
}

pub(super) fn private_trash_root(state: &tempfile::TempDir) -> PathBuf {
    let trash = private_degu_state(state).join("trash");
    std::fs::create_dir_all(&trash).unwrap();
    std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).unwrap();
    trash
}

fn pending_trash_record(ts: &str, paths: (&Path, &Path)) -> serde_json::Value {
    let mut record = serde_json::json!({
        "ts": ts,
        "tool_version": "0.0.1",
        "command": "clean",
        "action": "trash",
        "path": paths.0,
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": paths.1,
        "reclamation_id": "interrupted-run",
        "outcome": "pending",
    });
    let identity = degu_core::oplog::ObjectIdentity::capture(paths.1)
        .or_else(|_| degu_core::oplog::ObjectIdentity::capture(paths.0));
    if let Ok(identity) = identity {
        record["expected_identity"] = serde_json::to_value(identity).unwrap();
    }
    record
}

pub(super) fn seed_pending_fixture(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
) -> (PathBuf, PathBuf, PathBuf) {
    let staged_original = home.path().join(".cache/staged");
    let trash = private_trash_root(state);
    let staged_entry = trash.join("0001-staged");
    std::fs::create_dir_all(&staged_entry).unwrap();
    std::fs::write(staged_entry.join("data"), b"staged data").unwrap();
    let ambiguous_original = home.path().join(".cache/ambiguous");
    std::fs::create_dir_all(&ambiguous_original).unwrap();
    let ambiguous_entry = trash.join("0002-ambiguous");
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    let records = [
        pending_trash_record("2000-01-01T00:00:00Z", (&staged_original, &staged_entry)),
        pending_trash_record(
            "2000-01-01T00:00:01Z",
            (&ambiguous_original, &ambiguous_entry),
        ),
    ];
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    std::fs::write(state.path().join("degu/ops.jsonl"), format!("{jsonl}\n")).unwrap();
    (staged_original, staged_entry, ambiguous_entry)
}
