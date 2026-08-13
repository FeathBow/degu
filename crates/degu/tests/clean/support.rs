use crate::pty::{PtyRun, run as run_pty};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;

const EXPIRED_AGE_DAYS: u64 = 8;
const SECONDS_PER_DAY: u64 = 86_400;
const TRASH_TTL_DAYS: u64 = 7;
const EXPIRED_AGE: std::time::Duration =
    std::time::Duration::from_secs(EXPIRED_AGE_DAYS * SECONDS_PER_DAY);

pub(super) use crate::common::isolated_config_home as test_config_home;
pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::human_bytes::assert_human_bytes;
pub(super) use crate::next_command::assert_next_command;
pub(super) use crate::oplog_records::oplog_records;
pub(super) use crate::sgr_assertion::assert_sgr_color;
pub(super) use crate::strip_sgr::strip_sgr;
pub(super) use crate::trash_entries::visible as visible_trash_entries;

pub(super) fn fake_pip_cache(
    home: &tempfile::TempDir,
    cache_subdir: &str,
) -> (std::path::PathBuf, tempfile::TempDir) {
    let state = tempfile::tempdir().unwrap();
    // The plain `.cache/pip` request means "the pip default"; seed where the
    // scanner probes on this platform. Explicit non-default subdirs pass through.
    let cache = if cache_subdir == ".cache/pip" {
        crate::common::platform_cache_dir(home.path(), "pip")
    } else {
        home.path().join(cache_subdir)
    };
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    (cache, state)
}

pub(super) fn seed_expired_trash_entry(state: &tempfile::TempDir) -> std::path::PathBuf {
    seed_expired_trash_entry_named(state, "0001-old-cache")
}

pub(super) fn seed_expired_trash_entry_named(
    state: &tempfile::TempDir,
    name: &str,
) -> std::path::PathBuf {
    let trash_dir = private_trash_root(state);
    let entry = trash_dir.join(name);
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::write(entry.join("payload.bin"), [0u8; 1024]).unwrap();
    let staged_at = jiff::Timestamp::try_from(expired_time()).unwrap();
    let identity = degu_core::oplog::ObjectIdentity::capture(&entry).unwrap();
    let record = serde_json::json!({
        "ts": staged_at.to_string(),
        "tool_version": "0.0.0",
        "command": "clean",
        "action": "trash",
        "path": "/nonexistent/original/old-cache",
        "bytes_allocated": 1024,
        "inodes": 2,
        "trash_entry": entry.to_string_lossy(),
        "expected_identity": identity,
        "outcome": "ok",
    });
    std::fs::write(state.path().join("degu/ops.jsonl"), format!("{record}\n")).unwrap();
    entry
}

pub(super) fn private_trash_root(state: &tempfile::TempDir) -> std::path::PathBuf {
    let trash = crate::private_degu_state::create(state).join("trash");
    std::fs::create_dir_all(&trash).unwrap();
    std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).unwrap();
    trash
}

pub(super) fn expired_time() -> std::time::SystemTime {
    std::time::SystemTime::now() - EXPIRED_AGE
}

pub(super) fn fake_conda_env(home: &tempfile::TempDir) -> std::path::PathBuf {
    let env = home.path().join("miniconda3/envs/myenv");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
    env
}

pub(super) fn canonical_path_string(path: &std::path::Path) -> String {
    path.canonicalize().unwrap().to_string_lossy().into_owned()
}

pub(super) fn write_oplog(state: &tempfile::TempDir, records: &[serde_json::Value]) {
    std::fs::create_dir_all(state.path().join("degu")).unwrap();
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    std::fs::write(state.path().join("degu/ops.jsonl"), format!("{jsonl}\n")).unwrap();
}

/// Terminal form of the clean plan: a Plan headline, the trash destination
/// on its own line under "To:", then the restorability note.
pub(super) fn assert_plan_block(stdout: &str, state: &tempfile::TempDir) {
    assert!(stdout.contains("move 1 location"), "stdout: {stdout}");
    let trash_dir = state.path().join("degu/trash");
    let lines: Vec<&str> = stdout.lines().map(str::trim_end).collect();
    let to = lines
        .iter()
        .position(|line| *line == "To:")
        .unwrap_or_else(|| panic!("missing To: line in stdout: {stdout}"));
    assert_eq!(
        lines[to + 1],
        format!("  {}", trash_dir.display()),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "Restorable with degu undo; a later clean may purge it after {TRASH_TTL_DAYS} days."
        )),
        "stdout: {stdout}"
    );
}

pub(super) fn assert_mechanism_line(stdout: &str, state: &tempfile::TempDir, purge: bool) {
    let trash_dir = state.path().join("degu/trash");
    assert!(stdout.contains("Plan: move 1 location ("));
    assert!(stdout.contains(&format!(" to {} ", trash_dir.display())));
    if purge {
        assert!(stdout.contains(
            "sealed, staged, and permanently deleted through exact object-bound authority; not restorable."
        ));
        assert!(!stdout.contains("restorable with degu undo"));
    } else {
        assert!(stdout.contains("restorable with degu undo"));
        assert!(stdout.contains(&format!(
            "a later clean may purge it after {} days.",
            TRASH_TTL_DAYS
        )));
    }
}

pub(super) fn run_interactive_clean(
    home: &std::path::Path,
    state: &std::path::Path,
) -> std::process::Output {
    let body = r#"
spawn $env(DEGU_BIN) clean
expect -exact {Proceed? [y/N] }
send "y\r"
"#;
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &[],
    })
}

pub(super) fn run_interactive_clean_purge(
    home: &std::path::Path,
    state: &std::path::Path,
    permanent_response: &str,
) -> std::process::Output {
    let body = r#"
spawn $env(DEGU_BIN) clean --purge
expect -exact {Proceed? [y/N] }
send "y\r"
expect -exact {Type 'purge' to permanently delete this plan: }
send "$env(PERMANENT_RESPONSE)\r"
"#;
    let extra_env = [("PERMANENT_RESPONSE", OsStr::new(permanent_response))];
    run_pty(PtyRun {
        body,
        home,
        config_home: test_config_home(),
        state_home: state,
        extra_env: &extra_env,
    })
}

pub(super) fn run_clean(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    args: &[&str],
) -> std::process::Output {
    let mut command = degu();
    crate::common::with_mutation_anchor(&mut command, state.path());
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(args)
        .output()
        .unwrap()
}

/// Extracts the review preview command scan printed, pins its exact shape,
/// and returns its arguments as the shell would pass them to degu.
pub(super) fn review_preview_args(
    scan_stdout: &str,
    expected: &str,
    home: &std::path::Path,
) -> Vec<String> {
    let command = scan_stdout
        .lines()
        .find_map(|line| line.find("degu clean ").map(|at| line[at..].trim_end()))
        .unwrap_or_else(|| panic!("no review preview command in stdout: {scan_stdout}"));
    assert_eq!(command, expected, "stdout: {scan_stdout}");
    command
        .split(' ')
        .skip(1)
        .map(|arg| match arg.strip_prefix("~/") {
            Some(rest) => home.join(rest).to_str().unwrap().to_string(),
            None => arg.to_string(),
        })
        .collect()
}

/// Mode 0o000 does not bar root, so permission-denial fixtures cannot bite.
#[cfg(unix)]
pub(super) fn root_ignores_dir_modes() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(unix)]
pub(super) fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) fn run_terminal_clean_path(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    path: &std::path::Path,
) -> std::process::Output {
    let body = r#"
spawn -noecho $env(DEGU_BIN) clean --dry-run --path $env(CLEAN_PATH)
"#;
    let extra_env = [("CLEAN_PATH", path.as_os_str())];
    run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &extra_env,
    })
}
