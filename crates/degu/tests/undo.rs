use std::path::{Path, PathBuf};

#[path = "support/clean_run.rs"]
mod clean_run;
#[path = "support/mod.rs"]
mod common;
#[path = "support/oplog_records.rs"]
mod oplog_records;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "support/pip_fixture.rs"]
mod pip_fixture;
#[path = "support/private_degu_state.rs"]
mod private_degu_state;
use clean_run::run as clean_pip_cache;
use common::isolated_degu as degu;
use oplog_records::oplog_records;
use pip_fixture::create as fake_pip_cache;
use std::os::unix::fs::PermissionsExt;

#[path = "undo/fixtures.rs"]
mod fixtures;
#[path = "undo/order.rs"]
mod order;
#[path = "undo/parent_identity.rs"]
mod parent_identity;
#[path = "undo/pending.rs"]
mod pending;
#[path = "undo/restore.rs"]
mod restore;

fn run_undo(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    json: bool,
) -> std::process::Output {
    let mut command = degu();
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .arg("undo");
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

fn fake_go_build_cache(home: &tempfile::TempDir) -> PathBuf {
    let cache = crate::common::platform_cache_dir(home.path(), "go-build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("artifact.a"), vec![0u8; 128 * 1024]).unwrap();
    cache
}

fn clean_all_caches(home: &tempfile::TempDir, state: &tempfile::TempDir) {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One clean is one reclamation group, and the reader who wants an older group
/// back must be able to name it: `degu undo` on its own takes the newest.
#[test]
fn undo_restores_the_reclamation_group_it_is_given() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    let older = seed_cache(&home, "go-build", 128 * 1024);
    clean_one(&home, &state);
    // Deliberately the larger of the two: the trash listing is ordered by size, so
    // this puts the newer group first and a test that indexed into that listing
    // instead of naming its group would reach for the wrong one.
    let newer = seed_cache(&home, "pip", 512 * 1024);
    clean_one(&home, &state);

    let older_group = staged_group_for(&home, &state, &older);
    let newer_group = staged_group_for(&home, &state, &newer);
    assert_ne!(older_group, newer_group, "two cleans are two groups");

    let out = undo_reclamation(&home, &state, &older_group);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(older.exists(), "the named group should be restored");
    assert_eq!(
        staged_reclamation_ids(&home, &state),
        vec![newer_group],
        "the group that was not named should still be staged"
    );
}

/// Naming a group nothing can act on is a mistake, not an empty run: answering
/// "nothing to undo" would read as though that group had already come back.
#[test]
fn undo_refuses_a_reclamation_group_it_cannot_find() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    seed_cache(&home, "go-build", 128 * 1024);
    clean_one(&home, &state);

    let out = undo_reclamation(&home, &state, "no-such-group");

    assert!(!out.status.success(), "an unknown group must not exit zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no-such-group"), "{stderr}");
    let staged = staged_reclamation_ids(&home, &state);
    assert!(stderr.contains(&staged[0]), "{stderr}");
}

/// Seed one cache where the scanner probes for it, then harden the tree.
///
/// degu refuses a group- or world-writable ancestor, and the umask a host happens
/// to run with decides whether `create_dir_all` produced one, so the fixture makes
/// that deterministic the same way the pip fixture does.
fn seed_cache(home: &tempfile::TempDir, name: &str, bytes: usize) -> PathBuf {
    let cache = crate::common::platform_cache_dir(home.path(), name);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("blob.bin"), vec![0u8; bytes]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    cache
}

/// Clean whatever is seeded right now, which is one cache per call here, so each
/// call produces one reclamation group.
///
/// A clean that stages nothing still exits zero, so that is asserted rather than
/// inferred: without it, a fixture the scanner stopped offering would fail later
/// and somewhere else.
/// A group whose staging never moved is still recorded, and naming it must not
/// read as a restore. Without the actionability check the run exited zero saying
/// `Restored 0 of 0`, and the same group was offered as undoable to a reader who
/// had named a different one.
#[test]
fn undo_refuses_a_named_group_whose_staging_never_moved() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), b"cached wheel").unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    // Recorded as begun, with the destination it would have moved to absent: the
    // move never happened, so there is nothing to put back.
    let never_moved = state.path().join("degu/trash/0001-pip-cache");
    write_oplog(
        &state,
        &[trash_record(
            "2000-01-01T00:00:00Z",
            (&cache, &never_moved),
            TrashStatus::Pending(Some("interrupted-run")),
        )],
    );

    let named = undo_reclamation(&home, &state, "interrupted-run");
    assert!(
        !named.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&named.stdout)
    );
    assert!(cache.exists(), "the original must be left alone");

    let other = undo_reclamation(&home, &state, "no-such-group");
    let stderr = String::from_utf8_lossy(&other.stderr);
    assert!(
        !stderr.contains("interrupted-run"),
        "a group that cannot be undone was offered: {stderr}"
    );
}

fn clean_one(home: &tempfile::TempDir, state: &tempfile::TempDir) {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("into the trash"),
        "the clean staged nothing: {stdout}"
    );
}

fn undo_reclamation(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    id: &str,
) -> std::process::Output {
    degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["undo", "--reclamation-id", id])
        .output()
        .unwrap()
}

/// The groups still staged, read the way the documentation tells a reader to find
/// them. The listing is ordered by size rather than by age, so a caller that wants
/// one particular group names it instead of indexing into this.
fn staged_reclamation_ids(home: &tempfile::TempDir, state: &tempfile::TempDir) -> Vec<String> {
    staged_rows(home, state)
        .iter()
        .filter_map(|row| row["reclamation_id"].as_str().map(str::to_owned))
        .collect()
}

/// The group that staged one cache. A staged entry is named after the directory it
/// came from, which is what ties a row back to the cache this test cleaned.
fn staged_group_for(home: &tempfile::TempDir, state: &tempfile::TempDir, cache: &Path) -> String {
    let suffix = format!("-{}", cache.file_name().unwrap().to_string_lossy());
    let rows = staged_rows(home, state);
    let row = rows
        .iter()
        .find(|row| row["entry"].as_str().is_some_and(|e| e.ends_with(&suffix)))
        .unwrap_or_else(|| panic!("no staged entry from {cache:?} in {rows:?}"));
    row["reclamation_id"]
        .as_str()
        .expect("a staged entry names its clean")
        .to_owned()
}

fn staged_rows(home: &tempfile::TempDir, state: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["trash", "list", "--json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    json["entries"].as_array().cloned().unwrap_or_default()
}

fn ok_trash_records(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|record| record["action"] == "trash" && record["outcome"] == "ok")
        .collect()
}

fn restore_records(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|record| record["action"] == "restore" && record["outcome"] != "pending")
        .collect()
}

fn final_trash_entry(records: &[serde_json::Value]) -> PathBuf {
    ok_trash_records(records)
        .first()
        .map(|record| record_trash_entry(record))
        .unwrap()
}

fn record_path(record: &serde_json::Value) -> PathBuf {
    PathBuf::from(record["path"].as_str().unwrap())
}

fn record_trash_entry(record: &serde_json::Value) -> PathBuf {
    PathBuf::from(record["trash_entry"].as_str().unwrap())
}

fn record_reclamation_id(record: &serde_json::Value) -> &str {
    record["reclamation_id"].as_str().unwrap()
}

#[derive(Clone, Copy)]
enum TrashStatus<'a> {
    Ok(Option<&'a str>),
    Pending(Option<&'a str>),
}

fn trash_record(ts: &str, paths: (&Path, &Path), status: TrashStatus<'_>) -> serde_json::Value {
    let pending = matches!(status, TrashStatus::Pending(_));
    let (outcome, reclamation_id) = match status {
        TrashStatus::Ok(id) => ("ok", id),
        TrashStatus::Pending(id) => ("pending", id),
    };
    let mut record = serde_json::json!({
        "ts": ts,
        "tool_version": "0.0.1",
        "command": "clean",
        "action": "trash",
        "path": paths.0,
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": paths.1,
        "outcome": outcome,
    });
    if let Some(id) = reclamation_id {
        record["reclamation_id"] = serde_json::json!(id);
    }
    let mut identity = degu_core::oplog::ObjectIdentity::capture(paths.1);
    if pending && identity.is_err() {
        identity = degu_core::oplog::ObjectIdentity::capture(paths.0);
    }
    if let Ok(identity) = identity {
        record["expected_identity"] = serde_json::to_value(identity).unwrap();
    }
    // Record the restore-destination parent so undo can authenticate it; without
    // it the record is treated as legacy and restore refuses.
    if let Some(parent) = paths.0.parent()
        && let Ok(parent_identity) = degu_core::oplog::ObjectIdentity::capture(parent)
    {
        record["destination_parent"] = serde_json::to_value(parent_identity).unwrap();
    }
    record
}

fn write_oplog(state: &tempfile::TempDir, records: &[serde_json::Value]) {
    let state_dir = private_degu_state::create(state);
    let trash = state_dir.join("trash");
    if trash.exists() {
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");
    std::fs::write(state_dir.join("ops.jsonl"), format!("{jsonl}\n")).unwrap();
}

fn detach_fixture_dir(path: &Path) -> tempfile::TempDir {
    let detached = tempfile::tempdir().unwrap();
    std::fs::rename(path, detached.path().join("entry")).unwrap();
    detached
}

/// One account whose store is really activated, so an undo takes the sealed path and
/// fails the way a sealed undo fails. The legacy seam refuses an occupied original
/// with a different error entirely.
struct SealedUndo {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    cache: PathBuf,
    anchor: PathBuf,
}

impl SealedUndo {
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().unwrap();
        common::require_sealed_fixture_backend(home.path())?;
        // Inside the home: a sealed store refuses an ancestor granting foreign rename
        // authority, and trash routing needs the state under the source mount's anchor.
        let state = tempfile::tempdir_in(home.path()).unwrap();
        let cache = common::platform_cache_dir(home.path(), "pip");
        let this = Self {
            home,
            state,
            cache,
            anchor: PathBuf::new(),
        };
        this.seed();
        let anchor = this.state.path().join("degu-integration-activation-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = std::fs::canonicalize(&anchor).unwrap();
        Some(Self { anchor, ..this })
    }

    /// Directories only: a sealed purge refuses a tree whose regular files carry any
    /// extended attribute, and some filesystems attach one to every file written.
    fn seed(&self) {
        std::fs::create_dir_all(self.cache.join("http-v2/aa")).unwrap();
        common::make_tree_non_shared_writable(self.home.path()).unwrap();
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("XDG_CONFIG_HOME", common::isolated_config_home())
            .env("LOGNAME", common::isolated_config_home())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN.
            .args(args)
            .output()
            .unwrap()
    }
}

/// Clean a cache, let its tool refill it, then change your mind. degu refuses to
/// overwrite what is there now, which is right — and the refusal has to say that, in
/// words the reader can act on, rather than hand back the transaction bytes and the
/// wrappers each layer added on the way out.
#[test]
fn an_undo_onto_an_occupied_original_says_what_to_do_about_it() {
    let Some(fixture) = SealedUndo::new() else {
        return;
    };
    let staged = fixture.run(&["clean", "--yes", "--json"]);
    assert!(
        staged.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    assert!(!fixture.cache.exists());
    // The tool that owns the cache puts it back.
    fixture.seed();

    let out = fixture.run(&["undo", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["restored"].as_array().unwrap().is_empty(),
        "report: {report}"
    );
    let failed = report["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1, "report: {report}");
    let reason = failed[0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("already holds something") && reason.contains("undo again"),
        "the refusal does not say what happened or what to do: {reason}"
    );
    assert!(
        !reason.contains("TransactionId("),
        "a WAL transaction's bytes reached the reader: {reason}"
    );
    // The staged copy is still there, which is what the message promises.
    let listed = fixture.run(&["trash", "list", "--json"]);
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["entries"].as_array().unwrap().len(), 1);
}
