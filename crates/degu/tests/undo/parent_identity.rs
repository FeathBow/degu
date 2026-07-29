//! Restore destination-parent authentication (issue #254).
//!
//! `degu undo`/purge-rollback must move a trashed entry back only into the
//! physical directory it came from. A swapped ancestor symlink, or a
//! delete-and-replace of the destination parent, must be refused with the trash
//! entry left intact. Legitimate relocations through a stable symlink must still
//! restore to the physical location.

#![cfg(any(target_os = "linux", target_vendor = "apple"))]

use super::*;

/// The cache-home dir pip's default lives under: `Library/Caches` on macOS
/// (which ignores XDG_CACHE_HOME), `.cache` elsewhere.
#[cfg(target_os = "macos")]
const CACHE_HOME_SUBDIR: &str = "Library/Caches";
#[cfg(not(target_os = "macos"))]
const CACHE_HOME_SUBDIR: &str = ".cache";

fn undo_json(home: &tempfile::TempDir, state: &tempfile::TempDir) -> (bool, serde_json::Value) {
    let out = run_undo(home, state, true);
    let success = out.status.success();
    let report = serde_json::from_slice(&out.stdout).unwrap();
    (success, report)
}

fn staged_trash_entry(state: &tempfile::TempDir) -> std::path::PathBuf {
    let records = oplog_records(state);
    final_trash_entry(&records)
}

/// Symlink the platform cache-home (`home/<CACHE_HOME_SUBDIR>`) at `alias` and
/// point it at `physical_cache_home`, so pip's default probe resolves through the
/// symlink. The staged record captures the physical parent that `alias` resolves
/// to; the returned path is the logical `alias/pip` value (what the record
/// reports). No XDG env is set: macOS pip ignores it, and the symlinked default
/// works on both platforms.
fn clean_through_alias(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    alias: &std::path::Path,
    physical_cache_home: &std::path::Path,
) -> std::path::PathBuf {
    let physical_cache = physical_cache_home.join("pip");
    std::fs::create_dir_all(&physical_cache).unwrap();
    std::fs::write(physical_cache.join("wheel.whl"), [7_u8; 2048]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "clean stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!physical_cache.exists());
    // degu reports the logical path from the canonicalized HOME plus the cache-home
    // suffix (it does not resolve the cache-home symlink). `alias` is unused for the
    // returned value but stays the manipulable symlink for ancestor-swap fixtures.
    let _ = alias;
    home.path()
        .canonicalize()
        .unwrap()
        .join(CACHE_HOME_SUBDIR)
        .join("pip")
}

// (1) Post-stage ancestor-symlink swap must be refused: nothing moves, the trash
// entry stays intact, and the evil target is untouched.
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the attack fixture swaps an ancestor symlink with a raw remove_file; the verified deletion engine is the subject under test"
)]
fn undo_refuses_a_swapped_ancestor_symlink() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let real_cache_home = tempfile::tempdir().unwrap();
    let evil = tempfile::tempdir().unwrap();
    let evil_witness = evil.path().join("witness");
    std::fs::write(&evil_witness, b"do-not-touch").unwrap();

    // The swappable ancestor symlink is the platform cache-home pip resolves through.
    let alias = home.path().join(CACHE_HOME_SUBDIR);
    std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(real_cache_home.path(), &alias).unwrap();

    let cache = clean_through_alias(&home, &state, &alias, real_cache_home.path());
    let entry = staged_trash_entry(&state);

    // Swap the ancestor symlink so the logical cache path now resolves into evil.
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(evil.path(), &alias).unwrap();

    let (success, report) = undo_json(&home, &state);
    assert!(!success);
    let failed = report["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["path"], cache.to_string_lossy().as_ref());
    assert!(report["restored"].as_array().unwrap().is_empty());
    assert!(entry.join("wheel.whl").exists());
    assert!(!evil.path().join("pip").exists());
    assert_eq!(std::fs::read(&evil_witness).unwrap(), b"do-not-touch");
}

// (2) Post-stage the physical parent is deleted and replaced by a fresh
// directory with a new inode. same_object on the parent refuses.
#[test]
fn undo_refuses_a_replaced_destination_parent() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache_home = home.path().join(CACHE_HOME_SUBDIR);
    std::fs::create_dir_all(&cache_home).unwrap();

    let cache = cache_home.join("pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [7_u8; 2048]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let entry = staged_trash_entry(&state);

    // Replace the cache-home with a fresh directory: the physical inode changes.
    let detached = tempfile::tempdir().unwrap();
    std::fs::rename(&cache_home, detached.path().join("old-cache")).unwrap();
    std::fs::create_dir(&cache_home).unwrap();

    let (success, report) = undo_json(&home, &state);
    assert!(!success);
    assert_eq!(report["failed"].as_array().unwrap().len(), 1);
    assert!(report["restored"].as_array().unwrap().is_empty());
    assert!(entry.join("wheel.whl").exists());
    assert!(!cache.exists());
}

// (4) A stable relocation through a cache-home symlink restores to the physical
// location.
#[test]
fn undo_restores_through_a_stable_cache_symlink() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let physical = tempfile::tempdir().unwrap();
    let dot_cache = home.path().join(CACHE_HOME_SUBDIR);
    std::fs::create_dir_all(dot_cache.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(physical.path(), &dot_cache).unwrap();

    let cache = dot_cache.join("pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [7_u8; 2048]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!physical.path().join("pip").exists());

    let (success, report) = undo_json(&home, &state);
    assert!(success, "undo report: {report}");
    assert_eq!(report["restored"].as_array().unwrap().len(), 1);
    assert!(report["failed"].as_array().unwrap().is_empty());
    // Restored into the physical directory the symlink resolves to.
    assert!(physical.path().join("pip/wheel.whl").exists());
}

// (5) A cache-home symlinked to a scratch directory restores to the physical
// location.
#[test]
fn undo_restores_through_symlinked_xdg_cache_home() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    // The platform cache-home is a symlink into the scratch directory.
    let alias = home.path().join(CACHE_HOME_SUBDIR);
    std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(scratch.path(), &alias).unwrap();

    let cache = clean_through_alias(&home, &state, &alias, scratch.path());

    let (success, report) = undo_json(&home, &state);
    assert!(success, "undo report: {report}");
    assert_eq!(report["restored"].as_array().unwrap().len(), 1);
    assert!(report["failed"].as_array().unwrap().is_empty());
    assert!(scratch.path().join("pip/wheel.whl").exists());
    // The reported path stays the logical configured value, not the canonical one.
    assert_eq!(
        report["restored"][0]["path"],
        cache.to_string_lossy().as_ref()
    );
}

// (6) A PIP_CACHE_DIR-style logical path whose ancestor is a symlink to scratch
// restores to the physical location. degu reports env-redirected caches as
// report-only, so the staged record is seeded directly with the physical parent
// identity resolved through the symlink.
#[test]
fn undo_restores_through_symlinked_pip_cache_dir() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let alias_parent = tempfile::tempdir().unwrap();
    let alias = alias_parent.path().join("scratch-pip");
    std::os::unix::fs::symlink(scratch.path(), &alias).unwrap();

    // The logical restore destination sits under the symlinked ancestor.
    let logical = alias.join("pip");
    let entry = state.path().join("degu/trash/0001-pip");
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::write(entry.join("blob"), b"pip cache").unwrap();

    let mut record = trash_record(
        "2000-01-01T00:00:00Z",
        (&logical, &entry),
        TrashStatus::Ok(Some("run")),
    );
    // Record the physical scratch directory identity, resolved through the
    // symlinked ancestor, exactly as the stage path would capture it.
    let physical_parent = std::fs::canonicalize(&alias).unwrap();
    let parent_identity = degu_core::oplog::ObjectIdentity::capture(&physical_parent).unwrap();
    record["destination_parent"] = serde_json::to_value(parent_identity).unwrap();
    write_oplog(&state, &[record]);

    let (success, report) = undo_json(&home, &state);
    assert!(success, "undo report: {report}");
    assert!(report["failed"].as_array().unwrap().is_empty());
    assert!(!report["restored"].as_array().unwrap().is_empty());
    // Restored into the physical scratch directory the symlink resolves to.
    assert!(scratch.path().join("pip/blob").exists());
    // The reported path stays the logical configured value.
    assert_eq!(
        report["restored"][0]["path"],
        logical.to_string_lossy().as_ref()
    );
}

// (7) A legacy record (no destination_parent) is refused with actionable
// guidance, counts as a failure (nonzero exit), and leaves the trash entry
// re-discoverable.
#[test]
fn undo_refuses_a_legacy_record_without_destination_parent() {
    let (home, state, _) = fake_pip_cache();
    let cache = home.path().join(".cache/legacy");
    let entry = state.path().join("degu/trash/0001-legacy");
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::write(entry.join("data"), b"legacy").unwrap();

    // A record shaped like a pre-#254 log line: no destination_parent field.
    let mut record = trash_record(
        "2000-01-01T00:00:00Z",
        (&cache, &entry),
        TrashStatus::Ok(Some("legacy-run")),
    );
    record.as_object_mut().unwrap().remove("destination_parent");
    write_oplog(&state, &[record]);

    let out = run_undo(&home, &state, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("restore refused"));
    assert!(stdout.contains(&cache.display().to_string()));
    assert!(stdout.contains(&entry.display().to_string()));
    assert!(stdout.contains("mv"));
    assert!(!cache.exists());
    assert!(entry.join("data").exists());

    // The refusal made no filesystem change, so the trash entry is still listed.
    let list = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["trash", "list", "--json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(report["omitted"], 0);
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
}

// (9) The destination parent disappears entirely before restore (ENOENT).
#[test]
fn undo_refuses_when_the_destination_parent_is_gone() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache_home = home.path().join(CACHE_HOME_SUBDIR);
    std::fs::create_dir_all(&cache_home).unwrap();
    let cache = cache_home.join("pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [7_u8; 2048]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let entry = staged_trash_entry(&state);

    // Remove the destination parent entirely.
    let detached = tempfile::tempdir().unwrap();
    std::fs::rename(&cache_home, detached.path().join("old-cache")).unwrap();

    let (success, report) = undo_json(&home, &state);
    assert!(!success);
    assert_eq!(report["failed"].as_array().unwrap().len(), 1);
    assert!(report["restored"].as_array().unwrap().is_empty());
    assert!(entry.join("wheel.whl").exists());
}
