use super::support::*;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

fn aged_claim_marker(state: &tempfile::TempDir) -> std::path::PathBuf {
    let claims = private_trash_root(state).join(".claims");
    std::fs::create_dir_all(&claims).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = claims.join("12345");
    let file = std::fs::File::create(&marker).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(8 * 86_400))
        .unwrap();
    marker
}

#[test]
fn xdg_state_parent_alias_does_not_block_trash_purge() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let alias = state.path().join("alias");
    let real = state.path().join("real");
    std::fs::create_dir(&alias).unwrap();
    std::fs::create_dir(&real).unwrap();
    let request = alias.join("..").join("real");
    let cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), b"cache").unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    crate::common::make_tree_non_shared_writable(state.path()).unwrap();
    let staged = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", &request)
        .args(["clean", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(
        staged.status.success(),
        "{}",
        String::from_utf8_lossy(&staged.stderr)
    );

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", &request)
        .args(["trash", "purge", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["purged"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["quota_observations"]["observation_state"],
        "resolved"
    );
}

#[test]
fn trash_json_empty_entries_still_runs_observed_claim_housekeeping() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let marker = aged_claim_marker(&state);

    let out = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["purged"].as_array().unwrap().is_empty());
    assert_eq!(
        report["quota_observations"]["observation_state"],
        "resolved"
    );
}

#[test]
fn trash_human_empty_entries_still_runs_claim_housekeeping() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let marker = aged_claim_marker(&state);

    let out = run(&home, &state, &["trash", "purge", "--yes"]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("expired trash claim markers, if present, will be permanently deleted")
    );
    assert!(stdout.contains("Purged 0 trash entries"));
    assert!(!stdout.contains("Trash is empty."));
}

#[test]
fn trash_purge_colors_the_permanent_deletion_plan() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);

    let out = run(
        &home,
        &state,
        &["--color", "always", "trash", "purge", "--yes"],
    );

    assert!(out.status.success());
    assert!(out.stdout.windows(2).any(|window| window == b"\x1b["));
    assert!(
        out.stdout
            .windows(b"purge-supported entries".len())
            .any(|window| window == b"purge-supported entries")
    );
}

#[test]
fn trash_purge_yes_json_empties_trash_and_writes_oplog() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    let trash_dir = state.path().join("degu/trash");
    let trash_entry = visible_trash_entries(&trash_dir).pop().unwrap();

    let out = run(&home, &state, &["trash", "purge", "--yes", "--json"]);
    assert!(out.status.success());
    assert!(visible_trash_entries(&trash_dir).is_empty());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let purged = report["purged"].as_array().unwrap();
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], trash_entry.to_string_lossy().as_ref());

    let log = std::fs::read_to_string(state.path().join("degu/ops.jsonl")).unwrap();
    let records = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let purge = records
        .iter()
        .filter(|record| record["action"] == "purge")
        .collect::<Vec<_>>();
    assert_eq!(purge.len(), 2);
    assert_eq!(purge[0]["outcome"], "pending");
    assert_eq!(purge[1]["outcome"], "ok");
    assert_eq!(purge[0]["path"], purge[1]["path"]);
}

#[cfg(target_os = "linux")]
#[test]
fn trash_json_rejects_non_utf8_entries_before_purge() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let trash = private_trash_root(&state);
    let entry = trash.join(std::ffi::OsString::from_vec(b"entry-\xff".to_vec()));
    std::fs::write(&entry, b"must survive").unwrap();

    let list = run(&home, &state, &["trash", "list", "--json"]);
    assert!(list.status.success());
    let report: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(report["entries"].as_array().unwrap().is_empty());
    assert!(report["omitted"].as_u64().unwrap() >= 1);
    let stderr = String::from_utf8(list.stderr).unwrap();
    assert!(!stderr.contains("panicked"));

    let purge = run(&home, &state, &["trash", "purge", "--yes", "--json"]);
    assert!(!purge.status.success());
    assert!(purge.stdout.is_empty());
    assert_eq!(std::fs::read(&entry).unwrap(), b"must survive");
    assert!(!state.path().join("degu/ops.jsonl").exists());
    let stderr = String::from_utf8(purge.stderr).unwrap();
    assert!(stderr.contains("path contains invalid UTF-8"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn trash_purge_all_still_removes_ambiguous_entries() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (_, staged_entry, ambiguous_entry) = seed_pending_fixture(&home, &state);

    let out = run(&home, &state, &["trash", "purge", "--yes", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["purged"].as_array().unwrap().len(), 2);
    assert!(!staged_entry.exists());
    assert!(!ambiguous_entry.exists());

    let out = run(&home, &state, &["undo"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "Nothing to undo.\n");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("ambiguous"), "stderr: {stderr}");
}

#[test]
fn trash_purge_rejects_non_explicit_confirmation() {
    for input in ["y", "Purge", "PURGE"] {
        let (home, state, _) = fake_pip_cache();
        clean_pip_cache(&home, &state);
        let trash_dir = state.path().join("degu/trash");
        let trash_entry = visible_trash_entries(&trash_dir).pop().unwrap();
        let out = run_interactive_purge(home.path(), state.path(), input);

        assert!(!out.status.success(), "accepted {input:?}");
        assert_eq!(visible_trash_entries(&trash_dir), vec![trash_entry.clone()]);
        let transcript = String::from_utf8(out.stdout).unwrap();
        assert!(transcript.contains("\u{1b}["));
        assert!(transcript.contains("Purge cancelled; no trash entries were deleted."));
        assert!(transcript.contains("Type 'purge' to permanently delete"));
        let relative_entry = trash_entry.strip_prefix(home.path()).unwrap();
        let displayed_entry = format!("~/{}", relative_entry.display());
        assert!(
            transcript.contains(&trash_entry.display().to_string())
                || transcript.contains(&displayed_entry),
            "transcript: {transcript}"
        );
        assert!(transcript.find("Purge plan:").unwrap() < transcript.find("Type 'purge'").unwrap());
    }
}

#[test]
fn trash_purge_accepts_only_explicit_purge_confirmation() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    let trash_dir = state.path().join("degu/trash");
    let out = run_interactive_purge(home.path(), state.path(), "purge");

    assert!(out.status.success());
    assert!(visible_trash_entries(&trash_dir).is_empty());
}

#[test]
fn trash_purge_confirmation_cannot_expand_to_concurrently_staged_data() {
    let (home, state, cache) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("new-wheel.whl"), b"new cache").unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    let out = run_purge_during_concurrent_clean(home.path(), state.path());

    assert!(out.status.success());
    assert!(
        cache.exists(),
        "confirmation admitted a concurrently staged entry"
    );
    let transcript = String::from_utf8(out.stdout).unwrap();
    assert!(
        transcript.contains("concurrent clean status: 1"),
        "{transcript}"
    );
    assert!(
        transcript.contains("another degu operation holds the mutation lock"),
        "{transcript}"
    );
}

#[test]
fn trash_purge_executes_only_the_plan_shown_before_confirmation() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    let trash_dir = state.path().join("degu/trash");
    let late_entry = trash_dir.join("9999-late-entry");
    let out = run_purge_with_late_entry(home.path(), state.path(), &late_entry);

    assert!(out.status.success());
    assert!(
        late_entry.exists(),
        "purge reselected entries after confirmation"
    );
    assert_eq!(visible_trash_entries(&trash_dir), vec![late_entry]);
}

#[test]
fn trash_purge_rejects_an_entry_replaced_after_confirmation() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    let trash_dir = state.path().join("degu/trash");
    let planned_entry = visible_trash_entries(&trash_dir).pop().unwrap();
    let out = run_purge_with_replaced_entry(state.path(), state.path(), &planned_entry);

    assert!(!out.status.success());
    assert_eq!(
        std::fs::read(planned_entry.join("replacement.txt")).unwrap(),
        b"replacement data"
    );
    let transcript = String::from_utf8(out.stdout).unwrap();
    assert!(transcript.contains("identity changed after confirmation"));
    assert!(transcript.contains(&format!("failed to purge {}", planned_entry.display())));
}

#[test]
fn trash_purge_rejects_symlinked_managed_roots() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let victim = target.path().join("must-survive");
    std::fs::write(&victim, "user data").unwrap();
    let degu_state = private_degu_state(&state);
    symlink(target.path(), degu_state.join("trash")).unwrap();

    let output = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(!output.status.success());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "user data");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("trash root is not a real directory"));
}

#[test]
fn trash_purge_accepts_legacy_registry_but_rejects_symlinked_root() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let registered = external.path().join(".degu-trash");
    let victim = target.path().join("must-survive");
    std::fs::write(&victim, "user data").unwrap();
    symlink(target.path(), &registered).unwrap();
    let degu_state = private_degu_state(&state);
    std::fs::write(
        degu_state.join("trashroots"),
        format!("{}\n", registered.display()),
    )
    .unwrap();

    let output = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(!output.status.success());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "user data");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("using legacy unquoted trash registry line"));
    assert!(stderr.contains("trash root is not a real directory"));
}

#[test]
fn trash_purge_rejects_a_symlinked_claims_directory() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let trash = private_trash_root(&state);
    std::fs::write(trash.join("0001-cache"), "planned cache").unwrap();
    let victim = external.path().join("1234");
    std::fs::write(&victim, "must survive").unwrap();
    symlink(external.path(), trash.join(".claims")).unwrap();

    let output = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(!output.status.success());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "must survive");
    assert_eq!(
        std::fs::read_to_string(trash.join("0001-cache")).unwrap(),
        "planned cache"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("purge claims path is not a real directory"));
}

/// Two staged origins, so a selector has something to leave behind.
fn two_staged_origins() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, PathBuf) {
    let (home, state, pip) = fake_pip_cache();
    let go = crate::common::platform_cache_dir(home.path(), "go-build");
    std::fs::create_dir_all(&go).unwrap();
    std::fs::write(go.join("blob.bin"), vec![0u8; 4096]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    // `--path` compares against the origin the operation log recorded, which
    // is resolved. Take the resolved form here, while the origins still exist.
    let pip = std::fs::canonicalize(&pip).unwrap();
    let go = std::fs::canonicalize(&go).unwrap();
    clean_pip_cache(&home, &state);
    assert_eq!(
        visible_trash_entries(&private_trash_root(&state)).len(),
        2,
        "both origins must stage for a selector to be meaningful"
    );
    (home, state, pip, go)
}

fn staged_from(state: &tempfile::TempDir, origin: &Path) -> PathBuf {
    let name = origin.file_name().unwrap().to_string_lossy().into_owned();
    visible_trash_entries(&private_trash_root(state))
        .into_iter()
        .find(|entry| entry.file_name().unwrap().to_string_lossy().contains(&name))
        .unwrap_or_else(|| panic!("no staged entry for {}", origin.display()))
}

fn remaining_origins(state: &tempfile::TempDir) -> Vec<String> {
    visible_trash_entries(&private_trash_root(state))
        .into_iter()
        .map(|entry| entry.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn purge_path_removes_only_entries_staged_from_that_origin() {
    let (home, state, pip, _) = two_staged_origins();

    let out = run(
        &home,
        &state,
        &["trash", "purge", "--yes", "--path", pip.to_str().unwrap()],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left = remaining_origins(&state);
    assert_eq!(left.len(), 1, "left: {left:?}");
    assert!(left[0].contains("go-build"), "left: {left:?}");
}

#[test]
fn purge_path_matches_a_parent_of_the_origin() {
    let (home, state, pip, _) = two_staged_origins();
    let parent = pip.parent().unwrap().to_path_buf();

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--path",
            parent.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        remaining_origins(&state).is_empty(),
        "a parent selector must reach every origin beneath it"
    );
}

/// Narrowing chooses which entries are destroyed, not whether housekeeping
/// runs. degu has no background timer, so a reader who only ever purges
/// selectively would otherwise accumulate expired claims forever.
#[test]
fn purge_path_still_runs_expired_claim_housekeeping() {
    let (home, state, pip, _) = two_staged_origins();
    let marker = aged_claim_marker(&state);
    assert!(marker.exists());

    let out = run(
        &home,
        &state,
        &["trash", "purge", "--yes", "--path", pip.to_str().unwrap()],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists(), "expired claim housekeeping was skipped");
}

#[test]
fn purge_entry_removes_only_the_named_entry() {
    let (home, state, pip, _) = two_staged_origins();
    let entry = staged_from(&state, &pip);

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--entry",
            entry.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left = remaining_origins(&state);
    assert_eq!(left.len(), 1, "left: {left:?}");
    assert!(left[0].contains("go-build"), "left: {left:?}");
}

/// An exact selection is all or nothing: a name that no longer resolves to a
/// managed entry refuses the batch rather than destroying the rest of it.
#[test]
fn purge_entry_refuses_the_whole_plan_when_one_name_is_gone() {
    let (home, state, pip, _) = two_staged_origins();
    let entry = staged_from(&state, &pip);
    let missing = private_trash_root(&state).join("9999-never-staged");
    let before = remaining_origins(&state);

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--entry",
            entry.to_str().unwrap(),
            "--entry",
            missing.to_str().unwrap(),
        ],
    );

    assert!(!out.status.success(), "a missing entry was accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no longer available"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        remaining_origins(&state),
        before,
        "the batch was partly executed before it was refused"
    );
}

/// The selector matches whole path components. A refactor to a string prefix
/// would silently widen every selection to its lexical neighbours, so a name
/// that merely starts with the selector must not match.
#[test]
fn purge_path_does_not_match_a_sibling_sharing_a_name_prefix() {
    let (home, state, _, go) = two_staged_origins();
    let prefix = go.parent().unwrap().join("go");
    assert!(
        go.to_string_lossy().starts_with(prefix.to_str().unwrap()),
        "the fixture must share a lexical prefix for this to be a boundary test"
    );
    let before = remaining_origins(&state);

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--path",
            prefix.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        remaining_origins(&state),
        before,
        "a lexical prefix reached a sibling it does not contain"
    );
}

/// The operation log records an absolute origin. A selector typed relative to
/// the shell's directory used to match nothing and report a successful purge
/// of zero entries, which reads as "there was nothing there".
#[test]
fn purge_path_resolves_a_selector_against_the_current_directory() {
    let (home, state, pip, _) = two_staged_origins();
    // The origins are resolved; the shell's directory has to be too, or the
    // selector resolves to a path the operation log never recorded.
    let resolved_home = std::fs::canonicalize(home.path()).unwrap();
    let relative = pip.strip_prefix(&resolved_home).unwrap().to_path_buf();
    assert!(
        relative.is_relative(),
        "the fixture must produce a relative selector"
    );

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .current_dir(&resolved_home)
        .args(["trash", "purge", "--yes", "--path"])
        .arg(&relative)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left = remaining_origins(&state);
    assert_eq!(
        left.len(),
        1,
        "a relative selector matched nothing: {left:?}"
    );
    assert!(left[0].contains("go-build"), "left: {left:?}");
}

/// The operation log records a resolved origin, so a selector that reaches the
/// same place through `..` names the same entry. Comparing lexically would
/// silently match nothing and report a successful purge of zero entries.
#[test]
fn purge_path_accepts_a_selector_carrying_a_parent_component() {
    let (home, state, pip, _) = two_staged_origins();
    let parent = pip.parent().unwrap();
    let detoured = parent
        .join("..")
        .join(parent.file_name().unwrap())
        .join(pip.file_name().unwrap());

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--path",
            detoured.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left = remaining_origins(&state);
    assert_eq!(left.len(), 1, "a `..` selector matched nothing: {left:?}");
    assert!(left[0].contains("go-build"), "left: {left:?}");
}

/// The same place reached through a symlinked ancestor is the same place. The
/// staged origin is gone by now, so only the surviving ancestor can be
/// resolved — which is enough to land in the recorded namespace.
#[test]
fn purge_path_accepts_a_selector_through_a_symlinked_ancestor() {
    let (home, state, pip, _) = two_staged_origins();
    let caches = pip.parent().unwrap();
    let alias = home.path().join("cache-alias");
    symlink(caches, &alias).unwrap();
    let through_alias = alias.join(pip.file_name().unwrap());

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--path",
            through_alias.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left = remaining_origins(&state);
    assert_eq!(
        left.len(),
        1,
        "a symlinked ancestor matched nothing: {left:?}"
    );
    assert!(left[0].contains("go-build"), "left: {left:?}");
}

/// A selector that reaches no staged origin is legitimate, but it must say so:
/// otherwise a mistyped path is indistinguishable from an empty selection.
#[test]
fn purge_path_names_a_selector_that_reached_nothing() {
    let (home, state, _, _) = two_staged_origins();
    let absent = home.path().join("Library/Caches/never-staged");
    let before = remaining_origins(&state);

    let out = run(
        &home,
        &state,
        &[
            "trash",
            "purge",
            "--yes",
            "--path",
            absent.to_str().unwrap(),
        ],
    );

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("never-staged") && stderr.contains("removed nothing"),
        "an unmatched selector was not named: {stderr}"
    );
    assert_eq!(remaining_origins(&state), before);
}
