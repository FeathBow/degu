use super::support::*;
use std::os::unix::fs::PermissionsExt;

fn seed_aged_numeric_marker(state: &tempfile::TempDir) -> std::path::PathBuf {
    let claims = private_trash_root(state).join(".claims");
    std::fs::create_dir_all(&claims).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = claims.join("12345");
    let file = std::fs::File::create(&marker).unwrap();
    file.set_modified(expired_time()).unwrap();
    marker
}

fn seed_expired_interrupted_claim(state: &tempfile::TempDir) -> std::path::PathBuf {
    let trash = private_trash_root(state);
    let claims = trash.join(".claims");
    let claim = claims.join("purge-interrupted");
    std::fs::create_dir_all(&claim).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(claim.join("payload.bin"), [0u8; 1024]).unwrap();
    let record = serde_json::json!({
        "ts": "2000-01-01T00:00:00Z",
        "tool_version": "0.0.0",
        "command": "trash purge",
        "action": "trash",
        "path": "/nonexistent/original/interrupted",
        "bytes_allocated": 1024,
        "inodes": 2,
        "trash_entry": claim.to_string_lossy(),
        "outcome": "ok",
    });
    std::fs::write(state.path().join("degu/ops.jsonl"), format!("{record}\n")).unwrap();
    claim
}

#[test]
fn xdg_state_parent_alias_does_not_block_direct_or_expiry_mutation() {
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

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", &request)
        .args(["clean", "--purge", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report["quota_observations"]["direct_purge"]["observation_state"],
        "resolved"
    );
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["observation_state"],
        "resolved"
    );
}

#[test]
fn clean_empty_entries_still_runs_observed_claim_housekeeping() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let marker = seed_aged_numeric_marker(&state);

    let out = run_clean(&home, &state, &["clean", "--yes", "--json"]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["expiry"]["planned"].as_array().unwrap().is_empty());
    assert_eq!(report["expiry"]["attempted"], true);
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["observation_state"],
        "resolved"
    );
}

#[test]
fn clean_purges_expired_trash_entries_after_report() {
    assert_json_expiry_after_report();
    assert_human_expiry_after_report();
}

fn assert_json_expiry_after_report() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let expired = seed_expired_trash_entry(&state);
    let out = run_clean(&home, &state, &["clean", "--yes", "--json"]);
    assert!(out.status.success());
    assert!(!cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["outcome"], "ok");
    assert!(report["executed"][0]["trash_entry"].is_string());
    assert_eq!(report["expiry"]["attempted"], true);
    assert_eq!(report["expiry"]["planned"].as_array().unwrap().len(), 1);
    assert_eq!(report["expiry"]["purged"].as_array().unwrap().len(), 1);
    assert!(report["expiry"]["failed"].as_array().unwrap().is_empty());
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["kind"],
        "expiry_purge"
    );
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["quota_observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!expired.exists());
    assert_eq!(
        visible_trash_entries(&state.path().join("degu/trash")).len(),
        1
    );
}

fn assert_human_expiry_after_report() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let expired = seed_expired_trash_entry(&state);
    let out = run_clean(&home, &state, &["clean", "--yes"]);
    assert!(out.status.success());
    assert!(!cache.exists());
    assert!(!expired.exists());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let quota = stdout
        .find("Still counts against quota while staged")
        .unwrap();
    let preview = stdout.find("Expired trash: 1 entry").unwrap();
    let purged = stdout.find("Purged 1 expired trash entry").unwrap();
    assert!(preview < purged);
    assert!(purged > quota);
}

#[test]
fn clean_empty_plan_human_still_purges_expired_trash() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry(&state);
    let out = run_clean(&home, &state, &["clean", "--yes"]);
    assert!(out.status.success());
    assert!(!expired.exists());
    assert!(visible_trash_entries(&state.path().join("degu/trash")).is_empty());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let report = stdout
        .find("No locations are selected for this clean.")
        .unwrap();
    let purged = stdout.find("Purged 1 expired trash entry").unwrap();
    assert!(purged > report);
}

#[test]
fn clean_empty_plan_json_still_purges_expired_trash() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry(&state);
    let out = run_clean(&home, &state, &["clean", "--yes", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["expiry"]["attempted"], true);
    assert_eq!(report["expiry"]["planned"].as_array().unwrap().len(), 1);
    assert_eq!(report["expiry"]["purged"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["kind"],
        "expiry_purge"
    );
    assert!(!expired.exists());
    assert!(visible_trash_entries(&state.path().join("degu/trash")).is_empty());
}

#[test]
fn clean_never_auto_expires_an_interrupted_purge_claim() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let claim = seed_expired_interrupted_claim(&state);

    let out = run_clean(&home, &state, &["clean", "--yes", "--json"]);

    assert!(out.status.success());
    assert!(claim.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["expiry"]["planned"].as_array().unwrap().is_empty());
    assert!(report["expiry"]["purged"].as_array().unwrap().is_empty());
}

#[test]
fn clean_dry_run_previews_and_never_purges_expired_trash() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry(&state);
    let human = run_clean(&home, &state, &["clean", "--dry-run"]);
    assert!(human.status.success());
    assert!(expired.exists());
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(stdout.contains(
        "Expired trash: 1 entry will be considered (at least 7 days old); purge-supported entries would be permanently deleted, while sealed entries with unsupported purge topology are retained and remain undoable."
    ));
    assert!(stdout.contains(&expired.display().to_string()));
    assert_eq!(oplog_records(&state).len(), 1);

    let json = run_clean(&home, &state, &["clean", "--dry-run", "--json"]);
    assert!(json.status.success());
    assert!(expired.exists());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["expiry"]["attempted"], false);
    assert_eq!(report["expiry"]["planned"].as_array().unwrap().len(), 1);
    assert!(report["expiry"]["purged"].as_array().unwrap().is_empty());
    assert_eq!(
        report["quota_observations"]["direct_purge"]["observation_state"],
        "not_attempted"
    );
    assert_eq!(
        report["quota_observations"]["expiry_purge"]["observation_state"],
        "not_attempted"
    );
    assert_eq!(oplog_records(&state).len(), 1);
    assert_eq!(
        visible_trash_entries(&state.path().join("degu/trash")).len(),
        1
    );
}

#[test]
fn clean_expiry_preview_escapes_the_exact_planned_path() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry_named(&state, "0001-old-\u{1b}[31m");

    let output = run_clean(&home, &state, &["clean", "--dry-run"]);

    assert!(output.status.success());
    assert!(expired.exists());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains('\u{1b}'));
    assert!(stdout.contains("0001-old-\\u{1b}[31m"));
}

#[test]
fn clean_empty_plan_without_yes_cannot_purge_expired_trash_non_interactively() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry(&state);

    let out = run_clean(&home, &state, &["clean"]);

    assert!(!out.status.success());
    assert!(expired.exists());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("requires --yes or --dry-run")
    );
    assert_eq!(oplog_records(&state).len(), 1);
}

#[test]
fn clean_empty_plan_json_without_yes_cannot_purge_expired_trash() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let expired = seed_expired_trash_entry(&state);

    let out = run_clean(&home, &state, &["clean", "--json"]);

    assert!(!out.status.success());
    assert!(expired.exists());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("--json requires --yes or --dry-run")
    );
    assert_eq!(oplog_records(&state).len(), 1);
}
