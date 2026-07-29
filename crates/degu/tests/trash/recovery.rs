use super::support::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

#[test]
fn interrupted_purge_claim_requires_a_new_explicit_confirmation() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let claim = seed_interrupted_purge_claim(&state);
    let cancelled = run_interactive_purge(home.path(), state.path(), "y");

    assert!(!cancelled.status.success());
    assert!(claim.exists());

    let completed = run(&home, &state, &["trash", "purge", "--yes", "--json"]);
    assert!(completed.status.success());
    assert!(!claim.exists());
    let report: serde_json::Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(
        report["purged"].as_array().unwrap(),
        &[serde_json::Value::String(
            claim.to_string_lossy().into_owned()
        )]
    );
}

#[test]
fn interrupted_symlink_claim_deletes_only_the_link() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let victim = external.path().join("must-survive");
    std::fs::write(&victim, "user data").unwrap();
    let claims = private_trash_root(&state).join(".claims");
    std::fs::create_dir_all(&claims).unwrap();
    std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
    let claim = claims.join("purge-symlink");
    symlink(&victim, &claim).unwrap();

    let output = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(output.status.success());
    assert!(std::fs::symlink_metadata(&claim).is_err());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "user data");
}

#[test]
fn interrupted_claim_replaced_after_confirmation_is_preserved() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let claim = seed_interrupted_purge_claim(&state);
    let out = run_purge_with_replaced_entry(home.path(), state.path(), &claim);

    assert!(!out.status.success());
    assert_eq!(
        std::fs::read(claim.join("replacement.txt")).unwrap(),
        b"replacement data"
    );
    let transcript = String::from_utf8(out.stdout).unwrap();
    assert!(transcript.contains("identity changed after confirmation"));
}

#[test]
fn interrupted_claims_are_executed_before_visible_trash_entries() {
    let (home, state, _) = fake_pip_cache();
    clean_pip_cache(&home, &state);
    let claim = seed_interrupted_purge_claim(&state);

    let output = run(&home, &state, &["trash", "purge", "--yes", "--json"]);

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let purged = report["purged"].as_array().unwrap();
    assert_eq!(purged.len(), 2);
    assert_eq!(purged[0], claim.to_string_lossy().as_ref());
}

#[test]
fn interrupted_claim_added_after_confirmation_is_not_deleted() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    seed_interrupted_purge_claim(&state);
    let late_claim = state
        .path()
        .join("degu/trash/.claims/purge-late-interruption");
    let output = run_purge_with_late_entry(home.path(), state.path(), &late_claim);

    assert!(output.status.success());
    assert!(late_claim.exists());
}
