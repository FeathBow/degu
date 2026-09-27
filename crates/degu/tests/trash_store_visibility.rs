//! What a trash listing and purge plan may claim about an account they cannot see.
//!
//! `trash_roots` enumerates the current state directory and its registry, while an
//! activated store is recorded against an anchor the account database names. Point
//! the state directory elsewhere and the listing is complete for what it walked and
//! empty for what the account staged, so it has to say which it is.

#[path = "support/mod.rs"]
mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn run(home: &Path, state: &Path, anchor: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .env("XDG_CONFIG_HOME", common::isolated_config_home())
        .env("LOGNAME", common::isolated_config_home())
        .env("DEGU_INTEGRATION_TEST_ANCHOR", anchor)
        // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN: only a sealed
        // clean activates the store this test is about.
        .args(args)
        .output()
        .unwrap()
}

fn listing(home: &Path, state: &Path, anchor: &Path) -> serde_json::Value {
    let out = run(home, state, anchor, &["trash", "list", "--json"]);
    assert!(
        out.status.success(),
        "listing needs no authority: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("a trash listing is JSON")
}

fn warned(out: &std::process::Output) -> bool {
    String::from_utf8_lossy(&out.stderr).contains("activated sealed-staging store")
}

#[test]
fn a_listing_says_when_the_activated_store_is_not_the_one_it_walked() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let Some(_backend) = common::require_sealed_fixture_backend(home.path()) else {
        return;
    };

    let cache = common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("blob.bin"), vec![7u8; 64 * 1024]).unwrap();
    common::make_tree_non_shared_writable(home.path()).unwrap();
    let anchor = state.path().join("degu-integration-activation-anchor");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
    let anchor = std::fs::canonicalize(&anchor).unwrap();

    let cleaned = run(home.path(), state.path(), &anchor, &["clean", "--yes"]);
    assert!(
        cleaned.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&cleaned.stderr)
    );
    assert!(
        !cache.exists(),
        "the clean should have staged the cache away"
    );
    let binding = state.path().join("degu/sealed-staging/store.activation");
    assert!(binding.exists(), "the clean should have activated a store");

    let here = listing(home.path(), state.path(), &anchor);
    assert_eq!(here["entries"].as_array().unwrap().len(), 1);
    assert_eq!(here["activated_store_reachable"], serde_json::json!(true));

    // The only change is where the state directory points.
    let away = listing(home.path(), elsewhere.path(), &anchor);
    assert!(
        away["entries"].as_array().unwrap().is_empty(),
        "the other state directory enumerates no trash: {away}"
    );
    assert_eq!(
        away["activated_store_reachable"],
        serde_json::json!(false),
        "an empty listing may not claim to answer for the account: {away}"
    );
    assert!(warned(&run(
        home.path(),
        elsewhere.path(),
        &anchor,
        &["trash", "list"]
    )));

    let purged = run(
        home.path(),
        elsewhere.path(),
        &anchor,
        &["trash", "purge", "--yes"],
    );
    assert!(purged.status.success());
    assert!(
        warned(&purged),
        "a purge plan that reaches nothing may not read as an empty trash: {}",
        String::from_utf8_lossy(&purged.stderr)
    );
    let staged = std::fs::read_dir(state.path().join("degu/trash"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != ".claims")
        .count();
    assert_eq!(staged, 1, "the staged entry must survive that purge");
}
