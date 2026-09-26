//! The documented way out of an account whose recorded store is gone.
//!
//! `docs/safety.md` tells an operator to retire two activation records by hand,
//! because degu deliberately offers no command that could retire its own recovery
//! authority. A documented manual procedure that stopped working would leave the
//! account with nothing, so the steps are pinned here.

#[path = "support/mod.rs"]
mod common;

use assert_cmd::Command;
use std::path::Path;

fn degu() -> Command {
    common::isolated_degu()
}

fn clean(home: &Path, state: &Path) -> std::process::Output {
    degu()
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .args(["clean", "--yes"])
        .output()
        .unwrap()
}

fn stage_a_cache(home: &Path, name: &str) {
    let dir = common::platform_cache_dir(home, name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("blob.bin"), vec![0u8; 64 * 1024]).unwrap();
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the documented procedure is what an operator does with their own shell, outside degu; a fixture that deleted through the verified engine would not be the procedure"
)]
fn retiring_the_activation_records_restores_an_account_whose_store_is_gone() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    stage_a_cache(home.path(), "pip");
    assert!(
        clean(home.path(), state.path()).status.success(),
        "the first clean should activate a store"
    );

    // What an environment change, a reimage, or a moved state directory does to
    // an account: the anchor still names a store that is no longer there.
    let store = state.path().join("degu/sealed-staging");
    assert!(store.is_dir(), "the clean should have activated {store:?}");
    std::fs::remove_dir_all(&store).unwrap();

    stage_a_cache(home.path(), "npm");
    let blocked = clean(home.path(), state.path());
    assert!(
        !blocked.status.success(),
        "a lost store must block mutation rather than build a substitute"
    );
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("not in a resumable"),
        "stderr: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );

    // The documented step. The durable authority claim stays; only the records
    // that name the vanished store go.
    let anchor = state.path().join("degu-integration-activation-anchor");
    for record in ["sealed-staging.active", "sealed-staging.prepare"] {
        let path = anchor.join(record);
        assert!(path.exists(), "{record} should be there to retire");
        std::fs::remove_file(&path).unwrap();
    }
    assert!(
        anchor.join("sealed-staging.authority").exists(),
        "the authority claim is kept, not retired"
    );

    let recovered = clean(home.path(), state.path());
    assert!(
        recovered.status.success(),
        "the account should mutate again: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
}
