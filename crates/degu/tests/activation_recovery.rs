//! The documented way out of an account whose recorded store is gone.
//!
//! `docs/safety.md` tells an operator to retire two activation records by hand,
//! and says that doing so is what makes the staged data reachable again rather
//! than a cleanup afterwards. Both halves are pinned here, because a documented
//! manual procedure that stopped working would leave the account with nothing,
//! and an earlier draft of that section had the premise backwards.

#[path = "support/mod.rs"]
mod common;

use assert_cmd::Command;
use std::path::Path;

fn degu() -> Command {
    common::isolated_degu()
}

fn run(home: &Path, state: &Path, args: &[&str]) -> std::process::Output {
    degu()
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .args(args)
        .output()
        .unwrap()
}

/// Run and require success, reporting what degu said when it refused. An assertion
/// that hides the reason turns one failure into no evidence.
fn expect_ok(home: &Path, state: &Path, args: &[&str], why: &str) -> std::process::Output {
    let out = run(home, state, args);
    assert!(
        out.status.success(),
        "{why}: {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Seed one cache where the scanner probes for it, then harden the tree, because
/// the umask a host runs with decides whether `create_dir_all` left a
/// group-writable ancestor and degu will not clean through one.
fn seed_cache(home: &Path, byte: u8) -> std::path::PathBuf {
    let cache = common::platform_cache_dir(home, "pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("blob.bin"), vec![byte; 64 * 1024]).unwrap();
    common::make_tree_non_shared_writable(home).unwrap();
    cache
}

/// Every byte staged right now, so "the staged copy is still there" is measured
/// rather than inferred from a directory existing.
///
/// The staged location comes from degu rather than from a path this test builds:
/// `$XDG_STATE_HOME/degu/trash` is the destination only while it sits inside the
/// same authenticated mount domain as the source, and otherwise staging goes to a
/// `.degu-trash` on the source mount. Asking `trash list` is also what the
/// documented procedure tells an operator to do.
fn staged_bytes(home: &Path, state: &Path) -> u64 {
    staged(home, state).1
}

/// The staged entries degu reports, and their total size. Returned together so a
/// failure names where it looked rather than only what it counted.
fn staged(home: &Path, state: &Path) -> (Vec<String>, u64) {
    let out = run(home, state, &["trash", "list", "--json"]);
    assert!(
        out.status.success(),
        "listing needs no authority: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let entries = json["entries"]
        .as_array()
        .expect("a trash listing has entries")
        .iter()
        .map(|row| row["entry"].as_str().expect("an entry path").to_owned())
        .collect::<Vec<_>>();
    let bytes = entries.iter().map(|e| bytes_under(Path::new(e))).sum();
    (entries, bytes)
}

fn bytes_under(root: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = entry.metadata().unwrap();
            total += if metadata.is_dir() {
                bytes_under(&path)
            } else {
                metadata.len()
            };
        }
    }
    total
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the documented procedure is what an operator does with their own shell, outside degu; a fixture that deleted through the verified engine would not be the procedure"
)]
fn retiring_the_activation_records_is_what_reaches_the_staged_data() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    let cache = seed_cache(home.path(), 7);
    expect_ok(
        home.path(),
        state.path(),
        &["clean", "--yes"],
        "the first clean should stage the cache and activate a store",
    );
    assert!(!cache.exists(), "the clean should have staged it away");
    let (entries, staged) = staged(home.path(), state.path());
    assert_eq!(
        staged,
        64 * 1024,
        "the staged copy should be where degu says it is; it listed {entries:?}"
    );

    // What an environment change, a reimage, or a swept scratch filesystem does:
    // the anchor still names a store that is no longer there.
    let store = state.path().join("degu/sealed-staging");
    assert!(store.is_dir(), "the clean should have activated {store:?}");
    std::fs::remove_dir_all(&store).unwrap();

    // The premise the documentation rests on: the store is not where staged data
    // lives, so losing it does not lose the copy.
    assert_eq!(
        staged_bytes(home.path(), state.path()),
        staged,
        "the staged copy should survive the store"
    );

    // Recovery is blocked while the records name the vanished store, which is why
    // the documented order retires them first.
    let blocked = run(home.path(), state.path(), &["undo"]);
    assert!(!blocked.status.success(), "undo should be refused");
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("not in a resumable"),
        "stderr: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(!cache.exists(), "the refused undo must restore nothing");

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

    // Retiring them is what reaches the data, not a cleanup after the fact.
    let recovered = run(home.path(), state.path(), &["undo"]);
    assert!(
        recovered.status.success(),
        "undo should work once the records are retired: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        std::fs::read(cache.join("blob.bin")).unwrap(),
        vec![7u8; 64 * 1024],
        "the restored copy should be the staged bytes"
    );

    // And the account mutates again.
    seed_cache(home.path(), 9);
    expect_ok(
        home.path(),
        state.path(),
        &["clean", "--yes"],
        "the account should stage again",
    );
}
