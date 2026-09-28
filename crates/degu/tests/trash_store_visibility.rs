//! What a trash listing and purge plan may claim about an account they cannot see.
//!
//! `trash_roots` enumerates the current state directory and its registry, while an
//! activated store is recorded against an anchor the account database names. Point
//! the state directory elsewhere and the listing is complete for what it walked and
//! empty for what the account staged, so it has to say which it is.

#[path = "support/mod.rs"]
mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// One account with two state directories: the one its store was activated
/// against, and another this environment could be pointed at instead.
struct Sealed {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    elsewhere: tempfile::TempDir,
    cache: PathBuf,
    anchor: PathBuf,
}

impl Sealed {
    /// `None` when the fixture filesystem is not a certified backend, which is the
    /// same skip the other sealed fixtures take.
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().unwrap();
        common::require_sealed_fixture_backend(home.path())?;
        // Both state directories live inside the fixture home: a sealed store
        // refuses an ancestor that grants foreign rename authority, and a
        // top-level temporary directory has one.
        let state = tempfile::tempdir_in(home.path()).unwrap();
        let elsewhere = tempfile::tempdir_in(home.path()).unwrap();
        let cache = common::platform_cache_dir(home.path(), "pip");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("blob.bin"), vec![7u8; 64 * 1024]).unwrap();
        common::make_tree_non_shared_writable(home.path()).unwrap();
        let anchor = state.path().join("degu-integration-activation-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = std::fs::canonicalize(&anchor).unwrap();
        Some(Self {
            home,
            state,
            elsewhere,
            cache,
            anchor,
        })
    }

    fn run(&self, state: &Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", state)
            .env("XDG_CONFIG_HOME", common::isolated_config_home())
            .env("LOGNAME", common::isolated_config_home())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN: only a sealed
            // clean activates the store this file is about.
            .args(args)
            .output()
            .unwrap()
    }

    /// Stage the cache and confirm the store really was activated, so a later
    /// assertion about coverage is about coverage.
    fn stage(&self) {
        let out = self.run(self.state.path(), &["clean", "--yes"]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!self.cache.exists(), "the clean should have staged it away");
        assert!(
            self.binding(self.state.path()).exists(),
            "the clean should have activated a store"
        );
    }

    fn binding(&self, state: &Path) -> PathBuf {
        state
            .join("degu/sealed-staging")
            .join(degu_core::activation::STORE_BINDING_NAME)
    }

    /// The listing's own account of itself: how many entries, and whether it claims
    /// to cover everything this account staged.
    fn listing(&self, state: &Path) -> (usize, bool) {
        let out = self.run(state, &["trash", "list", "--json"]);
        assert!(
            out.status.success(),
            "listing needs no authority: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("a trash listing is JSON");
        (
            json["entries"].as_array().expect("entries").len(),
            json["activated_store_reachable"]
                .as_bool()
                .expect("a coverage answer"),
        )
    }

    fn warns(&self, state: &Path, args: &[&str]) -> bool {
        let out = self.run(state, args);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).contains("sealed-staging store")
    }

    /// Re-harden the fixture after a test creates a directory in it. A host running
    /// with a permissive umask leaves a new directory group-writable, and degu
    /// refuses to purge through one, so the fixture cannot rely on creation mode.
    fn harden(&self) {
        common::make_tree_non_shared_writable(self.home.path()).unwrap();
    }

    /// The `degu` directory of one state directory, created and hardened.
    fn product_dir(&self, state: &Path) -> PathBuf {
        let dir = state.join("degu");
        std::fs::create_dir_all(&dir).unwrap();
        self.harden();
        dir
    }

    fn staged_entries(&self) -> usize {
        std::fs::read_dir(self.state.path().join("degu/trash"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != ".claims")
            .count()
    }
}

#[test]
fn a_listing_says_when_the_activated_store_is_elsewhere() {
    let Some(fixture) = Sealed::new() else { return };
    fixture.stage();

    assert_eq!(fixture.listing(fixture.state.path()), (1, true));
    // The only change is where the state directory points.
    assert_eq!(
        fixture.listing(fixture.elsewhere.path()),
        (0, false),
        "an empty listing may not claim to answer for the account"
    );
    assert!(fixture.warns(fixture.elsewhere.path(), &["trash", "list"]));
    assert!(
        fixture.warns(fixture.elsewhere.path(), &["trash", "purge", "--yes"]),
        "a purge plan that reaches nothing may not read as an empty trash"
    );
    assert_eq!(
        fixture.staged_entries(),
        1,
        "the staged entry must survive that purge"
    );
}

#[test]
fn a_copied_store_binding_does_not_make_a_listing_complete() {
    let Some(fixture) = Sealed::new() else { return };
    fixture.stage();

    // Presence of a binding file is not evidence that this environment holds the
    // store the authority records: the copy names a store that is not here.
    let store = fixture
        .product_dir(fixture.elsewhere.path())
        .join("sealed-staging");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::copy(
        fixture.binding(fixture.state.path()),
        store.join(degu_core::activation::STORE_BINDING_NAME),
    )
    .unwrap();
    fixture.harden();

    assert_eq!(
        fixture.listing(fixture.elsewhere.path()),
        (0, false),
        "a copied binding may not buy coverage"
    );
    assert!(fixture.warns(fixture.elsewhere.path(), &["trash", "purge", "--yes"]));
    assert_eq!(fixture.staged_entries(), 1);
}

#[test]
fn a_store_symlinked_to_the_recorded_one_does_not_make_a_listing_complete() {
    let Some(fixture) = Sealed::new() else { return };
    fixture.stage();

    // Pointing this state directory's store at the recorded one resolves to the
    // same file, but the trash it enumerates is still its own — and coverage is
    // about the trash.
    std::os::unix::fs::symlink(
        fixture.state.path().join("degu/sealed-staging"),
        fixture
            .product_dir(fixture.elsewhere.path())
            .join("sealed-staging"),
    )
    .unwrap();
    fixture.harden();

    assert_eq!(
        fixture.listing(fixture.elsewhere.path()),
        (0, false),
        "a store symlinked to the recorded one may not buy coverage"
    );
    assert!(fixture.warns(fixture.elsewhere.path(), &["trash", "list"]));
    assert_eq!(
        fixture.staged_entries(),
        1,
        "the listing reached nothing, so nothing may have moved"
    );
}
