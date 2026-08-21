use super::support::*;
use assert_cmd::Command;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_TREE_DIRECTORIES: usize = 1_023;

#[test]
fn clean_tree_preview_assessment_does_not_activate_or_create_lifecycle_state() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    fixture.assert_preview_assessed();
}

#[test]
fn preview_blocks_1024_tree_directories_before_any_production_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    // The inventory counts its root. Root + 1,023 children is 1,024 tree
    // directories and would require 1,025 active recovery permissions once the
    // source-parent seal is included. Reject it before any lifecycle mutation.
    for index in 0..MAX_TREE_DIRECTORIES {
        let dir = fixture.cache.join(format!("dir-{index:04}"));
        std::fs::create_dir(&dir).unwrap();
        // Group-writable trees are deliberately demoted by classification, so
        // pin the fixture mode instead of inheriting the ambient umask.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(count_directories(&fixture.cache), 1_024);
    fixture.assert_preview_blocked("directory_limit_exceeded", "directory limit exceeded");
    fixture.assert_production_rejects("directory limit exceeded");
    assert_eq!(count_directories(&fixture.cache), 1_024);
    assert!(fixture.cache.join("wheel.whl").is_file());
}

#[test]
fn preview_blocks_regular_file_hardlink_pair_and_production_rejects() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.cache.join("wheel.whl");
    std::fs::hard_link(&original, fixture.cache.join("wheel-alias.whl")).unwrap();
    assert_eq!(std::fs::metadata(&original).unwrap().nlink(), 2);
    fixture.assert_preview_blocked("external_hard_link", "external hard link encountered");
    fixture.assert_production_rejects("external hard link encountered at wheel");
    assert_eq!(std::fs::metadata(&original).unwrap().nlink(), 2);
    assert!(fixture.cache.join("wheel-alias.whl").is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn preview_json_preserves_non_utf8_blocked_descendant_bytes() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    assert!(
        fixture.cache.to_str().is_some(),
        "the selected root must remain JSON-representable"
    );
    let outside = fixture.home.path().join("outside-hardlink");
    std::fs::write(&outside, b"must not be read").unwrap();
    let non_utf8_name = OsString::from_vec(vec![0xff]);
    let descendant = fixture.cache.join(&non_utf8_name);
    std::fs::hard_link(&outside, &descendant).unwrap();

    let output = fixture.run(&["clean", "-n", "--json"]);
    assert_output_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON output: {error}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let preflight = &report["staging_preflight"][0];
    assert_eq!(preflight["status"], "blocked", "{report:#}");
    assert_eq!(preflight["kind"], "external_hard_link", "{report:#}");
    assert!(preflight["relative_path"].is_null(), "{report:#}");
    assert_eq!(preflight["relative_path_unix_bytes_hex"], "ff");

    let human = fixture.run(&["clean", "-n"]);
    assert_output_success(&human);
    let stdout = String::from_utf8(human.stdout).expect("human preview must be valid UTF-8");
    assert!(
        stdout.contains("external hard link encountered"),
        "{stdout}"
    );
    assert!(
        stdout
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\t')),
        "human preview contained a terminal control: {stdout:?}"
    );
    fixture.assert_no_activation_or_created_lifecycle_state();
    assert_eq!(std::fs::metadata(&descendant).unwrap().nlink(), 2);
}

#[test]
fn ordinary_full_scope_keeps_per_item_admission() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let rejected = fixture.home.path().join(".npm");
    std::fs::create_dir_all(&rejected).unwrap();
    let content = rejected.join("content");
    std::fs::write(&content, [0_u8; 4096]).unwrap();
    let external_peer = fixture.home.path().join(".npm-external-peer");
    std::fs::hard_link(&content, &external_peer).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();
    let eligible_path = std::fs::canonicalize(&fixture.cache).unwrap();
    let rejected_path = std::fs::canonicalize(&rejected).unwrap();

    let output = fixture.run(&["clean", "--yes", "--json"]);
    assert!(
        !output.status.success(),
        "mixed full-scope clean unexpectedly succeeded"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 2, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 2, "{report:#}");
    let staged = executed
        .iter()
        .find(|item| item["path"].as_str() == Some(eligible_path.to_string_lossy().as_ref()))
        .unwrap_or_else(|| panic!("missing staged pip result: {report:#}"));
    let failed = executed
        .iter()
        .find(|item| item["path"].as_str() == Some(rejected_path.to_string_lossy().as_ref()))
        .unwrap_or_else(|| panic!("missing rejected npm result: {report:#}"));
    assert_eq!(staged["state"], "staged", "{report:#}");
    assert_eq!(failed["state"], "stage_failed", "{report:#}");
    assert!(!fixture.cache.exists(), "admissible item was not staged");
    assert!(content.is_file(), "rejected item was mutated");
    assert!(external_peer.is_file(), "external peer was mutated");
    assert_activation_and_wal(&fixture.anchor, fixture.state.path());
    assert_eq!(
        visible_trash_entries(&fixture.state.path().join("degu/trash")).len(),
        1,
        "rejected item created a trash entry"
    );
}

#[test]
fn explicit_review_reaches_sealed_preflight_before_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let review = fixture
        .home
        .path()
        .join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(review.join("snapshots/main")).unwrap();
    let model = review.join("snapshots/main/model.bin");
    std::fs::write(&model, [0_u8; 4096]).unwrap();
    std::fs::hard_link(&model, review.join("snapshots/main/model-alias.bin")).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();

    let output = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--review",
        review.to_str().unwrap(),
    ]);
    assert_rejected(&output, "external hard link encountered");
    assert!(model.is_file());
    assert!(review.join("snapshots/main/model-alias.bin").is_file());
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(
        !fixture
            .state
            .path()
            .join("degu/sealed-staging/.claims")
            .exists()
    );
}

#[test]
fn explicit_path_batch_rejects_before_any_item_mutates() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let rejected = fixture.home.path().join(".npm");
    std::fs::create_dir_all(&rejected).unwrap();
    let content = rejected.join("content");
    std::fs::write(&content, [0_u8; 4096]).unwrap();
    std::fs::hard_link(&content, rejected.join("content-alias")).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();

    let eligible_arg = fixture.cache.to_str().unwrap();
    let rejected_arg = rejected.to_str().unwrap();
    let run = || {
        fixture.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            eligible_arg,
            "--path",
            rejected_arg,
        ])
    };

    let first = run();
    assert_atomic_batch_rejected_without_source_mutation(&first, &fixture.cache, &rejected);
    assert_activation_and_wal(&fixture.anchor, fixture.state.path());
    let store = fixture.state.path().join("degu/sealed-staging");
    let wal = store.join("seal.wal");
    let wal_len_after_startup = std::fs::metadata(&wal).unwrap().len();
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!store.join(".claims").exists());

    let second = run();
    assert_atomic_batch_rejected_without_source_mutation(&second, &fixture.cache, &rejected);
    assert_eq!(
        std::fs::metadata(&wal).unwrap().len(),
        wal_len_after_startup,
        "rejected explicit batch appended a transaction frame"
    );
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!store.join(".claims").exists());
}

fn assert_atomic_batch_rejected_without_source_mutation(
    output: &std::process::Output,
    eligible: &Path,
    rejected: &Path,
) {
    assert!(
        !output.status.success(),
        "rejected batch unexpectedly succeeded"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON output: {error}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(report["planned"].as_array().unwrap().len(), 2, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 2, "{report:#}");
    let mut states = executed
        .iter()
        .map(|item| item["state"].as_str().unwrap())
        .collect::<Vec<_>>();
    states.sort_unstable();
    assert_eq!(states, ["not_attempted", "stage_failed"], "{report:#}");
    assert!(eligible.join("wheel.whl").is_file());
    assert!(rejected.join("content").is_file());
    assert!(rejected.join("content-alias").is_file());
}

struct Fixture {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    cache: PathBuf,
    anchor: PathBuf,
}

impl Fixture {
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().unwrap();
        let backend = match certify_backend(home.path()) {
            Ok(backend) => backend,
            #[cfg(target_os = "linux")]
            Err(degu_core::backend::CertificationError::UnsupportedFilesystem) => {
                eprintln!(
                    "skipping sealed-admission characterization: fixture filesystem is not certified native ext4/XFS"
                );
                return None;
            }
            Err(reason) => {
                #[cfg(target_os = "macos")]
                panic!("macOS integration fixtures are expected to be on APFS: {reason:?}");
                #[cfg(not(target_os = "macos"))]
                panic!("native fixture certification failed unexpectedly: {reason:?}");
            }
        };
        #[cfg(target_os = "macos")]
        assert_eq!(backend, degu_core::backend::CertifiedLocalBackend::Apfs);

        let (cache, state) = fake_pip_cache(&home, ".cache/pip");
        assert_eq!(certify_backend(&cache).unwrap(), backend);
        assert_eq!(certify_backend(state.path()).unwrap(), backend);
        assert_eq!(
            std::fs::metadata(&cache).unwrap().dev(),
            std::fs::metadata(state.path()).unwrap().dev(),
            "source and state must have the same device identity; sealed production admission proves the mount binding"
        );
        let anchor = state.path().join("degu-integration-activation-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = std::fs::canonicalize(anchor).unwrap();
        Some(Self {
            home,
            state,
            cache,
            anchor,
        })
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin("degu"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("LOGNAME", test_config_home())
            .env("XDG_CONFIG_HOME", test_config_home())
            .env("XDG_STATE_HOME", self.state.path())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN.
            .args(args);
        command.output().unwrap()
    }

    fn assert_preview_assessed(&self) {
        let parent = self.cache.parent().unwrap();
        let parent_mode = std::fs::metadata(parent).unwrap().mode();
        self.assert_no_activation_or_created_lifecycle_state();
        let output = self.run(&["clean", "-n", "--json"]);
        assert_output_success(&output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["planned"].as_array().unwrap().len(), 1, "{report:#}");
        let preflight = report["staging_preflight"].as_array().unwrap();
        assert_eq!(preflight.len(), 1, "{report:#}");
        assert_eq!(preflight[0]["status"], "tree_policy_assessed");
        assert_eq!(
            preflight[0]["pending_validation"],
            serde_json::json!({
                "source_parent_seal": "requires_execution",
                "regular_file_content_read_and_proof": "requires_execution",
                "runtime_revalidation": "requires_execution",
            })
        );
        assert!(preflight[0].get("kind").is_none());
        assert_eq!(std::fs::metadata(parent).unwrap().mode(), parent_mode);
        self.assert_no_activation_or_created_lifecycle_state();
    }

    fn assert_preview_blocked(&self, kind: &str, reason: &str) {
        let parent = self.cache.parent().unwrap();
        let parent_mode = std::fs::metadata(parent).unwrap().mode();
        self.assert_no_activation_or_created_lifecycle_state();

        let output = self.run(&["clean", "-n", "--json"]);
        assert_output_success(&output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let planned = report["planned"].as_array().unwrap();
        assert_eq!(
            planned.len(),
            1,
            "preview did not retain fixture: {report:#}"
        );
        assert_eq!(
            planned[0]["path"],
            std::fs::canonicalize(&self.cache)
                .unwrap()
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(planned[0]["disposition"]["mode"], "eligible");
        let preflight = report["staging_preflight"].as_array().unwrap();
        assert_eq!(preflight.len(), 1, "{report:#}");
        assert_eq!(preflight[0]["path"], planned[0]["path"]);
        assert_eq!(preflight[0]["status"], "blocked");
        assert_eq!(preflight[0]["kind"], kind);
        assert!(preflight[0]["category"].is_string());
        assert!(
            preflight[0]["reason"].as_str().unwrap().contains(reason),
            "{report:#}"
        );

        let human = self.run(&["clean", "-n"]);
        assert_output_success(&human);
        let stdout = String::from_utf8(human.stdout).unwrap();
        assert!(
            stdout.contains("Blocked by sealed staging preflight"),
            "{stdout}"
        );
        assert!(stdout.contains(reason), "{stdout}");
        assert!(!stdout.contains("Ready to clean"), "{stdout}");
        assert!(!stdout.contains("Would move"), "{stdout}");
        assert!(stdout.contains("pip"), "{stdout}");

        assert_eq!(std::fs::metadata(parent).unwrap().mode(), parent_mode);
        self.assert_no_activation_or_created_lifecycle_state();
        assert!(self.cache.is_dir());
    }

    // This is intentionally a mutation/activation assertion, not a claim that
    // the whole dry-run avoids lifecycle reads: expiry preview may inspect
    // existing operation and trash state.
    fn assert_no_activation_or_created_lifecycle_state(&self) {
        let degu_state = self.state.path().join("degu");
        assert!(!degu_state.exists(), "dry-run created XDG state");
        assert!(
            !degu_state.join("trash").exists(),
            "dry-run created trash state"
        );
        assert!(
            !degu_state.join("sealed-staging/seal.wal").exists(),
            "dry-run created or activated the sealed WAL"
        );
        for name in [
            "sealed-staging.authority",
            "sealed-staging.prepare",
            "sealed-staging.active",
        ] {
            assert!(!self.anchor.join(name).exists(), "dry-run created {name}");
        }
    }

    fn assert_production_rejects(&self, expected: &str) {
        let first = self.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            self.cache.to_str().unwrap(),
        ]);
        assert_rejected(&first, expected);
        assert!(self.cache.is_dir(), "rejected source was moved or deleted");
        assert_activation_and_wal(&self.anchor, self.state.path());
        let store = self.state.path().join("degu/sealed-staging");
        let wal = store.join("seal.wal");
        // Activation and the first CLI session's recovery may initialize or
        // advance store bookkeeping. Establish the no-mutation baseline only
        // after that recovery boundary; the next atomic preflight must not
        // advance it.
        let wal_len_before = std::fs::metadata(&wal).unwrap().len();
        assert!(!self.state.path().join("degu/trash").exists());
        assert!(!store.join(".claims").exists());

        // A new CLI session must reach the same data-only admission decision
        // without adding a transaction frame or creating staging destinations.
        let second = self.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            self.cache.to_str().unwrap(),
        ]);
        assert_rejected(&second, expected);
        assert!(self.cache.is_dir());
        assert_eq!(std::fs::metadata(wal).unwrap().len(), wal_len_before);
        assert!(!self.state.path().join("degu/trash").exists());
    }
}

fn assert_rejected(output: &std::process::Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "rejected clean unexpectedly succeeded"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 1, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 1, "{report:#}");
    assert_eq!(executed[0]["state"], "stage_failed");
    assert_eq!(executed[0]["purged"], false);
    assert!(executed[0]["trash_entry"].is_null());
    let reason = executed[0]["outcome"]["failed"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("sealed batch preflight rejected"),
        "{reason}"
    );
    assert!(reason.contains(expected), "{reason}");
    assert!(
        stderr.contains("one or more clean locations failed"),
        "{stderr}"
    );
}

fn count_directories(root: &Path) -> usize {
    1 + std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .count()
}
