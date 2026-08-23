use super::support::*;
use assert_cmd::Command;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

struct Lifecycle {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    cache: std::path::PathBuf,
    cache_path: String,
}

impl Lifecycle {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let (cache, state) = fake_pip_cache(&home, ".cache/pip");
        let cache_path = canonical_path_string(&cache);
        Self {
            home,
            state,
            cache,
            cache_path,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        run_clean(&self.home, &self.state, args)
    }
}

#[test]
fn clean_lifecycle_stages_restores_and_releases_only_on_purge() {
    let fixture = Lifecycle::new();
    assert_stage(&fixture);
    assert_trash_list(&fixture);
    assert_undo(&fixture);
    let trash_entry = assert_restage(&fixture);
    assert_purge(&fixture, &trash_entry);
}

fn assert_stage(fixture: &Lifecycle) {
    let out = fixture.run(&["clean", "--yes"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!fixture.cache.exists());
}

fn assert_trash_list(fixture: &Lifecycle) {
    let out = fixture.run(&["trash", "list", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["omitted"], 0);
    let rows = report["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["original"], fixture.cache_path);
}

fn assert_undo(fixture: &Lifecycle) {
    let out = fixture.run(&["undo", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!report["restored"].as_array().unwrap().is_empty());
    assert!(fixture.cache.exists());
}

fn assert_restage(fixture: &Lifecycle) -> String {
    let out = fixture.run(&["clean", "--yes", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!fixture.cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    report["executed"][0]["trash_entry"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn assert_purge(fixture: &Lifecycle, trash_entry: &str) {
    let out = fixture.run(&["trash", "purge", "--yes", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["purged"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some(trash_entry))
    );
    assert!(visible_trash_entries(&fixture.state.path().join("degu/trash")).is_empty());
}

/// This is deliberately a debug integration test: the test-built CLI alone
/// recognizes the temporary activation anchor. Release builds reject that
/// feature at compile time, so production binaries cannot acquire authority
/// from an ambient test variable.
#[test]
fn production_sealed_staging_cli_clean_undo_and_direct_purge() {
    let home = tempfile::tempdir().unwrap();
    let Some(backend) = require_sealed_fixture_backend(home.path()) else {
        return;
    };

    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let source_backend = certify_backend(&cache).unwrap();
    let state_backend = certify_backend(state.path()).unwrap();
    assert_eq!(
        source_backend, backend,
        "source backend changed within fixture"
    );
    assert_eq!(
        state_backend, backend,
        "state backend changed within fixture"
    );
    assert_eq!(
        std::fs::metadata(&cache).unwrap().dev(),
        std::fs::metadata(state.path()).unwrap().dev(),
        "source and sealed state must have the same device identity; production admission separately proves the mount binding"
    );
    let source_path = std::fs::canonicalize(&cache).unwrap();
    let anchor = state.path().join("degu-integration-activation-anchor");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
    let anchor = std::fs::canonicalize(anchor).unwrap();

    let run = |args: &[&str]| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin("degu"));
        command
            .env_clear()
            .env("HOME", home.path())
            .env("LOGNAME", test_config_home())
            .env("XDG_CONFIG_HOME", test_config_home())
            .env("XDG_STATE_HOME", state.path())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &anchor)
            // Intentionally do not set DEGU_INTEGRATION_TEST_LEGACY_CLEAN.
            .args(args);
        command.output().unwrap()
    };

    let clean = run(&["clean", "--yes", "--json"]);
    assert_output_success(&clean);
    let clean_report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(clean_report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(clean_report["executed"][0]["state"], "staged");
    assert_eq!(clean_report["executed"][0]["purged"], false);
    assert!(clean_report["executed"][0]["trash_entry"].is_string());
    assert!(!cache.exists());
    assert_activation_and_wal(&anchor, state.path());
    let activation = activation_snapshot(&anchor, state.path());
    let wal = state.path().join("degu/sealed-staging/seal.wal");
    let staged_wal_len = std::fs::metadata(&wal).unwrap().len();
    assert!(
        staged_wal_len > 0,
        "sealed clean did not append WAL evidence"
    );
    let first_records = oplog_records(&state);
    assert_trash_projection(&first_records, 0, &source_path);
    let first_reclamation = first_records[0]["reclamation_id"].clone();
    let first_trash = first_records[0]["trash_entry"].clone();

    let undo = run(&["undo", "--json"]);
    assert_output_success(&undo);
    let undo_report: serde_json::Value = serde_json::from_slice(&undo.stdout).unwrap();
    assert_eq!(undo_report["restored"].as_array().unwrap().len(), 1);
    assert_eq!(
        undo_report["restored"][0]["path"],
        source_path.to_string_lossy().as_ref()
    );
    for section in ["failed", "gone", "log_failures", "ambiguous"] {
        assert!(undo_report[section].as_array().unwrap().is_empty());
    }
    assert!(cache.join("wheel.whl").is_file());
    assert!(visible_trash_entries(&state.path().join("degu/trash")).is_empty());
    assert_eq!(activation_snapshot(&anchor, state.path()), activation);
    let restored_wal_len = std::fs::metadata(&wal).unwrap().len();
    assert!(
        restored_wal_len > staged_wal_len,
        "sealed undo did not append WAL evidence"
    );
    let restored_records = oplog_records(&state);
    assert_eq!(restored_records.len(), 2);
    let restore_record = &restored_records[1];
    assert_eq!(restore_record["action"], "restore");
    assert_eq!(restore_record["outcome"], "ok");
    assert_eq!(
        restore_record["path"],
        source_path.to_string_lossy().as_ref()
    );
    assert_eq!(restore_record["trash_entry"], first_trash);
    assert_eq!(restore_record["reclamation_id"], first_reclamation);

    let purge = run(&["clean", "--purge", "--yes", "--json"]);
    assert_output_success(&purge);
    assert!(!cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&purge.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["purged"], true);
    assert_eq!(report["executed"][0]["state"], "purged");
    assert!(visible_trash_entries(&state.path().join("degu/trash")).is_empty());
    assert_activation_and_wal(&anchor, state.path());
    assert_eq!(activation_snapshot(&anchor, state.path()), activation);
    assert!(
        std::fs::metadata(&wal).unwrap().len() > restored_wal_len,
        "sealed direct purge did not append WAL evidence"
    );
    let purged_records = oplog_records(&state);
    assert_eq!(purged_records.len(), 3);
    assert_trash_projection(&purged_records, 2, &source_path);
    let second_reclamation = purged_records[2]["reclamation_id"].clone();
    assert_ne!(second_reclamation, first_reclamation);
    // Direct sealed purge projects the completed trash association; its purge
    // authority and terminal result remain in the durable seal WAL.
    assert_eq!(purged_records[2]["trash_entry"], first_trash);
}

fn activation_snapshot(anchor: &Path, state: &Path) -> Vec<Vec<u8>> {
    [
        anchor.join("sealed-staging.authority"),
        anchor.join("sealed-staging.prepare"),
        anchor.join("sealed-staging.active"),
        state.join("degu/sealed-staging/store.activation"),
    ]
    .map(|path| std::fs::read(path).unwrap())
    .into()
}

fn assert_trash_projection(records: &[serde_json::Value], offset: usize, source: &Path) {
    let record = &records[offset];
    assert_eq!(record["action"], "trash");
    assert_eq!(record["outcome"], "ok");
    assert_eq!(record["path"], source.to_string_lossy().as_ref());
    assert!(record["trash_entry"].is_string());
    assert!(record["reclamation_id"].is_string());
    assert!(record["expected_identity"].is_object());
    assert!(record["destination_parent"].is_object());
}
