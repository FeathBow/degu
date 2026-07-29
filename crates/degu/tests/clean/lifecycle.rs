use super::support::*;

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
    assert!(out.status.success());
    assert!(!fixture.cache.exists());
}

fn assert_trash_list(fixture: &Lifecycle) {
    let out = fixture.run(&["trash", "list", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["omitted"], 0);
    let rows = report["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["original"], fixture.cache_path);
}

fn assert_undo(fixture: &Lifecycle) {
    let out = fixture.run(&["undo", "--json"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!report["restored"].as_array().unwrap().is_empty());
    assert!(fixture.cache.exists());
}

fn assert_restage(fixture: &Lifecycle) -> String {
    let out = fixture.run(&["clean", "--yes", "--json"]);
    assert!(out.status.success());
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
    assert!(out.status.success());
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
