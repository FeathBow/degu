use super::support::*;

#[test]
fn clean_only_pip_does_not_collect_uv() {
    let home = tempfile::tempdir().unwrap();
    let (pip_cache, state) = fake_pip_cache(&home, ".cache/pip");
    let uv_cache = home.path().join(".cache/uv");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive"), [0u8; 2048]).unwrap();
    let pip_path = canonical_path_string(&pip_cache);
    let out = run_clean(
        &home,
        &state,
        &["clean", "--only", "pip", "--yes", "--json"],
    );

    assert!(out.status.success());
    assert!(!pip_cache.exists());
    assert!(uv_cache.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["path"], pip_path);
    assert!(report["excluded"].as_array().unwrap().is_empty());
}

#[test]
fn clean_older_than_executes_stale_cache_and_excludes_fresh_cache() {
    let fixture = AgeFixture::new();
    let out = run_clean(
        &fixture.home,
        &fixture.state,
        &["clean", "--older-than", "7", "--yes", "--json"],
    );
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["executed"].as_array().unwrap().len(), 1);
    assert_eq!(report["executed"][0]["path"], fixture.pip_path);
    let excluded = report["excluded"].as_array().unwrap();
    assert!(
        excluded
            .iter()
            .any(|finding| { finding["ecosystem"] == "uv" && finding["path"] == fixture.uv_path })
    );
    assert!(
        !excluded.iter().any(|finding| {
            finding["ecosystem"] == "pip" && finding["path"] == fixture.pip_path
        })
    );
}

struct AgeFixture {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    pip_path: String,
    uv_path: String,
}

impl AgeFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let pip = crate::common::platform_cache_dir(home.path(), "pip");
        let uv = home.path().join(".cache/uv");
        std::fs::create_dir_all(&pip).unwrap();
        std::fs::create_dir_all(&uv).unwrap();
        let stale_file = pip.join("wheel.whl");
        std::fs::write(&stale_file, [0u8; 2048]).unwrap();
        std::fs::write(uv.join("archive"), [0u8; 2048]).unwrap();
        crate::common::make_tree_non_shared_writable(home.path()).unwrap();
        let age = std::time::Duration::from_secs(30 * 24 * 60 * 60);
        std::fs::File::open(&stale_file)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
        Self {
            pip_path: canonical_path_string(&pip),
            uv_path: canonical_path_string(&uv),
            home,
            state,
        }
    }
}

#[test]
fn clean_min_size_excludes_small_findings_and_totals_only_planned_items() {
    let fixture = SizeFixture::new();
    let json = run_clean(
        &fixture.home,
        &fixture.state,
        &["clean", "--dry-run", "--min-size", "64K", "--json"],
    );
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let planned_bytes = assert_size_report(&fixture, &report);

    let human = run_clean(
        &fixture.home,
        &fixture.state,
        &["clean", "--dry-run", "--min-size", "64K"],
    );
    assert!(human.status.success());
    assert_size_human_output(
        &String::from_utf8(human.stdout).unwrap(),
        planned_bytes,
        &fixture.small_path,
    );
}

struct SizeFixture {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    small_path: String,
    large_path: String,
}

impl SizeFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        // Single-location probing means one finding per adapter, so use two
        // adapters: a small go-build cache (dropped) and a large pip cache (kept).
        let small = crate::common::platform_cache_dir(home.path(), "go-build");
        let large = crate::common::platform_cache_dir(home.path(), "pip");
        std::fs::create_dir_all(&small).unwrap();
        std::fs::create_dir_all(&large).unwrap();
        std::fs::write(small.join("obj.a"), [0u8; 1024]).unwrap();
        std::fs::write(large.join("wheel.whl"), vec![0u8; 128 * 1024]).unwrap();
        std::fs::hard_link(large.join("wheel.whl"), large.join("wheel-link.whl")).unwrap();
        crate::common::make_tree_non_shared_writable(home.path()).unwrap();
        Self {
            small_path: canonical_path_string(&small),
            large_path: canonical_path_string(&large),
            home,
            state,
        }
    }
}

fn assert_size_report(fixture: &SizeFixture, report: &serde_json::Value) -> u64 {
    let planned = report["planned"].as_array().unwrap();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0]["ecosystem"], "pip");
    assert_eq!(planned[0]["path"], fixture.large_path);
    assert!(
        report["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["ecosystem"] == "go-build" && finding["path"] == fixture.small_path
            })
    );
    planned[0]["bytes_allocated"].as_u64().unwrap()
}

fn assert_size_human_output(stdout: &str, planned_bytes: u64, small_path: &str) {
    assert!(stdout.contains("Ready to clean - 1 location - "));
    assert!(stdout.contains("Hidden by filters: 1 location"));
    assert!(!stdout.contains(small_path));
    let line = stdout
        .lines()
        .find(|line| line.starts_with("Would move "))
        .unwrap();
    let displayed = line
        .strip_prefix("Would move ")
        .unwrap()
        .strip_suffix(" to Degu trash")
        .unwrap();
    assert_human_bytes(displayed, planned_bytes);
    assert!(stdout.contains("is hardlink-shared; reclaimed space may be lower."));
}

#[test]
fn clean_top_excludes_rows_beyond_largest_finding() {
    let fixture = SizeFixture::new();
    let out = run_clean(
        &fixture.home,
        &fixture.state,
        &["clean", "--dry-run", "--top", "1", "--json"],
    );
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let planned = report["planned"].as_array().unwrap();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0]["ecosystem"], "pip");
    assert_eq!(planned[0]["path"], fixture.large_path);
    assert!(
        report["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["ecosystem"] == "go-build" && finding["path"] == fixture.small_path
            })
    );
}

#[test]
fn clean_path_scope_does_not_expand_unrelated_details() {
    let fixture = SizeFixture::new();
    let out = run_clean(
        &fixture.home,
        &fixture.state,
        &[
            "clean",
            "--dry-run",
            "--details",
            "--path",
            &fixture.large_path,
        ],
    );

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Outside this selection: 1 location"),
        "{stdout}"
    );
    assert!(!stdout.contains(&fixture.small_path), "{stdout}");
}

#[test]
fn clean_path_filter_matching_no_plan_item_fails_before_staging() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let unrelated = tempfile::tempdir().unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--json", "--path"])
        .arg(unrelated.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}
