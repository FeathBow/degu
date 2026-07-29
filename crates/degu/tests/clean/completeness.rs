use super::support::*;

#[test]
fn path_clean_of_a_fully_measured_root_survives_an_incomplete_sibling_root() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);

    let registry_arg = registry.to_str().unwrap();
    let narrowed = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--only",
            "cargo",
            "--path",
            registry_arg,
        ],
    );
    let whole_plan = run_clean(&home, &state, &["clean", "--dry-run"]);
    set_mode(&git_db, 0o755);

    assert!(
        narrowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&narrowed.stderr)
    );
    let narrowed_stdout = String::from_utf8(narrowed.stdout).unwrap();
    assert!(
        narrowed_stdout.contains(".cargo/registry"),
        "stdout: {narrowed_stdout}"
    );
    let would_move = narrowed_stdout
        .lines()
        .find(|line| line.starts_with("Would move "))
        .unwrap_or_else(|| panic!("no Would move line in stdout: {narrowed_stdout}"));
    assert!(
        !would_move.contains(">="),
        "fully measured selection must not display a lower bound: {would_move}"
    );
    assert!(!whole_plan.status.success());
    assert!(
        String::from_utf8_lossy(&whole_plan.stderr)
            .contains("refusing to clean on incomplete results")
    );
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(unix)]
#[test]
fn wide_path_clean_refuses_an_unmeasured_region_inside_the_selection() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);
    let cargo = home.path().join(".cargo");

    let out = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--only",
            "cargo",
            "--path",
            cargo.to_str().unwrap(),
        ],
    );
    set_mode(&git_db, 0o755);

    assert!(
        !out.status.success(),
        "a wide selection covering an unmeasured region must refuse; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results") && stderr.contains(".cargo/git"),
        "stderr: {stderr}"
    );
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn clean_json_omits_a_native_path_and_keeps_representable_findings() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let registry = home.path().join(".cargo/registry/cache");
    std::fs::create_dir_all(&registry).unwrap();
    std::fs::write(registry.join("crate.crate"), [0_u8; 4096]).unwrap();
    let pip = home.path().join(OsString::from_vec(b"pip-\xff".to_vec()));
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), [0_u8; 2048]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", &pip)
        .args(["clean", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["omitted"].as_u64().unwrap() >= 1, "{report}");
    assert_eq!(report["completeness"], "incomplete", "{report}");
    assert!(
        !report["planned"].as_array().unwrap().is_empty(),
        "representable cargo cache must plan: {report}"
    );
    assert!(pip.exists());
    assert!(registry.join("crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// The whole-scope refusal (no `--path`) must name the recorded incomplete
/// region instead of pointing at scan warnings the clean never prints.
#[cfg(unix)]
#[test]
fn whole_scope_refusal_names_the_incomplete_region() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);

    let out = run_clean(&home, &state, &["clean", "--dry-run"]);
    set_mode(&git_db, 0o755);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(".cargo/git"),
        "refusal does not name the incomplete region; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("resolve the reported scan warnings"),
        "refusal still points at scan warnings the clean never prints; stderr: {stderr}"
    );
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// Selecting the incompletely measured root itself must keep failing closed,
/// and the refusal must name the region that caused it.
#[cfg(unix)]
#[test]
fn path_clean_pointing_at_an_incompletely_measured_root_is_refused() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);
    let git = home.path().join(".cargo/git");

    let out = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--only",
            "cargo",
            "--path",
            git.to_str().unwrap(),
        ],
    );
    set_mode(&git_db, 0o755);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("not fully measured") && stderr.contains(".cargo/git"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("resolve the reported scan warnings"),
        "refusal still points at scan warnings the clean never prints; stderr: {stderr}"
    );
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// An unreadable ancestor CACHEDIR.TAG leaves the cache
/// region incompletely classified while traversal keeps descending, so a
/// nested self-tagged target becomes an eligible, fully measured finding
/// that the complete world would have vetoed with a single report-only claim
/// at the region. Incompleteness changed eligibility, not measurement, so
/// the gate must refuse and name the ancestor region. The gate runs before
/// both dry-run and staging, so refusing the dry run proves staging is
/// unreachable too.
#[cfg(unix)]
#[test]
fn path_clean_under_an_unclassifiable_ancestor_cache_region_is_refused() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("cache");
    let target = cache.join("stuff/target");
    std::fs::create_dir_all(&target).unwrap();
    let ancestor_tag = cache.join("CACHEDIR.TAG");
    std::fs::write(&ancestor_tag, CACHEDIR_TAG_SIGNATURE).unwrap();
    std::fs::write(cache.join("stuff/Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(target.join("CACHEDIR.TAG"), CACHEDIR_TAG_SIGNATURE).unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("artifact.bin"), [0u8; 4096]).unwrap();
    set_mode(&ancestor_tag, 0o000);

    let out = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--path",
            target.to_str().unwrap(),
            root.path().to_str().unwrap(),
        ],
    );
    set_mode(&ancestor_tag, 0o644);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    let region = cache.canonicalize().unwrap();
    assert!(
        stderr.contains(&region.display().to_string()),
        "refusal does not name the ancestor region {}; stderr: {stderr}",
        region.display()
    );
    assert!(target.join("artifact.bin").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// An incomplete hit's measured bytes are a lower bound that undershoots
/// --min-size; post-path filters must not shrink what the gate sees.
#[cfg(unix)]
#[test]
fn min_size_cannot_hide_an_incomplete_path_hit_from_the_gate() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);
    let alias = home.path().join("cargo-alias");
    std::os::unix::fs::symlink(home.path().join(".cargo"), &alias).unwrap();

    let out = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--only",
            "cargo",
            "--path",
            alias.to_str().unwrap(),
            "--min-size",
            "2048",
        ],
    );
    set_mode(&git_db, 0o755);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("not fully measured") && stderr.contains(".cargo/git"),
        "stderr: {stderr}"
    );
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

#[cfg(unix)]
const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55\n";

#[cfg(unix)]
fn fake_cargo_home_with_unreadable_git(
    home: &tempfile::TempDir,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let registry = home.path().join(".cargo/registry");
    std::fs::create_dir_all(registry.join("cache")).unwrap();
    std::fs::write(registry.join("cache/crate.crate"), [0u8; 4096]).unwrap();
    let git_db = home.path().join(".cargo/git/db");
    std::fs::create_dir_all(&git_db).unwrap();
    set_mode(&git_db, 0o000);
    (registry, git_db)
}
