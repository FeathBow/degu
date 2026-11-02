use super::support::*;

const DEGU_FAILURE_EXIT_CODE: i32 = 1;

#[test]
fn clean_rejects_a_truncated_scan_before_preview_or_mutation() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");

    for args in [
        &["clean", "--budget", "0s", "--dry-run"][..],
        &["clean", "--budget", "0s", "--yes", "--json"][..],
    ] {
        let out = run_clean(&home, &state, args);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("refusing to clean on partial results")
        );
        assert!(cache.join("wheel.whl").exists());
        assert!(!state.path().join("degu/trash").exists());
        assert!(!state.path().join("degu/ops.jsonl").exists());
    }
}

/// Same source, two roots: incompleteness gates per root, so it must not
/// poison a --path clean of the fully measured sibling root.
#[cfg(unix)]
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
    // The whole plan reaches the same answer: the sibling is proven clear of it.
    assert!(
        whole_plan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&whole_plan.stderr)
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
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

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
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    // Spelled apart from the plan, but it resolves to a planned location, so nothing
    // proves the plan clear of what the scan could not inspect.
    let alias = home.path().join("uv-cache-link");
    std::os::unix::fs::symlink(&cache, &alias).unwrap();

    let out = run_gap_clean(&home, &state, &alias, &["clean", "--dry-run"]);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("uv-cache-link"),
        "refusal does not name the incomplete region; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("resolve the reported scan warnings"),
        "refusal still points at scan warnings the clean never prints; stderr: {stderr}"
    );
    assert!(cache.join("wheel.whl").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

fn run_gap_clean(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    uv_cache: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let mut command = degu();
    crate::common::with_mutation_anchor(&mut command, state.path());
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("UV_CACHE_DIR", uv_cache)
        .args(args)
        .output()
        .unwrap()
}

/// The positive half: a region beside the plan leaves the plan alone, and the
/// output names what stayed out of it.
#[cfg(unix)]
#[test]
fn whole_scope_names_left_out() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);

    let out = run_clean(&home, &state, &["clean", "--dry-run"]);
    set_mode(&git_db, 0o755);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let unwrapped: String = stdout.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        unwrapped.contains("Couldnotbeinspected,soleftoutofthisplan:"),
        "stdout: {stdout}"
    );
    assert!(unwrapped.contains(".cargo/git"), "stdout: {stdout}");
    assert!(stdout.contains("Would move "), "stdout: {stdout}");
    assert!(stdout.contains(".cargo/registry"), "stdout: {stdout}");
    assert!(registry.join("cache/crate.crate").exists());
    assert!(!state.path().join("degu/trash").exists());
}

/// All the way through: the plan moves, the unreadable sibling stays where it is,
/// and undo brings the plan back.
#[cfg(unix)]
#[test]
fn whole_clean_stages_beside_gap() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let (registry, git_db) = fake_cargo_home_with_unreadable_git(&home);

    let cleaned = run_clean(&home, &state, &["clean", "--yes"]);
    let moved = !registry.exists();
    set_mode(&git_db, 0o755);

    assert!(
        cleaned.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&cleaned.stderr)
    );
    assert!(moved, "the planned location must have moved");
    assert!(git_db.exists(), "the unmeasured region must stay in place");

    let undone = run_clean(&home, &state, &["undo"]);
    assert!(
        undone.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&undone.stderr)
    );
    assert!(registry.join("cache/crate.crate").exists());
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
    crate::common::make_tree_non_shared_writable(root.path()).unwrap();
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
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    set_mode(&git_db, 0o000);
    (registry, git_db)
}

#[cfg(unix)]
#[test]
fn interactive_clean_rejects_an_incomplete_nonempty_plan_before_confirmation() {
    use crate::pty::{PtyRun, run as run_pty};

    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let alias = home.path().join("uv-cache-link");
    std::os::unix::fs::symlink(&cache, &alias).unwrap();
    let body = r#"
spawn -noecho $env(DEGU_BIN) clean
expect {
    -exact {refusing to clean on incomplete results} {}
    -exact {Proceed? [y/N] } {
        send "n\r"
        puts stderr "unexpected confirmation prompt"
    }
}
"#;
    let extra_env = [("UV_CACHE_DIR", alias.as_os_str())];
    let out = run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &extra_env,
    });

    assert_eq!(out.status.code(), Some(DEGU_FAILURE_EXIT_CODE));
    let transcript = String::from_utf8_lossy(&out.stdout);
    assert!(
        transcript.contains("refusing to clean on incomplete results"),
        "transcript: {transcript}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("unexpected confirmation prompt"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cache.join("wheel.whl").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// A plan clear of the gaps still reaches the prompt, and the reader sees what it
/// leaves out before answering.
#[cfg(unix)]
#[test]
fn interactive_clean_discloses_gap() {
    use crate::pty::{PtyRun, run as run_pty};

    let home = tempfile::tempdir().unwrap();
    let unresolved = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home, ".cache/pip");
    let alias = home.path().join("uv-cache-link");
    std::os::unix::fs::symlink(unresolved.path(), &alias).unwrap();
    let body = r#"
spawn -noecho $env(DEGU_BIN) --color never clean
expect -exact {Proceed? [y/N] }
send "n\r"
expect eof
"#;
    let extra_env = [("UV_CACHE_DIR", alias.as_os_str())];
    let out = run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &extra_env,
    });

    let transcript = String::from_utf8_lossy(&out.stdout);
    let unwrapped: String = transcript.chars().filter(|c| !c.is_whitespace()).collect();
    let disclosed = unwrapped
        .find("Couldnotbeinspected,soleftoutofthisplan:")
        .unwrap_or_else(|| panic!("transcript: {transcript}"));
    let prompt = unwrapped.find("Proceed?[y/N]").unwrap();
    assert!(disclosed < prompt, "transcript: {transcript}");
    assert!(
        unwrapped.contains("uv-cache-link"),
        "transcript: {transcript}"
    );
    assert!(cache.join("wheel.whl").exists());
    assert!(!state.path().join("degu/trash").exists());
}

/// Lays out a directory `PIP_CACHE_DIR` will name: pip's shape, no tag.
fn redirected_pip_layout(home: &tempfile::TempDir) -> std::path::PathBuf {
    let cache = home.path().join("scratch/cache/pip");
    std::fs::create_dir_all(cache.join("wheels/ab")).unwrap();
    std::fs::write(cache.join("wheels/ab/results.csv"), [0_u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();
    cache
}

fn run_with_pip_dir(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    cache: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let mut command = degu();
    crate::common::with_mutation_anchor(&mut command, state.path());
    command
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", cache)
        .args(args)
        .output()
        .unwrap()
}

/// Data a shallow layout check cannot see stays where it is unless someone asks for
/// that exact location: a default clean never takes it.
#[test]
fn default_clean_spares_layout_match() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = redirected_pip_layout(&home);

    let out = run_with_pip_dir(&home, &state, &cache, &["clean", "--yes"]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cache.join("wheels/ab/results.csv").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// The other half: a location offered for review moves when asked for, and comes back.
#[test]
fn review_moves_layout_match() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = redirected_pip_layout(&home);
    let path = cache.to_str().unwrap();

    let moved = run_with_pip_dir(&home, &state, &cache, &["clean", "--yes", "--review", path]);

    assert!(
        moved.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&moved.stderr)
    );
    assert!(!cache.exists(), "the reviewed location must have moved");

    let undone = run_with_pip_dir(&home, &state, &cache, &["undo"]);
    assert!(
        undone.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&undone.stderr)
    );
    assert!(cache.join("wheels/ab/results.csv").exists());
}

fn confirm_after_change(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    cache: &std::path::Path,
    late_dir: &std::path::Path,
) -> std::process::Output {
    use crate::pty::{PtyRun, run as run_pty};

    let body = r#"
spawn -noecho $env(DEGU_BIN) --color never clean --review $env(PIP_CACHE_DIR)
expect -exact {Proceed? [y/N] }
file mkdir $env(LATE_DIR)
send "y\r"
expect eof
"#;
    let extra_env = [
        ("PIP_CACHE_DIR", cache.as_os_str()),
        ("LATE_DIR", late_dir.as_os_str()),
    ];
    run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: test_config_home(),
        state_home: state.path(),
        extra_env: &extra_env,
    })
}

/// A write below the root leaves the root's identity alone, so only asking the layout
/// again can notice it. Here a build drops a release directory into `wheels` while the
/// plan waits for its answer.
#[cfg(unix)]
#[test]
fn layout_change_during_prompt_refuses() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = redirected_pip_layout(&home);
    let late = cache.join("wheels/release");

    let out = confirm_after_change(&home, &state, &cache, &late);

    let transcript: String = String::from_utf8_lossy(&out.stdout)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(
        transcript.contains("nolongerhasthelayout"),
        "transcript: {transcript}"
    );
    assert!(cache.join("wheels/ab/results.csv").exists());
    assert!(late.exists());
}

/// The positive half: the same prompt with a change the layout allows goes through.
#[cfg(unix)]
#[test]
fn layout_kept_during_prompt_moves() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = redirected_pip_layout(&home);

    let out = confirm_after_change(&home, &state, &cache, &cache.join("wheels/cd"));

    assert!(
        out.status.success(),
        "transcript: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!cache.exists(), "the reviewed location must have moved");
}
