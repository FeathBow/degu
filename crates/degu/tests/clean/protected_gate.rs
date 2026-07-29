//! The whole-plan completeness gate distinguishes measurement incompleteness
//! from deliberate protected prunes (AI-tool and credential directory names
//! at the walker boundary). A prune keeps the scan incomplete, keeps the
//! containing finding report-only, and keeps totals lower bounds, but it
//! never blocks cleaning unrelated locations. See issue #267.

use super::support::*;
use degu_core::safety::{MIXED_STATE_AI_TOOL_REASON, PROTECTED_CREDENTIAL_REASON};

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// A pip cache reached through PIP_CACHE_DIR, corroborated by CACHEDIR.TAG,
/// carrying a protected subdirectory named `name` deep inside.
fn seed_pruned_pip_cache(home: &std::path::Path, name: &str) -> std::path::PathBuf {
    let cache = home.join("cache/pip");
    let pruned = cache.join("nested").join(name);
    std::fs::create_dir_all(&pruned).unwrap();
    std::fs::write(
        cache.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(cache.join("payload.bin"), [0_u8; 2048]).unwrap();
    std::fs::write(pruned.join("secret"), [0_u8; 64]).unwrap();
    cache
}

/// The disjoint eligible finding: a well-known cargo registry cache.
fn seed_cargo_registry(home: &std::path::Path) -> std::path::PathBuf {
    let registry = home.join(".cargo/registry");
    std::fs::create_dir_all(registry.join("cache")).unwrap();
    std::fs::write(registry.join("cache/crate.crate"), [0_u8; 4096]).unwrap();
    registry
}

fn run_with_pip_cache(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
    cache: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .env("PIP_CACHE_DIR", cache)
        .args(args)
        .output()
        .unwrap()
}

fn pip_finding(report: &serde_json::Value) -> serde_json::Value {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap_or_else(|| panic!("missing pip finding in {report}"))
        .clone()
}

/// The prune keeps the scan-level completeness flag, the frozen JSON shape,
/// and the containing finding's report-only demotion exactly as today; only
/// the whole-plan gate stops treating it as blocking.
fn assert_prune_does_not_block_the_whole_plan(name: &str, reason: &str) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = seed_pruned_pip_cache(home.path(), name);
    seed_cargo_registry(home.path());

    let scan = run_with_pip_cache(&home, &state, &cache, &["scan", "--json"]);
    assert!(
        scan.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(report["completeness"]["findings"], "incomplete", "{name}");
    assert!(
        report.get("incomplete_regions").is_none(),
        "{name}: regions must never serialize; the JSON schema is frozen"
    );
    let finding = pip_finding(&report);
    assert_eq!(finding["disposition"]["mode"], "report_only", "{name}");
    assert_eq!(finding["disposition"]["reason"], reason, "{name}");
    assert!(
        finding["skipped"].as_u64().unwrap() > 0,
        "{name}: skipped must keep counting the protected boundary"
    );

    let clean = run_with_pip_cache(&home, &state, &cache, &["clean", "--dry-run", "--json"]);
    assert!(
        clean.status.success(),
        "{name}: whole-plan clean must not be blocked by a deliberate prune: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(report["completeness"], "incomplete", "{name}");
    let planned = report["planned"].as_array().unwrap();
    assert_eq!(
        planned.len(),
        1,
        "{name}: only the eligible item is planned: {report}"
    );
    assert_eq!(planned[0]["ecosystem"], "cargo", "{name}");
    assert!(
        !planned[0]["path"].as_str().unwrap().contains("cache/pip"),
        "{name}: the prune-containing finding must stay unplanned"
    );
    assert!(report["executed"].as_array().unwrap().is_empty(), "{name}");
    assert!(cache.join("payload.bin").exists(), "{name}");
    assert!(
        cache.join("nested").join(name).join("secret").exists(),
        "{name}"
    );
    assert!(!state.path().join("degu/trash").exists(), "{name}");
    assert!(!state.path().join("degu/ops.jsonl").exists(), "{name}");
}

#[test]
fn protected_ai_prune_does_not_block_the_whole_plan() {
    assert_prune_does_not_block_the_whole_plan(".claude", MIXED_STATE_AI_TOOL_REASON);
}

#[test]
fn protected_credential_prune_does_not_block_the_whole_plan() {
    assert_prune_does_not_block_the_whole_plan(".ssh", PROTECTED_CREDENTIAL_REASON);
}

/// Measurement wins: the same finding carries a deliberate prune and an
/// unreadable directory, so the region cause upgrades to measurement and
/// the whole plan keeps refusing.
#[cfg(unix)]
#[test]
fn mixed_protected_and_unreadable_prune_refuses_the_whole_plan() {
    if root_ignores_dir_modes() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = seed_pruned_pip_cache(home.path(), ".claude");
    seed_cargo_registry(home.path());
    let unreadable = cache.join("unreadable");
    std::fs::create_dir_all(&unreadable).unwrap();
    set_mode(&unreadable, 0o000);

    let out = run_with_pip_cache(&home, &state, &cache, &["clean", "--dry-run"]);
    set_mode(&unreadable, 0o755);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("cache/pip"),
        "refusal must name the incompletely measured region: {stderr}"
    );
    assert!(cache.join("payload.bin").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// The pruned region — a discarded artifact claim, so no finding survives it —
/// is never consulted for disjointness; the output discloses the exclusion.
#[test]
fn path_clean_covering_the_parent_of_a_protected_prune_proceeds() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let eligible_target = seed_cargo_target(root.path(), "proj-a");
    let pruned_target = seed_cargo_target(root.path(), "proj-b");
    let pruned = pruned_target.join(".claude");
    std::fs::create_dir_all(&pruned).unwrap();
    std::fs::write(pruned.join("settings.json"), "{}").unwrap();

    // The positional root authorizes artifact discovery; --path selects the
    // parent of the pruned region (the same directory).
    let root_arg = root.path().to_str().unwrap();
    let out = run_clean(
        &home,
        &state,
        &["clean", "--dry-run", "--path", root_arg, root_arg],
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("proj-a"), "stdout: {stdout}");
    assert!(
        stdout.contains("excluded from completeness gating"),
        "human output must disclose the protected-gate exclusion: {stdout}"
    );
    assert!(eligible_target.join("artifact.bin").exists());
    assert!(pruned_target.join("artifact.bin").exists());
    assert!(pruned.join("settings.json").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// The finding is not fully measured, and a deliberate prune never earns it
/// back into a plan.
#[test]
fn path_clean_selecting_the_prune_containing_finding_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let cache = seed_pruned_pip_cache(home.path(), ".claude");
    seed_cargo_registry(home.path());

    let out = run_with_pip_cache(
        &home,
        &state,
        &cache,
        &["clean", "--dry-run", "--path", cache.to_str().unwrap()],
    );

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("not fully measured") && stderr.contains("cache/pip"),
        "stderr: {stderr}"
    );
    assert!(cache.join("payload.bin").exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

/// One project-shaped directory with an eligible-looking cargo target.
fn seed_cargo_target(root: &std::path::Path, project: &str) -> std::path::PathBuf {
    let target = root.join(project).join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(root.join(project).join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("artifact.bin"), [0_u8; 4096]).unwrap();
    target
}
