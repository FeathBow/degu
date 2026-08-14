//! Human findings tables fold a tier's tail past ten rows: the ten largest
//! rows stay, one dimmed line aggregates the rest, and --details / --json
//! keep the complete list.

use super::support::*;

const MIB: usize = 1024 * 1024;
const SMALL_PAYLOAD: usize = 4096;
const FOLDED_HINT: &str = "Rerun with --details to list every location.";
const ARTIFACTS_HINT: &str = "Rerun with --details for each Not managed location's full reason.";

/// A Cargo project whose tagged target directory scans as an Eligible
/// build-artifact finding (the scoped_builds fixture shape).
fn cargo_target(root: &std::path::Path, name: &str, payload: usize) {
    let project = root.join(name);
    std::fs::create_dir_all(project.join("target")).unwrap();
    std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        project.join("target/CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(project.join("target/.rustc_info.json"), "{}").unwrap();
    std::fs::write(project.join("target/payload.bin"), vec![0u8; payload]).unwrap();
}

/// Thirteen small eligible findings plus one large: the eligible tier holds
/// fourteen rows, so ten stay visible and four fold.
fn fourteen_eligible_targets(root: &std::path::Path) {
    cargo_target(root, "big", MIB);
    for index in 0..13 {
        cargo_target(root, &format!("small-{index:02}"), SMALL_PAYLOAD);
    }
    crate::common::make_tree_non_shared_writable(root).unwrap();
}

fn scan(home: &std::path::Path, root: &std::path::Path, extra: &[&str]) -> String {
    let out = degu()
        .env("HOME", home)
        .arg("scan")
        .args(extra)
        .arg(root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn scan_human_folds_an_eligible_tier_past_ten_rows() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    fourteen_eligible_targets(root.path());

    let stdout = scan(home.path(), root.path(), &[]);

    // The tier header keeps the full tally; only the rendering folds.
    assert!(
        stdout.contains("Ready to clean - 14 locations - "),
        "stdout: {stdout}"
    );
    // Piped output renders the wide table: one data row per finding, each
    // ending in its tagged target path.
    let rows = stdout
        .lines()
        .filter(|line| line.trim_end().ends_with("/target"))
        .count();
    assert_eq!(rows, 10, "stdout: {stdout}");
    let fold = stdout
        .lines()
        .find(|line| line.starts_with("... and 4 more locations - "))
        .unwrap_or_else(|| panic!("missing fold line: {stdout}"));
    assert!(fold.ends_with(" inodes"), "stdout: {stdout}");
    // The ten visible rows are the largest: the big target never folds.
    assert!(stdout.contains("big/target"), "stdout: {stdout}");
    assert_eq!(stdout.matches(FOLDED_HINT).count(), 1, "stdout: {stdout}");
}

#[test]
fn scan_details_and_json_never_fold() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    fourteen_eligible_targets(root.path());

    let details = scan(home.path(), root.path(), &["--details"]);
    assert!(details.contains("location 14"), "stdout: {details}");
    assert!(!details.contains("more locations"), "stdout: {details}");
    assert!(!details.contains(FOLDED_HINT), "stdout: {details}");

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    assert_eq!(findings.as_array().unwrap().len(), 14);
}

#[test]
fn folded_review_tier_keeps_the_largest_preview_target() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    let seed_model = |name: &str, bytes: usize| {
        let snapshots = hub.join(name).join("snapshots/main");
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(snapshots.join("model.bin"), vec![0u8; bytes]).unwrap();
    };
    seed_model("models--org--big", MIB);
    for index in 0..11 {
        seed_model(&format!("models--org--small-{index:02}"), 8 * 1024);
    }
    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .arg("scan")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Needs review - 12 locations - "),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("... and 2 more locations - "),
        "stdout: {stdout}"
    );
    // Ranking is global and bytes-descending, so the preview still points
    // at the largest Needs review location when its tier folds.
    assert!(
        stdout.contains("degu clean -dn --review ~/.cache/huggingface/hub/models--org--big"),
        "stdout: {stdout}"
    );
}

/// One lower-bound cause stands in for all: an unreadable claimed cache
/// produces the same incomplete-scan shape as a `--budget 0s` truncation.
#[cfg(unix)]
#[test]
fn lower_bound_banner_and_fold_line_agree_on_lower_bound_marks() {
    use std::os::unix::fs::PermissionsExt;

    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "permission-denial coverage requires a non-root test process"
    );
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    fourteen_eligible_targets(root.path());
    let unreadable = root.path().join("pip-cache");
    std::fs::create_dir(&unreadable).unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &unreadable)
        .arg("scan")
        .arg(root.path())
        .output()
        .unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Scan incomplete: totals marked >= are lower bounds."),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Ready to clean - 14 locations - >= "),
        "stdout: {stdout}"
    );
    let fold = stdout
        .lines()
        .find(|line| line.starts_with("... and 4 more locations - "))
        .unwrap_or_else(|| panic!("missing fold line: {stdout}"));
    assert_eq!(fold.matches(">= ").count(), 2, "fold line: {fold}");
}

/// When a folded tier and unmanaged artifacts coincide, the one details
/// hint uses the folded-locations wording; the two hints never both print.
#[test]
fn folded_tier_and_unmanaged_artifacts_share_one_details_hint() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    fourteen_eligible_targets(root.path());
    let weak = root.path().join("decoy/__pycache__");
    std::fs::create_dir_all(&weak).unwrap();
    std::fs::write(weak.join("notes.txt"), "not bytecode").unwrap();

    let stdout = scan(home.path(), root.path(), &[]);

    assert!(
        stdout.contains("Not managed - 1 location - "),
        "stdout: {stdout}"
    );
    assert_eq!(stdout.matches(FOLDED_HINT).count(), 1, "stdout: {stdout}");
    assert!(!stdout.contains(ARTIFACTS_HINT), "stdout: {stdout}");
}
