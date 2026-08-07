use assert_cmd::Command;
use serde_json::Value;

#[cfg(unix)]
const UNPRIVILEGED_ID: u32 = 65_534;
#[cfg(unix)]
const TRAVERSABLE_DIR_MODE: u32 = 0o755;
#[cfg(unix)]
const OWNER_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const UNREADABLE_DIR_MODE: u32 = 0o000;

struct Fixture {
    home: tempfile::TempDir,
    config: tempfile::TempDir,
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            config: tempfile::tempdir().unwrap(),
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self) -> Command {
        #[cfg(unix)]
        self.prepare_for_unprivileged_process();
        let mut cmd = degu_command();
        cmd.env_clear()
            .env("HOME", self.home.path())
            .env("LOGNAME", self.home.path())
            .env("XDG_CONFIG_HOME", self.config.path());
        cmd
    }

    #[cfg(unix)]
    fn prepare_for_unprivileged_process(&self) {
        use std::os::unix::fs::PermissionsExt;

        if !rustix::process::geteuid().is_root() {
            return;
        }
        for path in [self.home.path(), self.config.path(), self.root.path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(TRAVERSABLE_DIR_MODE))
                .unwrap();
        }
    }
}

fn degu_command() -> Command {
    #[cfg(unix)]
    if rustix::process::geteuid().is_root() {
        use std::os::unix::process::CommandExt;

        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"));
        command.gid(UNPRIVILEGED_ID).uid(UNPRIVILEGED_ID);
        return Command::from_std(command);
    }
    Command::cargo_bin("degu").unwrap()
}

fn json(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[cfg(unix)]
fn assert_unreadable_scan_failure(
    unreadable: &std::path::Path,
    root: &std::path::Path,
    command: Command,
) {
    let out = run_unreadable_scan(unreadable, root, command);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("failed to scan project root")
    );
}

#[cfg(unix)]
fn run_unreadable_scan(
    unreadable: &std::path::Path,
    root: &std::path::Path,
    command: Command,
) -> std::process::Output {
    run_unreadable_scan_with(unreadable, root, command, &["--json"])
}

#[cfg(unix)]
fn run_unreadable_scan_with(
    unreadable: &std::path::Path,
    root: &std::path::Path,
    command: Command,
    extra_args: &[&str],
) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(
        unreadable,
        std::fs::Permissions::from_mode(UNREADABLE_DIR_MODE),
    )
    .unwrap();
    let mut command = command;
    let out = command.args(extra_args).arg(root).output().unwrap();
    std::fs::set_permissions(unreadable, std::fs::Permissions::from_mode(OWNER_DIR_MODE)).unwrap();
    out
}

#[test]
fn complete_empty_scan_reports_section_completeness() {
    let fixture = Fixture::new();
    let out = fixture
        .command()
        .args(["scan", "--json"])
        .arg(fixture.root.path())
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let report = json(&out);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert!(report["runtime"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "complete");
    assert_eq!(report["completeness"]["runtime"], "not_requested");
}

#[test]
fn expired_budget_without_roots_is_truncated() {
    let fixture = Fixture::new();
    let out = fixture
        .command()
        .args(["scan", "--only", "pip", "--budget", "0s", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let report = json(&out);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "truncated");
    assert_eq!(report["completeness"]["runtime"], "not_requested");
}

#[test]
fn zero_budget_truncates_each_requested_section() {
    let fixture = Fixture::new();
    let out = fixture
        .command()
        .args(["scan", "--budget", "0s", "--runtime", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let report = json(&out);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert!(report["runtime"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "truncated");
    assert_eq!(report["completeness"]["runtime"], "truncated");
}

#[test]
fn runtime_roots_do_not_claim_project_findings() {
    let fixture = Fixture {
        home: tempfile::tempdir().unwrap(),
        config: tempfile::tempdir().unwrap(),
        root: tempfile::tempdir_in("/tmp").unwrap(),
    };
    let artifact = fixture.root.path().join("__pycache__");
    std::fs::create_dir(&artifact).unwrap();
    std::fs::write(artifact.join("module.pyc"), [0_u8; 8]).unwrap();
    let artifact = artifact.canonicalize().unwrap();
    let out = fixture
        .command()
        .args(["scan", "--runtime", "--json"])
        .arg(fixture.root.path())
        .output()
        .unwrap();

    assert!(out.status.success());
    let report = json(&out);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["path"].as_str() == Some(artifact.to_str().unwrap()) }),
        "{report}"
    );
    assert_eq!(report["completeness"]["findings"], "complete");
}

#[test]
fn missing_scan_root_fails_instead_of_reporting_empty_success() {
    let fixture = Fixture::new();
    let missing = fixture.root.path().join("missing");
    let out = fixture
        .command()
        .args(["scan", "--json"])
        .arg(&missing)
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains(&missing.display().to_string())
    );
}

#[test]
fn non_directory_scan_root_fails_instead_of_reporting_empty_success() {
    let fixture = Fixture::new();
    let file = fixture.root.path().join("not-a-directory");
    std::fs::write(&file, []).unwrap();
    let out = fixture
        .command()
        .args(["scan", "--json"])
        .arg(&file)
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains(&file.display().to_string())
    );
}

#[cfg(unix)]
#[test]
fn unreadable_scan_root_fails_instead_of_reporting_empty_success() {
    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("checkpoint");
    std::fs::create_dir(&unreadable).unwrap();
    let mut command = fixture.command();
    command.arg("scan");
    assert_unreadable_scan_failure(&unreadable, &unreadable, command);
}

#[cfg(unix)]
#[test]
fn unreadable_scan_root_fails_before_budget_truncation() {
    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("unreadable");
    std::fs::create_dir(&unreadable).unwrap();
    let mut command = fixture.command();
    command
        .args(["scan", "--budget", "0s"])
        .arg(fixture.root.path());
    assert_unreadable_scan_failure(&unreadable, &unreadable, command);
}

#[cfg(unix)]
#[test]
fn unreadable_claimed_scan_root_fails_instead_of_reporting_complete() {
    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("pip-cache");
    std::fs::create_dir(&unreadable).unwrap();
    let mut command = fixture.command();
    command.env("PIP_CACHE_DIR", &unreadable).arg("scan");
    assert_unreadable_scan_failure(&unreadable, &unreadable, command);
}

/// Cache adapters keep a partial finding (skipped > 0) where the project walk
/// records a region and drops the unmeasured claim; both stay fail-closed.
#[cfg(unix)]
#[test]
fn unreadable_nested_claimed_root_reports_incomplete() {
    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("pip-cache");
    std::fs::create_dir(&unreadable).unwrap();
    let mut command = fixture.command();
    command.env("PIP_CACHE_DIR", &unreadable).arg("scan");
    let out = run_unreadable_scan(&unreadable, fixture.root.path(), command);
    assert!(out.status.success());
    let report = json(&out);
    assert_eq!(report["completeness"]["findings"], "incomplete");
    assert!(report["findings"][0]["skipped"].as_u64().unwrap() > 0);

    let mut command = fixture.command();
    command
        .env("PIP_CACHE_DIR", &unreadable)
        .args(["scan", "--summary"]);
    let out = run_unreadable_scan(&unreadable, fixture.root.path(), command);
    assert!(out.status.success());
    let report = json(&out);
    assert_eq!(report["total"]["lower_bound"], true);
    assert_eq!(report["ecosystems"][0]["lower_bound"], true);
    assert_eq!(report["truncated"], false);

    let mut command = fixture.command();
    command.env("PIP_CACHE_DIR", &unreadable).arg("scan");
    let out = run_unreadable_scan_with(&unreadable, fixture.root.path(), command, &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.lines().next().unwrap().contains("detected across"),
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.lines().nth(1).unwrap(),
        "Scan incomplete: totals marked >= are lower bounds.",
        "stdout: {stdout}"
    );
}

/// Degrade, not fail: the incomplete region gates only what it overlaps,
/// so cleaning a disjoint fully measured location stays possible.
#[cfg(unix)]
#[test]
fn unreadable_nested_artifact_dir_reports_incomplete_instead_of_failing() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("__pycache__");
    std::fs::create_dir(&unreadable).unwrap();
    let region = unreadable.canonicalize().unwrap();
    let pkg = fixture.root.path().join("pkg");
    let readable = pkg.join("__pycache__");
    std::fs::create_dir_all(&readable).unwrap();
    std::fs::write(readable.join("module.pyc"), [0_u8; 512]).unwrap();
    for path in [&pkg, &readable] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(TRAVERSABLE_DIR_MODE))
            .unwrap();
    }
    let readable = readable.canonicalize().unwrap();

    let mut command = fixture.command();
    command.arg("scan");
    let out = run_unreadable_scan(&unreadable, fixture.root.path(), command);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(report["completeness"]["findings"], "incomplete");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["path"].as_str() == Some(readable.to_str().unwrap())),
        "{report}"
    );

    let mut command = fixture.command();
    command.arg("clean");
    let out = run_unreadable_scan_with(&unreadable, fixture.root.path(), command, &["--dry-run"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&region.display().to_string()),
        "refusal does not name the incomplete region {}; stderr: {stderr}",
        region.display()
    );

    let mut command = fixture.command();
    command.arg("clean");
    let out = run_unreadable_scan_with(
        &unreadable,
        fixture.root.path(),
        command,
        &["--dry-run", "--path", readable.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Would move "), "stdout: {stdout}");
}

/// Accepted asymmetry: the claim is never measured, so no finding surfaces;
/// the region record alone keeps the clean gate refusing — still fail-closed.
#[cfg(unix)]
#[test]
fn unreadable_claimed_node_modules_records_a_region_but_loses_its_finding() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let app = fixture.root.path().join("app");
    std::fs::create_dir(&app).unwrap();
    std::fs::write(app.join("package.json"), "{}").unwrap();
    let unreadable = app.join("node_modules");
    std::fs::create_dir(&unreadable).unwrap();
    let region = unreadable.canonicalize().unwrap();
    let pkg = fixture.root.path().join("pkg");
    let readable = pkg.join("__pycache__");
    std::fs::create_dir_all(&readable).unwrap();
    std::fs::write(readable.join("module.pyc"), [0_u8; 512]).unwrap();
    for path in [&pkg, &readable] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(TRAVERSABLE_DIR_MODE))
            .unwrap();
    }
    let readable = readable.canonicalize().unwrap();

    let mut command = fixture.command();
    command.arg("scan");
    let out = run_unreadable_scan(&unreadable, fixture.root.path(), command);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(report["completeness"]["findings"], "incomplete");
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["path"].as_str() == Some(readable.to_str().unwrap())),
        "{report}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding["path"].as_str() == Some(region.to_str().unwrap())),
        "the unmeasured claim must not surface as a finding: {report}"
    );

    let mut command = fixture.command();
    command.arg("clean");
    let out = run_unreadable_scan_with(&unreadable, fixture.root.path(), command, &["--dry-run"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("refusing to clean on incomplete results"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&region.display().to_string()),
        "refusal does not name the incomplete region {}; stderr: {stderr}",
        region.display()
    );
}

/// Unclassified-site degrade: no probe claims the unreadable dir, so the
/// walk itself must degrade rather than fail the scan.
#[cfg(unix)]
#[test]
fn unreadable_nested_dir_under_a_readable_root_keeps_readable_findings() {
    let fixture = Fixture::new();
    let unreadable = fixture.root.path().join("data");
    std::fs::create_dir(&unreadable).unwrap();
    let readable = fixture.root.path().join("pkg/__pycache__");
    std::fs::create_dir_all(&readable).unwrap();
    std::fs::write(readable.join("module.pyc"), [0_u8; 512]).unwrap();
    let readable = readable.canonicalize().unwrap();

    let mut command = fixture.command();
    command.arg("scan");
    let out = run_unreadable_scan(&unreadable, fixture.root.path(), command);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(report["completeness"]["findings"], "incomplete");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["path"].as_str() == Some(readable.to_str().unwrap())),
        "{report}"
    );
}
