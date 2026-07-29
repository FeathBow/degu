use assert_cmd::Command;
use std::path::Path;

#[cfg(target_os = "linux")]
const EXPECTED_SPACE_SOFT_LIMIT: u64 = 2 * 1024 * 1024;
#[cfg(target_os = "linux")]
const EXPECTED_SPACE_HARD_LIMIT: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const EXPECTED_INODE_SOFT_LIMIT: u64 = 20;
#[cfg(target_os = "linux")]
const EXPECTED_INODE_HARD_LIMIT: u64 = 40;

fn degu(home: &Path) -> Command {
    let mut command = Command::cargo_bin("degu").unwrap();
    command
        .env_clear()
        .env("HOME", home)
        .env("DEGU_ALLOW_ROOT", "1");
    command
}

#[test]
fn quota_missing_target_fails_without_json_stdout() {
    let home = tempfile::tempdir().unwrap();
    let output = degu(home.path())
        .args(["quota", "--json"])
        .arg(home.path().join("missing"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("quota target is unavailable"));
}

#[test]
fn quota_missing_target_escapes_terminal_controls_in_stderr() {
    let home = tempfile::tempdir().unwrap();
    let target = home.path().join("literal\\nmissing\n\x1b]8;;unsafe\x07");
    let output = degu(home.path())
        .args(["quota", "--json"])
        .arg(target)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    assert!(
        stderr.contains("literal\\\\nmissing\\n\\u{1b}]8;;unsafe\\u{7}"),
        "{stderr:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn quota_macos_reports_unsupported_without_fallback() {
    let home = tempfile::tempdir().unwrap();
    let output = degu(home.path())
        .args(["quota", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("quota unsupported"), "{stderr}");
    assert!(stderr.contains("authoritative user quota"), "{stderr}");
    assert!(stderr.contains("degu scan"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn quota_linux_returns_authoritative_state_or_explicit_error() {
    let home = tempfile::tempdir().unwrap();
    let output = degu(home.path())
        .args(["quota", "--json"])
        .output()
        .unwrap();

    if output.status.success() {
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["state"], "active");
        match json["provider"].as_str().unwrap() {
            "linux_vfs" => {
                assert_eq!(json["data_source"], "linux_quotactl");
                assert_eq!(json["scope"]["filesystem"], "ext4");
            }
            "lustre_lfs" => {
                assert_eq!(json["data_source"], "lfs_quota");
                assert_eq!(json["scope"]["filesystem"], "lustre");
            }
            other => panic!("unexpected quota provider {other}"),
        }
        return;
    }
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        [
            "quota unsupported",
            "quota not configured",
            "quota provider unavailable",
            "quota permission denied",
            "quota provider returned incomplete data"
        ]
        .iter()
        .any(|prefix| stderr.contains(prefix)),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a quota-enabled ext4 filesystem"]
fn quota_linux_ext4_fixture_reports_configured_limits() {
    let path = std::env::var_os("DEGU_QUOTA_TEST_PATH")
        .map(std::path::PathBuf::from)
        .expect("DEGU_QUOTA_TEST_PATH must name the ext4 fixture");
    let output = degu(&path)
        .args(["quota", "--json"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["state"], "active");
    assert_eq!(json["provider"], "linux_vfs");
    assert_eq!(json["data_source"], "linux_quotactl");
    assert_eq!(json["scope"]["filesystem"], "ext4");
    assert_eq!(json["subject"]["kind"], "user");
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let subject_id = unsafe { libc::geteuid() };
    assert_eq!(json["subject"]["id"], subject_id);
    assert_eq!(json["space"]["soft_limit"], EXPECTED_SPACE_SOFT_LIMIT);
    assert_eq!(json["space"]["hard_limit"], EXPECTED_SPACE_HARD_LIMIT);
    assert_eq!(json["inodes"]["soft_limit"], EXPECTED_INODE_SOFT_LIMIT);
    assert_eq!(json["inodes"]["hard_limit"], EXPECTED_INODE_HARD_LIMIT);
    for dimension in ["space", "inodes"] {
        assert!(json[dimension]["used"].is_number());
        assert!(json[dimension]["headroom_to_hard_limit"].is_number());
        assert!(json[dimension]["grace"].is_null());
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a Lustre mount"]
fn quota_linux_lustre_fixture_reports_the_lfs_provider() {
    let path = std::env::var_os("DEGU_QUOTA_LUSTRE_TEST_PATH")
        .map(std::path::PathBuf::from)
        .expect("DEGU_QUOTA_LUSTRE_TEST_PATH must name a path on a Lustre mount");
    let home = tempfile::tempdir().unwrap();
    let output = degu(home.path())
        .args(["quota", "--json"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["state"], "active");
    assert_eq!(json["provider"], "lustre_lfs");
    assert_eq!(json["data_source"], "lfs_quota");
    assert_eq!(json["scope"]["filesystem"], "lustre");
    assert_eq!(json["subject"]["kind"], "user");
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let subject_id = unsafe { libc::geteuid() };
    assert_eq!(json["subject"]["id"], subject_id);
    for dimension in ["space", "inodes"] {
        assert!(json[dimension]["used"].is_number());
    }
}
