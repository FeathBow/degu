use assert_cmd::Command;
use std::path::Path;

fn degu(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("degu").unwrap();
    cmd.env_clear().env("HOME", home).env("LOGNAME", home);
    cmd
}

fn config_home(disable: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("degu")).unwrap();
    let disabled = disable
        .iter()
        .map(|adapter| format!("\"{adapter}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.path().join("degu/config.toml"),
        format!("disable = [{disabled}]\n"),
    )
    .unwrap();
    dir
}

fn scan_runtime_json(home: &Path, tmp: &Path, slurm_job_id: Option<&str>) -> serde_json::Value {
    let mut cmd = degu(home);
    cmd.env("TMPDIR", tmp);
    match slurm_job_id {
        Some(job_id) => {
            cmd.env("SLURM_JOB_ID", job_id);
        }
        None => {
            cmd.env_remove("SLURM_JOB_ID");
        }
    }
    let out = cmd.args(["scan", "--runtime", "--json"]).output().unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn scan_json_reports_or_marks_incomplete_after_shm_handle_is_dropped() {
    let home = tempfile::tempdir().unwrap();
    let name = format!("torch_degu{}", std::process::id());
    let file = tempfile::Builder::new()
        .prefix(&name)
        .tempfile_in("/dev/shm")
        .unwrap();
    let path = file.path().to_path_buf();
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    file.as_file().set_modified(stale).unwrap();

    let out = degu(home.path())
        .args(["scan", "--runtime", "--only", "shm", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let held = report["runtime"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["path"] == path.display().to_string());
    assert!(!held);

    let _guard = file.into_temp_path();
    let out = degu(home.path())
        .args(["scan", "--runtime", "--only", "shm", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let finding = report["runtime"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["path"] == path.display().to_string());
    if let Some(finding) = finding {
        assert_eq!(finding["ecosystem"], "shm");
        assert_eq!(finding["disposition"]["mode"], "report_only");
    } else {
        assert_eq!(report["completeness"]["runtime"], "incomplete");
    }
}

#[test]
fn scan_json_reports_stale_tmp_entries_unless_slurm_owns_tmp() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old.tmp");
    let fresh = tmp.path().join("fresh.tmp");
    std::fs::write(&old, [0u8; 4096]).unwrap();
    std::fs::write(&fresh, [0u8; 4096]).unwrap();
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(stale)
        .unwrap();

    let report = scan_runtime_json(home.path(), tmp.path(), None);
    let finding = report["runtime"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["path"] == old.display().to_string())
        .unwrap();
    assert_eq!(finding["ecosystem"], "tmp");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert!(
        report["runtime"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["path"] != fresh.display().to_string())
    );

    let report = scan_runtime_json(home.path(), tmp.path(), Some("123"));
    for member in ["findings", "runtime"] {
        assert!(
            report[member]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["path"] != old.display().to_string())
        );
        assert!(
            report[member]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["path"] != fresh.display().to_string())
        );
    }
}

#[test]
fn scan_summary_json_reports_truncated_when_tmp_budget_is_expired() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["shm"]);

    let out = degu(home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--summary", "--budget", "0s", "--runtime", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["truncated"], true);
}

#[test]
fn scan_summary_json_reports_truncated_when_shm_budget_is_expired() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["tmp"]);

    let out = degu(home.path())
        .env("XDG_CONFIG_HOME", config.path())
        .args(["scan", "--summary", "--budget", "0s", "--runtime", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["truncated"], true);
}
