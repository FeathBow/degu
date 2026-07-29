use super::support::*;

const MIN_STALE_DAYS: u64 = 10;
const STALE_CONTENT_AGE: std::time::Duration =
    std::time::Duration::from_secs((MIN_STALE_DAYS + 1) * 24 * 60 * 60);
const STALE_ENTRY_AGE: std::time::Duration =
    std::time::Duration::from_secs(MIN_STALE_DAYS * 3 * 24 * 60 * 60);

#[test]
fn bare_scan_excludes_node_runtime_adapters_by_default() {
    let home = tempfile::tempdir().unwrap();
    let (tmp, stale_file) = fake_stale_tmpdir();

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["-v", "scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["runtime"].as_array().unwrap().len(), 0);
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);
    let stderr = String::from_utf8(strip_sgr(&out.stderr)).unwrap();
    assert!(!stderr.contains(&stale_file.display().to_string()));
    assert!(!stderr.contains(tmp.path().to_str().unwrap()));

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["scan"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("node-runtime"));
}

#[test]
fn scan_runtime_flag_reports_tmp_findings_in_the_runtime_array() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let stale_tree = tmp.path().join("stale-tree");
    let active_tree = tmp.path().join("active-tree");
    let stale_dir = stale_tree.join("deep");
    let stale_file = stale_dir.join("stale.bin");
    let fresh_file = active_tree.join("deep/fresh.bin");
    std::fs::create_dir_all(&stale_dir).unwrap();
    std::fs::create_dir_all(fresh_file.parent().unwrap()).unwrap();
    std::fs::write(&stale_file, [0_u8; 4096]).unwrap();
    std::fs::write(&fresh_file, [0_u8; 4096]).unwrap();
    for (path, age) in [
        (&stale_file, STALE_CONTENT_AGE),
        (&stale_dir, STALE_CONTENT_AGE),
        (&stale_tree, STALE_ENTRY_AGE),
        (&active_tree, STALE_ENTRY_AGE),
    ] {
        std::fs::File::open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }
    let stale_tree = stale_tree.canonicalize().unwrap();
    let active_tree = active_tree.canonicalize().unwrap();
    let active_path = active_tree.display().to_string();

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["scan", "--runtime", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let runtime = report["runtime"].as_array().unwrap();
    let finding = runtime
        .iter()
        .find(|finding| finding["path"] == stale_tree.display().to_string())
        .unwrap();
    assert_eq!(finding["age_days"], MIN_STALE_DAYS + 1);
    assert!(runtime.iter().all(|finding| finding["path"] != active_path));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["ecosystem"] != "tmp" && finding["ecosystem"] != "shm")
    );
}

#[test]
fn scan_config_runtime_true_reports_tmp_findings_in_the_runtime_array() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let empty_dir = tmp.path().join("old-empty");
    std::fs::create_dir(&empty_dir).unwrap();
    std::fs::File::open(&empty_dir)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - STALE_ENTRY_AGE)
        .unwrap();
    let empty_dir = empty_dir.canonicalize().unwrap();
    let config_home = runtime_config_home("runtime = true\n");

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let finding = report["runtime"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["path"] == empty_dir.display().to_string())
        .unwrap();
    assert_eq!(finding["ecosystem"], "tmp");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(finding["age_days"], MIN_STALE_DAYS * 3);
    assert_eq!(finding["bytes_apparent"], 0);
    assert_eq!(finding["inodes"], 1);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["ecosystem"] != "tmp" && finding["ecosystem"] != "shm")
    );
}

#[test]
fn scan_runtime_bytes_stay_out_of_the_degu_visible_total() {
    let home = tempfile::tempdir().unwrap();
    let pip = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel.whl"), [0u8; 4 * 1024]).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let stale_file = tmp.path().join("old.tmp");
    std::fs::write(&stale_file, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let stale = std::time::SystemTime::now() - STALE_CONTENT_AGE;
    std::fs::File::options()
        .write(true)
        .open(&stale_file)
        .unwrap()
        .set_modified(stale)
        .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .args(["scan", "--runtime"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let summary = stdout
        .lines()
        .find(|line| line.contains(" detected across "))
        .expect("scan must print the detected-storage summary line");
    let (total, _, _, _) = parse_summary_sizes(&stdout);
    assert!(
        total < 1024.0 * 1024.0,
        "runtime bytes leaked into the detected-storage total: {summary}"
    );
    assert!(stdout.contains("node-runtime (Not managed):"));
    assert!(stdout.contains("Total node-runtime:"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn explicitly_selecting_shm_off_linux_fails_loudly() {
    let home = tempfile::tempdir().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--runtime", "--only", "shm", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("shm is only available on Linux"),
        "{stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
