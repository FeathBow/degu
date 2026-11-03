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
            "nfs_rquota" => {
                assert_eq!(json["data_source"], "quota_tool");
                let filesystem = json["scope"]["filesystem"].as_str().unwrap();
                assert!(filesystem.starts_with("nfs"), "{filesystem}");
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
    let subject_id = rustix::process::geteuid().as_raw();
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
    let subject_id = rustix::process::geteuid().as_raw();
    assert_eq!(json["subject"]["id"], subject_id);
    for dimension in ["space", "inodes"] {
        assert!(json[dimension]["used"].is_number());
    }
    assert!(json["other_subjects"].is_array());
    assert!(json["limits_complete"].is_boolean());
}

/// `degu quota` end to end, with a stand-in host: a mount table, and tools that
/// answer the way the real ones do. Only this reaches the command's own wiring, so
/// it is what fails if the command stops asking about every subject. The host is
/// read from a variable only a debug build looks at, so these need one too.
#[cfg(all(target_os = "linux", debug_assertions))]
mod stand_in {
    use super::degu;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    const HOST_ENV: &str = "DEGU_QUOTA_TEST_HOST";
    const DEADLINE_ENV: &str = "DEGU_QUOTA_TEST_DEADLINE_MS";
    const LFS_COLUMNS: &str =
        "     Filesystem  kbytes   quota   limit   grace   files   quota   limit   grace";
    const QUOTA_COLUMNS: &str =
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace";

    /// Written by a child process, so this test process never holds the file open
    /// for writing. A concurrent test's fork would otherwise inherit that descriptor
    /// and the stand-in's exec could fail with ETXTBSY.
    fn install_tool(path: &Path, body: &str) {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    /// A directory the stand-in mount table says is a mount of this filesystem.
    fn host(filesystem: &str, source: &str) -> (tempfile::TempDir, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(target.path()).unwrap();
        std::fs::write(
            root.path().join("mountinfo"),
            format!(
                "40 25 0:64 / {} rw - {filesystem} {source} rw\n",
                canonical.display()
            ),
        )
        .unwrap();
        (root, target)
    }

    fn lfs_body(group_answer: &str) -> String {
        format!(
            "#!/bin/sh\nC='{LFS_COLUMNS}'\ncase \"$1 $2\" in\n'project -d') echo \"654321 P $3\" ;;\n'quota -u') echo \"Disk quotas for usr me (uid $3):\"; echo \"$C\"; echo \"  $4 8 0 0 - 8 0 0 -\" ;;\n'quota -p') echo \"Disk quotas for prj $3 (pid $3):\"; echo \"$C\"; echo \"  $4 2048 0 5120 - 81 0 100 -\" ;;\n'quota -g') {group_answer} ;;\nesac\n"
        )
    }

    fn lustre(group_answer: &str) -> (tempfile::TempDir, tempfile::TempDir) {
        let (root, target) = host("lustre", "10.0.0.1@tcp:/scratch");
        install_tool(&root.path().join("lfs"), &lfs_body(group_answer));
        (root, target)
    }

    fn run(root: &Path, target: &Path, json: bool) -> std::process::Output {
        let home = tempfile::tempdir().unwrap();
        let mut command = degu(home.path());
        command.env(HOST_ENV, root).arg("quota");
        if json {
            command.arg("--json");
        }
        command.arg(target).output().unwrap()
    }

    fn report(root: &Path, target: &Path) -> serde_json::Value {
        let output = run(root, target, true);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    const GROUP_ANSWERS: &str =
        "echo \"Disk quotas for grp lab (gid $3):\"; echo \"$C\"; echo \"  $4 9 0 0 - 9 0 0 -\"";

    #[test]
    fn lustre_every_subject() {
        let (root, target) = lustre(GROUP_ANSWERS);
        let json = report(root.path(), target.path());

        assert_eq!(json["provider"], "lustre_lfs");
        assert_eq!(json["subject"]["kind"], "user");
        assert!(json["space"]["hard_limit"].is_null());
        let others = json["other_subjects"].as_array().unwrap();
        assert_eq!(others.len(), 2, "{json}");
        assert_eq!(others[0]["kind"], "project");
        assert_eq!(others[0]["id"], 654_321);
        assert_eq!(others[0]["inodes"]["hard_limit"], 100);
        assert_eq!(others[1]["kind"], "group");
        assert_eq!(others[1]["state"], "active");
        assert_eq!(json["limits_complete"], true);
        assert_eq!(json["leading_limit"]["subject_kind"], "project");
        assert_eq!(json["leading_limit"]["dimension"], "inodes");
        assert_eq!(json["leading_limit"]["at_limit"], false);

        let human = run(root.path(), target.path(), false);
        let text = String::from_utf8_lossy(&human.stdout);
        assert!(human.status.success(), "{text}");
        assert!(text.contains("Highest use project 654321 inodes"), "{text}");
        assert!(text.contains("Project 654321"), "{text}");
        assert!(text.contains("Group "), "{text}");
    }

    #[test]
    fn lustre_partial_failure() {
        let (root, target) = lustre("echo 'lfs quota: group refused' >&2; exit 1");
        let json = report(root.path(), target.path());

        let others = json["other_subjects"].as_array().unwrap();
        assert_eq!(others[0]["state"], "active");
        assert_eq!(others[1]["kind"], "group");
        assert_eq!(others[1]["state"], "unavailable");
        assert!(
            others[1]["reason"]
                .as_str()
                .unwrap()
                .contains("group refused")
        );
        assert_eq!(json["limits_complete"], false);

        let human = run(root.path(), target.path(), false);
        let text = String::from_utf8_lossy(&human.stdout);
        assert!(human.status.success(), "{text}");
        assert!(text.contains("could not be read"), "{text}");
        assert!(text.contains("may not be the one that matters"), "{text}");
    }

    fn nfs_body(source: &str, group_answer: &str, mount: &Path) -> String {
        format!(
            "#!/bin/sh\ncase \"$5\" in\n-u) echo 'Disk quotas for user me (uid '\"$(id -u)\"'): '; echo '{QUOTA_COLUMNS}'; echo '{source} {} 8 0 16 0 1 0 0 0' ;;\n-g) {group_answer} ;;\nesac\n",
            mount.display()
        )
    }

    #[test]
    fn nfs_refused_group() {
        let source = "nfs.example:/p2/home";
        let (root, target) = host("nfs4", source);
        let mount = std::fs::canonicalize(target.path()).unwrap();
        install_tool(
            &root.path().join("quota"),
            &nfs_body(
                source,
                "echo \"quota: error while getting quota from nfs.example:/p2/home for lab (id $(id -g)): Connection refused\" >&2",
                &mount,
            ),
        );
        let json = report(root.path(), target.path());

        assert_eq!(json["provider"], "nfs_rquota");
        assert_eq!(json["space"]["hard_limit"], 16 * 1024);
        assert_eq!(json["other_subjects"][0]["kind"], "group");
        assert_eq!(json["other_subjects"][0]["state"], "unavailable");
        assert_eq!(json["other_subjects"][0]["reason"], "Connection refused");
        assert_eq!(json["limits_complete"], false);
    }

    #[test]
    fn nfs_other_source() {
        let (root, target) = host("nfs4", "nfs.example:/p2/home");
        let mount = std::fs::canonicalize(target.path()).unwrap();
        install_tool(
            &root.path().join("quota"),
            &nfs_body("other.example:/p2/home", "exit 0", &mount),
        );
        let output = run(root.path(), target.path(), true);

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("quota provider returned incomplete data"),
            "{stderr}"
        );
        assert!(stderr.contains("other.example:/p2/home"), "{stderr}");
    }

    /// Gone, or finished and waiting for whoever adopted it to reap it.
    fn has_ended(pid: &str) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return true;
        };
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z'))
    }

    // The deadline ends degu with a tool still running, and only the thread that
    // degu is about to lose was watching that tool's own time limit.
    #[test]
    fn deadline_kills_tool() {
        let (root, target) = host("lustre", "10.0.0.1@tcp:/scratch");
        let pid_file = root.path().join("tool.pid");
        install_tool(
            &root.path().join("lfs"),
            &format!(
                "#!/bin/sh\necho $$ > '{}'\nexec sleep 300\n",
                pid_file.display()
            ),
        );
        let home = tempfile::tempdir().unwrap();
        let output = degu(home.path())
            .env(HOST_ENV, root.path())
            .env(DEADLINE_ENV, "1000")
            .args(["quota", "--json"])
            .arg(target.path())
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("did not answer within"), "{stderr}");
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let pid = pid.trim();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !has_ended(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let ended = has_ended(pid);
        if !ended {
            // Do not leave it behind when this fails.
            let _ = Command::new("kill").args(["-9", pid]).status();
        }
        assert!(ended, "the tool outlived degu");
    }
}

/// With debug assertions off the stand-in must be ignored: the real mount table is
/// read, so the stand-in tool never runs. `cargo test --release` cannot build this
/// today, because this crate's tests turn on `integration-test-anchor`, which refuses
/// to compile without debug assertions. It stays here so the check is written down
/// next to the seam it guards, and it passes with that feature removed.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[test]
fn release_ignores_host() {
    let root = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(target.path()).unwrap();
    std::fs::write(
        root.path().join("mountinfo"),
        format!(
            "40 25 0:64 / {} rw - lustre 10.0.0.1@tcp:/scratch rw\n",
            canonical.display()
        ),
    )
    .unwrap();
    let marker = root.path().join("tool-ran");
    let tool = root.path().join("lfs");
    std::fs::write(&tool, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    let mut permissions = std::fs::metadata(&tool).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&tool, permissions).unwrap();
    let output = degu(root.path())
        .env("DEGU_QUOTA_TEST_HOST", root.path())
        .env("DEGU_QUOTA_TEST_DEADLINE_MS", "1")
        .args(["quota", "--json"])
        .arg(target.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!marker.exists(), "{stdout}{stderr}");
    assert!(!stdout.contains("lustre_lfs"), "{stdout}");
    // The deadline seam is gone too: one millisecond would have failed this.
    assert!(!stderr.contains("did not answer within"), "{stderr}");
}
