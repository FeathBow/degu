//! Regressions at the configuration and mutation command boundaries.

use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const PRIVATE_MODE: u32 = 0o700;
const CONTROL_TEXT: &str = "\u{1b}]2;review-marker\u{7}";

struct Fixture {
    _directory: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        let config = directory.path().join(format!("config{CONTROL_TEXT}"));
        let state = directory.path().join("state");
        for path in [&home, &config.join("degu"), &state.join("degu")] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
        }
        Self {
            _directory: directory,
            home,
            config,
            state,
        }
    }

    fn command(&self) -> assert_cmd::Command {
        let mut command = assert_cmd::Command::cargo_bin("degu").unwrap();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .timeout(COMMAND_TIMEOUT);
        command
    }

    fn config_path(&self) -> PathBuf {
        self.config.join("degu/config.toml")
    }

    fn config_json(&self) -> serde_json::Value {
        let output = self.command().args(["config", "--json"]).output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn advisor(&self) -> PathBuf {
        let path = self.config.join("degu/advisor");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
        path
    }
}

#[test]
fn configuration_text_escapes_controls_but_json_preserves_values() {
    let fixture = Fixture::new();
    let root = format!("/project/{CONTROL_TEXT}");
    let protect = format!("/cache/{CONTROL_TEXT}");
    let config = format!(
        "roots = [{}]\nprotect = [{}]\n",
        json_string(&root),
        json_string(&protect)
    );
    std::fs::write(fixture.config_path(), config).unwrap();
    fixture.advisor();

    let output = fixture.command().arg("config").output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert!(
        !output.stdout.contains(&b'\x1b'),
        "raw ESC reached the terminal"
    );
    assert!(
        !output.stdout.contains(&b'\x07'),
        "raw BEL reached the terminal"
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\\u{1b}]2;review-marker\\u{7}"), "{text}");
    let json = fixture.config_json();
    assert_eq!(json["roots"][0], root);
    assert_eq!(json["protect"][0], protect);
    assert!(json["file"].as_str().unwrap().contains(CONTROL_TEXT));
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn undo_rejects_fifo_state_entries_without_waiting_for_a_writer() {
    for name in ["lock", "ops.jsonl", "trashroots"] {
        let fixture = Fixture::new();
        let path = fixture.state.join("degu").join(name);
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "failed to create fixture FIFO");
        assert_rejected_state(&fixture, name);
    }
}

#[test]
fn undo_rejects_directories_at_private_file_names() {
    for name in ["lock", "ops.jsonl", "trashroots"] {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.state.join("degu").join(name)).unwrap();
        assert_rejected_state(&fixture, name);
    }
}

fn assert_rejected_state(fixture: &Fixture, name: &str) {
    let output = fixture.command().arg("undo").output().unwrap();
    assert!(
        output.status.code().is_some(),
        "{name}: command hit its timeout"
    );
    assert!(
        !output.status.success(),
        "{name}: invalid entry was accepted"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(name), "{name}: {error}");
    assert!(error.contains("not a regular file"), "{name}: {error}");
}

#[cfg(target_os = "macos")]
fn set_acl(path: &Path, rule: &str) {
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", rule])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "failed to install fixture ACL");
}

#[cfg(target_os = "macos")]
#[test]
fn advisor_with_a_mutating_acl_is_refused_even_with_private_mode_bits() {
    let fixture = Fixture::new();
    let advisor = fixture.advisor();
    set_acl(&advisor, "everyone allow write");
    assert_eq!(
        std::fs::metadata(&advisor).unwrap().permissions().mode() & 0o777,
        PRIVATE_MODE
    );
    let json = fixture.config_json();
    assert_eq!(json["advisory"]["advisor"]["status"], "refused");
    assert!(
        json["advisory"]["advisor"]["reason"]
            .as_str()
            .unwrap()
            .contains("ACL")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn non_mutating_advisor_acls_remain_usable() {
    for rule in ["everyone deny delete", "everyone allow read"] {
        let fixture = Fixture::new();
        set_acl(&fixture.advisor(), rule);
        assert_eq!(
            fixture.config_json()["advisory"]["advisor"]["status"],
            "found"
        );
    }
}
