use assert_cmd::Command;
use serde_json::Value;

fn doctor_with_environment(
    home: &std::path::Path,
    state: &std::path::Path,
) -> std::process::Output {
    Command::cargo_bin("degu")
        .unwrap()
        .env_clear()
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .env(
            "XDG_CONFIG_HOME",
            home.join("config-does-not-select-authority"),
        )
        .env("DEGU_ALLOW_ROOT", "1")
        // The integration binary enables a mutation-only test seam. Doctor
        // must still ignore it and report the real platform/EUID authority.
        .env("DEGU_INTEGRATION_TEST_ANCHOR", state.join("fake-anchor"))
        .args(["doctor", "--json"])
        .output()
        .unwrap()
}

#[test]
fn doctor_is_one_short_read_only_command_with_stable_json() {
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();
    let state_a = tempfile::tempdir().unwrap();
    let state_b = tempfile::tempdir().unwrap();

    let first = doctor_with_environment(home_a.path(), state_a.path());
    let second = doctor_with_environment(home_b.path(), state_b.path());
    let first_json: Value = serde_json::from_slice(&first.stdout).unwrap();
    let second_json: Value = serde_json::from_slice(&second.stdout).unwrap();

    assert_eq!(first_json["schema_version"], 1);
    assert_eq!(first_json["check"], "account_readiness");
    assert_eq!(first_json["mutated"], false);
    assert_eq!(first_json["path"], second_json["path"]);
    assert_eq!(first_json["status"], second_json["status"]);
    assert_eq!(first.status.success(), first_json["status"] == "ready");
    assert_eq!(second.status.success(), second_json["status"] == "ready");

    let path = first_json["path"].as_str().unwrap();
    let euid = rustix::process::geteuid().as_raw().to_string();
    assert!(path.ends_with(&format!("/{euid}")), "{path}");
    #[cfg(target_os = "linux")]
    assert!(
        path.starts_with("/var/lib/degu/store-activation/"),
        "{path}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        path.starts_with("/private/var/db/degu/store-activation/"),
        "{path}"
    );

    assert!(std::fs::read_dir(state_a.path()).unwrap().next().is_none());
    assert!(std::fs::read_dir(state_b.path()).unwrap().next().is_none());
}

#[test]
fn doctor_accepts_no_authority_path_argument() {
    Command::cargo_bin("degu")
        .unwrap()
        .env("DEGU_ALLOW_ROOT", "1")
        .args(["doctor", "/tmp/caller-selected-anchor"])
        .assert()
        .failure()
        .stdout("");
}
