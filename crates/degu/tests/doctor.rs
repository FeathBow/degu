use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

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

fn assert_exact_json_keys(report: &Value) {
    let mut keys = report
        .as_object()
        .expect("doctor report must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "activation_state",
            "authority_mode",
            "backend",
            "check",
            "mutated",
            "path",
            "reason",
            "remediation",
            "schema_version",
            "self_managed_path",
            "status",
            "system_path",
            "witness_path",
        ]
    );
}

fn assert_system_path(path: &str, euid: &str) {
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
}

fn assert_self_path(path: &str, euid: &str, injected_home: &Path, injected_state: &Path) {
    assert!(
        path.ends_with(&format!("/.local/state/degu/store-activation/{euid}")),
        "{path}"
    );
    let path = Path::new(path);
    assert!(!path.starts_with(injected_home), "{path:?}");
    assert!(!path.starts_with(injected_state), "{path:?}");
}

fn assert_role_paths(report: &Value, euid: &str, injected_home: &Path, injected_state: &Path) {
    let status = report["status"].as_str().expect("doctor status");
    assert!(matches!(
        status,
        "ready"
            | "missing"
            | "split_authority"
            | "recovery_required"
            | "unsafe"
            | "unsupported"
            | "uncertain"
    ));
    if let Some(path) = report["system_path"].as_str() {
        assert_system_path(path, euid);
    }
    if let Some(path) = report["self_managed_path"].as_str() {
        assert_self_path(path, euid, injected_home, injected_state);
    }
    if status == "ready" {
        let path = report["path"]
            .as_str()
            .expect("ready authority must name its selected path");
        match report["authority_mode"].as_str() {
            Some("administrator_hardened") => assert_system_path(path, euid),
            Some("self_managed") => assert_self_path(path, euid, injected_home, injected_state),
            mode => panic!("unexpected ready authority mode: {mode:?}"),
        }
    }
    if report["witness_path"].is_string() {
        assert_eq!(status, "recovery_required");
        assert!(report["path"].is_string());
    }
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

    assert_eq!(first_json["schema_version"], 2);
    assert_eq!(first_json["check"], "account_readiness");
    assert_eq!(first_json["mutated"], false);
    assert_exact_json_keys(&first_json);
    assert_exact_json_keys(&second_json);
    for field in [
        "status",
        "authority_mode",
        "activation_state",
        "path",
        "witness_path",
        "system_path",
        "self_managed_path",
        "backend",
    ] {
        assert_eq!(first_json[field], second_json[field], "field {field}");
    }
    assert_eq!(first.status.success(), first_json["status"] == "ready");
    assert_eq!(second.status.success(), second_json["status"] == "ready");

    let euid = rustix::process::geteuid().as_raw().to_string();
    assert_role_paths(&first_json, &euid, home_a.path(), state_a.path());
    assert_role_paths(&second_json, &euid, home_b.path(), state_b.path());

    // Ambient HOME, XDG state, configuration, and the integration-only
    // mutation anchor do not select either production authority candidate.
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
