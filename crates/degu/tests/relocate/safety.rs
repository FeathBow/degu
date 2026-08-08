use crate::relocate_support::generated_script;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55\n";

/// A tempdir whose own mode is owner-only, so `--init` trusts it as a
/// relocate-target parent regardless of the ambient umask (002 on the Linux
/// test runners would otherwise leave it group-writable and refused).
fn private_scratch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn relocate_init(home: &std::path::Path, target: &std::path::Path) -> std::process::Output {
    crate::relocate_support::degu()
        .env("HOME", home)
        .args(["relocate", "--init", "--json"])
        .arg(target)
        .output()
        .unwrap()
}

fn assert_init_failure_without_output(output: &std::process::Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn relocate_init_creates_only_exact_cache_roots_with_private_modes() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let hf_home = scratch.path().join("hf-home");
    let cargo_home = scratch.path().join("cargo-home");
    std::fs::create_dir(&hf_home).unwrap();
    std::fs::create_dir(&cargo_home).unwrap();
    std::fs::write(hf_home.join("token"), b"hugging face token").unwrap();
    std::fs::write(cargo_home.join("credentials.toml"), b"cargo credentials").unwrap();
    let output = std::process::Command::new("sh")
        .env("HOME", home.path())
        .env("HF_HOME", &hf_home)
        .env("CARGO_HOME", &cargo_home)
        .env("XDG_CONFIG_HOME", crate::common::isolated_config_home())
        .args([
            "-c",
            "umask 002; exec \"$1\" relocate --init --json \"$2\"",
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_degu"))
        .arg(&target)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["initialization"]["requested"], true);
    assert!(
        report["initialization"]["already_initialized"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["initialization"]["failed"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let roots = report["exports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|export| std::path::PathBuf::from(export["value"].as_str().unwrap()))
        .collect::<BTreeSet<_>>();
    let initialized = report["initialization"]["initialized"].as_array().unwrap();
    assert_eq!(initialized.len(), roots.len());
    assert!(initialized.iter().all(|entry| entry["state"] == "created"));

    assert_eq!(
        std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!target.join("CACHEDIR.TAG").exists());
    assert!(!hf_home.join("CACHEDIR.TAG").exists());
    assert!(!cargo_home.join("CACHEDIR.TAG").exists());
    assert_eq!(
        std::fs::read(hf_home.join("token")).unwrap(),
        b"hugging face token"
    );
    assert_eq!(
        std::fs::read(cargo_home.join("credentials.toml")).unwrap(),
        b"cargo credentials"
    );
    for root in roots {
        assert_eq!(
            std::fs::symlink_metadata(&root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "{}",
            root.display()
        );
        let tag = root.join("CACHEDIR.TAG");
        assert_eq!(
            std::fs::read_to_string(&tag).unwrap(),
            CACHEDIR_TAG_SIGNATURE
        );
        assert_eq!(
            std::fs::symlink_metadata(&tag)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{}",
            tag.display()
        );
    }
}

#[test]
fn relocate_init_creates_private_directories_under_a_restrictive_umask() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let output = std::process::Command::new("sh")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", crate::common::isolated_config_home())
        .args([
            "-c",
            "umask 0777; exec \"$1\" relocate --init --json \"$2\"",
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_degu"))
        .arg(&target)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for entry in report["initialization"]["initialized"].as_array().unwrap() {
        let root = std::path::Path::new(entry["path"].as_str().unwrap());
        assert_eq!(
            std::fs::symlink_metadata(root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::symlink_metadata(root.join("CACHEDIR.TAG"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn relocate_init_rejects_preexisting_untagged_roots_without_mutation() {
    for payload in [None, Some(b"existing cache bytes".as_slice())] {
        let home = tempfile::tempdir().unwrap();
        let scratch = private_scratch();
        let target = scratch.path().join("cache");
        let pip = target.join("pip");
        std::fs::create_dir_all(&pip).unwrap();
        if let Some(bytes) = payload {
            std::fs::write(pip.join("payload.bin"), bytes).unwrap();
        }
        crate::common::make_tree_non_shared_writable(&target).unwrap();

        let output = relocate_init(home.path(), &target);

        assert_init_failure_without_output(&output);
        assert!(!pip.join("CACHEDIR.TAG").exists());
        let entries = std::fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [std::ffi::OsString::from("pip")]);
        if let Some(bytes) = payload {
            assert_eq!(std::fs::read(pip.join("payload.bin")).unwrap(), bytes);
        }
    }
}

#[test]
fn relocate_init_is_idempotent_and_preserves_existing_payloads() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let first = relocate_init(home.path(), &target);
    assert!(first.status.success());
    let payload = target.join("pip/payload.bin");
    std::fs::write(&payload, b"existing cache bytes").unwrap();

    let second = relocate_init(home.path(), &target);

    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert!(
        report["initialization"]["initialized"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        report["initialization"]["already_initialized"]
            .as_array()
            .unwrap()
            .len(),
        report["exports"].as_array().unwrap().len()
    );
    assert!(
        report["initialization"]["already_initialized"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["state"] == "already_initialized")
    );
    assert_eq!(std::fs::read(payload).unwrap(), b"existing cache bytes");
}

#[test]
fn initialized_roots_preserve_adapter_dispositions_during_scan() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let initialized = relocate_init(home.path(), &target);
    assert!(initialized.status.success());
    let pip = target.join("pip");
    let uv = target.join("uv");
    let wandb = target.join("wandb");
    std::fs::write(pip.join("wheel.bin"), [0_u8; 4096]).unwrap();
    std::fs::write(uv.join("archive.zip"), [0_u8; 4096]).unwrap();
    let wandb_object = wandb.join("artifacts/obj/md5/aa/digest");
    std::fs::create_dir_all(wandb_object.parent().unwrap()).unwrap();
    std::fs::write(&wandb_object, [0_u8; 4096]).unwrap();

    let output = crate::relocate_support::degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip)
        .env("UV_CACHE_DIR", &uv)
        .env("WANDB_CACHE_DIR", &wandb)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let pip_finding = findings
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap();
    assert_eq!(pip_finding["confidence"], "verified");
    assert_eq!(pip_finding["disposition"]["mode"], "eligible");
    let uv_finding = findings
        .iter()
        .find(|finding| finding["ecosystem"] == "uv")
        .unwrap();
    assert_eq!(uv_finding["confidence"], "verified");
    assert_eq!(uv_finding["disposition"]["mode"], "report_only");
    assert!(findings.iter().any(|finding| {
        finding["ecosystem"] == "wandb" && finding["disposition"]["mode"] == "report_only"
    }));
}

#[test]
fn relocate_init_invalid_targets_fail_without_mutation_or_stdout() {
    let home = tempfile::tempdir().unwrap();
    let relative = std::path::Path::new("relative");
    let output = relocate_init(home.path(), relative);
    assert_init_failure_without_output(&output);
    assert!(!relative.exists());

    let scratch = private_scratch();
    let file = scratch.path().join("file");
    std::fs::write(&file, b"target bytes").unwrap();
    let output = relocate_init(home.path(), &file);
    assert_init_failure_without_output(&output);
    assert_eq!(std::fs::read(file).unwrap(), b"target bytes");

    let non_utf8 = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/degu-relocate-init-invalid-\xff".to_vec(),
    ));
    let output = relocate_init(home.path(), &non_utf8);
    assert_init_failure_without_output(&output);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("valid UTF-8")
    );
    assert!(!non_utf8.exists());
}

#[test]
fn relocate_init_rejects_a_symlink_target_base() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let outside = scratch.path().join("outside");
    let target = scratch.path().join("cache");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, &target).unwrap();

    let output = relocate_init(home.path(), &target);

    assert_init_failure_without_output(&output);
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());

    let target_with_slash = std::path::PathBuf::from(format!("{}/", target.display()));
    let output = relocate_init(home.path(), &target_with_slash);

    assert_init_failure_without_output(&output);
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
}

#[test]
fn relocate_script_preserves_failure_when_an_export_is_readonly() {
    let home = tempfile::tempdir().unwrap();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let script = generated_script(home.path(), &target);
    let sourced = std::process::Command::new("bash")
        .env_remove("PIP_CACHE_DIR")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            "readonly PIP_CACHE_DIR=original; . \"$1\" && rm -f \"$1\"; status=$?; [ -e \"$1\" ] || exit 99; exit \"$status\"",
            "bash",
        ])
        .arg(&script)
        .output()
        .unwrap();
    assert!(!sourced.status.success());
    assert_ne!(sourced.status.code(), Some(99));
    assert!(script.exists());
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the test removes an initialized root to prove a stale saved script fails visibly instead of recreating it"
)]
fn initialized_script_verifies_roots_without_recreating_them() {
    let home = private_scratch();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let output = crate::relocate_support::degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", crate::common::isolated_config_home())
        .args(["relocate", "--init"])
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let script = String::from_utf8(output.stdout).unwrap();
    assert!(
        script.contains("[ -d "),
        "initialized script must verify roots exist: {script}"
    );
    assert!(
        !script.contains("mkdir -p"),
        "initialized script must not recreate roots: {script}"
    );

    let pip = target.join("pip");
    assert!(pip.is_dir());
    std::fs::remove_dir_all(&pip).unwrap();
    let script_path = scratch.path().join("relocate.sh");
    std::fs::write(&script_path, &script).unwrap();
    let sourced = std::process::Command::new("sh")
        .args(["-c", "umask 002; . \"$1\"", "sh"])
        .arg(&script_path)
        .output()
        .unwrap();

    assert!(
        !sourced.status.success(),
        "sourcing must fail after an initialized root was removed"
    );
    assert!(!pip.exists(), "sourcing must not recreate a removed root");
}

#[test]
fn a_group_writable_descendant_keeps_an_initialized_root_report_only() {
    let home = private_scratch();
    let scratch = private_scratch();
    let target = scratch.path().join("cache");
    let init = relocate_init(home.path(), &target);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let pip = target.join("pip");
    // A cache tool running under umask 002 leaves a group-writable descendant;
    // degu keeps the tree report-only until a cooperative-trust policy lands.
    let descendant = pip.join("http-cache");
    std::fs::create_dir(&descendant).unwrap();
    std::fs::set_permissions(&descendant, std::fs::Permissions::from_mode(0o775)).unwrap();
    std::fs::write(descendant.join("blob"), [0_u8; 4096]).unwrap();

    let output = crate::relocate_support::degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip)
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let pip_finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap();
    assert_eq!(pip_finding["confidence"], "verified");
    assert_eq!(pip_finding["disposition"]["mode"], "report_only");
}
