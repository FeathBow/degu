use std::os::unix::ffi::OsStringExt;

#[path = "support/mod.rs"]
mod common;
#[cfg(target_os = "linux")]
#[path = "relocate/native_paths.rs"]
mod native_paths;
mod relocate_support;
#[path = "relocate/safety.rs"]
mod safety;
use relocate_support::{degu, generated_script};

const HF_HOME_RELOCATION_REFUSAL_REASON: &str = "HF_HOME also decides where huggingface-cli login writes its token; degu does not move credentials";
const CARGO_HOME_RELOCATION_REFUSAL_REASON: &str =
    "CARGO_HOME also carries installed binaries and credentials, so degu leaves it unchanged";

fn assert_relocation_exports(report: &serde_json::Value, uv_cache: &std::path::Path) {
    let exports = report["exports"].as_array().unwrap();
    let uv = exports
        .iter()
        .find(|export| export["ecosystem"] == "uv")
        .unwrap();
    assert_eq!(uv["var"], "UV_CACHE_DIR");
    assert_eq!(uv["value"], "/scratch/x/uv");
    assert_eq!(
        uv["current"],
        serde_json::json!([uv_cache.to_string_lossy().to_string()])
    );
    let hf = exports
        .iter()
        .find(|export| export["ecosystem"] == "huggingface")
        .unwrap();
    assert_eq!(hf["var"], "HF_HUB_CACHE");
    assert_eq!(hf["value"], "/scratch/x/huggingface/hub");
    let datasets = exports
        .iter()
        .find(|export| export["var"] == "HF_DATASETS_CACHE")
        .unwrap();
    assert_eq!(datasets["ecosystem"], "huggingface");
    assert_eq!(datasets["value"], "/scratch/x/huggingface/datasets");
    let xet = exports
        .iter()
        .find(|export| export["var"] == "HF_XET_CACHE")
        .unwrap();
    assert_eq!(xet["ecosystem"], "huggingface");
    assert_eq!(xet["value"], "/scratch/x/huggingface/xet");
    let modelscope = exports
        .iter()
        .find(|export| export["ecosystem"] == "modelscope")
        .unwrap();
    assert_eq!(modelscope["var"], "MODELSCOPE_CACHE");
    assert_eq!(modelscope["value"], "/scratch/x/modelscope");
    let wandb = exports
        .iter()
        .find(|export| export["ecosystem"] == "wandb")
        .unwrap();
    assert_eq!(wandb["var"], "WANDB_CACHE_DIR");
    assert_eq!(wandb["value"], "/scratch/x/wandb");
}

fn assert_relocation_refusals(report: &serde_json::Value) {
    let refusals = report["not_relocatable"].as_array().unwrap();
    let hf = refusals
        .iter()
        .find(|entry| entry["ecosystem"] == "huggingface")
        .unwrap();
    assert_eq!(hf["var"], "HF_HOME");
    assert_eq!(hf["reason"], HF_HOME_RELOCATION_REFUSAL_REASON);
    let cargo = refusals
        .iter()
        .find(|entry| entry["ecosystem"] == "cargo")
        .unwrap();
    assert_eq!(cargo["var"], "CARGO_HOME");
    assert_eq!(cargo["reason"], CARGO_HOME_RELOCATION_REFUSAL_REASON);
}

#[test]
fn relocate_json_reports_exports_and_current_roots() {
    let home = tempfile::tempdir().unwrap();
    let cache_home = tempfile::tempdir().unwrap();
    let uv_cache = cache_home.path().join("uv");
    std::fs::create_dir_all(&uv_cache).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", cache_home.path())
        .args(["relocate", "/scratch/x", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["target"], "/scratch/x");
    assert_relocation_exports(&report, &uv_cache);
    assert_relocation_refusals(&report);
}

#[test]
fn relocate_human_emits_shell_script_shape_without_stderr() {
    let home = tempfile::tempdir().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["relocate", "/scratch/x"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("DEGU_TARGET="));
    assert!(stdout.contains("mkdir -p \"/scratch/x/pip\" &&"));
    assert!(stdout.contains("export PIP_CACHE_DIR=\"/scratch/x/pip\""));
    assert!(
        stdout
            .lines()
            .filter(|line| line.trim_start().starts_with("export "))
            .all(|line| !line.ends_with(" &&"))
    );
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("export HF_HOME="))
    );
    assert!(stdout.contains(&format!(
        "# refused: HF_HOME — {HF_HOME_RELOCATION_REFUSAL_REASON}"
    )));
    assert!(stdout.contains(&format!(
        "# refused: CARGO_HOME — {CARGO_HOME_RELOCATION_REFUSAL_REASON}"
    )));
}

#[test]
fn relocate_script_keeps_external_paths_inside_comments() {
    let home = tempfile::tempdir().unwrap();
    let injected_name = "pip\u{9b}\\literal\r\u{1b}[31m\nexport DEGU_RELOCATE_INJECTED=1";
    let pip_cache = home.path().join(injected_name);
    std::fs::create_dir_all(&pip_cache).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path().join("cache");

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .args(["relocate", target.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\\\\literal\\r\\u{1b}[31m\\nexport DEGU_RELOCATE_INJECTED=1"));
    assert!(!stdout.contains('\r') && !stdout.contains('\u{1b}') && !stdout.contains('\u{9b}'));
    assert!(
        !stdout
            .lines()
            .any(|line| line == "export DEGU_RELOCATE_INJECTED=1")
    );

    let script = home.path().join("relocate.sh");
    std::fs::write(&script, stdout).unwrap();
    let sourced = std::process::Command::new("sh")
        .env_remove("DEGU_RELOCATE_INJECTED")
        .args([
            "-eu",
            "-c",
            ". \"$1\"; test \"${DEGU_RELOCATE_INJECTED-unset}\" = unset",
            "sh",
        ])
        .arg(&script)
        .status()
        .unwrap();
    assert!(sourced.success());
}

#[test]
fn relocate_script_stops_before_exports_when_a_directory_cannot_be_created() {
    let home = tempfile::tempdir().unwrap();
    let blocker = home.path().join("not-a-directory");
    std::fs::write(&blocker, b"fixture").unwrap();
    let target = blocker.join("cache");
    let script = generated_script(home.path(), &target);
    let sourced = std::process::Command::new("sh")
        .env_remove("PIP_CACHE_DIR")
        .args([
            "-u",
            "-c",
            ". \"$1\"; status=$?; [ \"${PIP_CACHE_DIR+set}\" != set ] || exit 99; exit \"$status\"",
            "sh",
        ])
        .arg(&script)
        .output()
        .unwrap();
    assert!(!sourced.status.success());
    assert_ne!(sourced.status.code(), Some(99));
}

fn sorted_entries(dir: &std::path::Path) -> Vec<String> {
    let mut entries: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    entries
}

#[test]
fn relocate_moves_nothing_and_lists_existing_data_in_human_script() {
    let home = tempfile::tempdir().unwrap();
    let bashrc = home.path().join(".bashrc");
    let bashrc_fixture = b"# fixture profile\n";
    std::fs::write(&bashrc, bashrc_fixture).unwrap();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip_cache).unwrap();
    let fixture_file = pip_cache.join("wheel.bin");
    std::fs::write(&fixture_file, b"fixture wheel bytes").unwrap();

    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path().join("degu-target");
    assert!(!target.exists());

    let home_entries_before = sorted_entries(home.path());
    let cache_entries_before = sorted_entries(&pip_cache);

    let human = degu()
        .env("HOME", home.path())
        .args(["relocate", target.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(human.status.success());

    let json = degu()
        .env("HOME", home.path())
        .args(["relocate", target.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());

    assert_eq!(sorted_entries(&pip_cache), cache_entries_before);
    assert_eq!(
        std::fs::read(&fixture_file).unwrap(),
        b"fixture wheel bytes"
    );
    assert!(!target.exists());
    assert_eq!(sorted_entries(home.path()), home_entries_before);
    assert_eq!(
        std::fs::read(&bashrc).unwrap(),
        bashrc_fixture,
        ".bashrc fixture must be byte-identical after both relocate invocations"
    );

    let stdout = String::from_utf8(human.stdout).unwrap();
    let existing_section = stdout
        .split("# existing data remains at the locations below; migrate manually if desired:")
        .nth(1)
        .unwrap();
    let canonical_pip_cache =
        crate::common::platform_cache_dir(&home.path().canonicalize().unwrap(), "pip");
    assert!(existing_section.contains(&format!("# pip: {}", canonical_pip_cache.display())));
}

#[test]
fn relocate_invalid_targets_fail_with_empty_stdout() {
    let home = tempfile::tempdir().unwrap();

    for json in [false, true] {
        let mut cmd = degu();
        cmd.env("HOME", home.path()).args(["relocate", "relative"]);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }

    let target = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/degu-invalid-\xff".to_vec(),
    ));
    for json in [false, true] {
        let mut cmd = degu();
        cmd.env("HOME", home.path()).arg("relocate").arg(&target);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("valid UTF-8")
        );
    }
}

#[test]
fn relocate_refuses_an_existing_file_target_before_printing_a_script() {
    let home = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path().join("scratch-file");
    std::fs::write(&target, b"fixture").unwrap();

    for json in [false, true] {
        let mut cmd = degu();
        cmd.env("HOME", home.path()).arg("relocate").arg(&target);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.contains(&format!(
                "relocate target {} exists and is not a directory",
                target.display()
            )),
            "{stderr}"
        );
        assert!(
            stderr.contains("choose a directory path or move the existing file, then rerun"),
            "{stderr}"
        );
    }
}

// The hub, datasets, and xet caches are three relocations of one ecosystem;
// the trailer must label each distinctly instead of printing one ambiguous
// "huggingface" line three times.
#[test]
fn relocate_trailer_labels_sibling_huggingface_caches_distinctly() {
    let home = tempfile::tempdir().unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["relocate", "/scratch/x"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let existing_section = stdout
        .split("# existing data remains at the locations below; migrate manually if desired:")
        .nth(1)
        .unwrap();
    for label in ["huggingface/hub", "huggingface/datasets", "huggingface/xet"] {
        assert!(
            existing_section.contains(&format!("# {label}: none found")),
            "missing {label:?}:\n{existing_section}"
        );
    }
    assert!(
        !existing_section
            .lines()
            .any(|line| line.starts_with("# huggingface:")),
        "ambiguous huggingface label survives:\n{existing_section}"
    );
}

// Each Hugging Face export must bind only its own root: hub, datasets, and xet
// are separate migrations, and a cross-listed current path would steer data
// into the wrong target.
#[test]
fn relocate_binds_each_huggingface_export_to_its_own_root() {
    let home = tempfile::tempdir().unwrap();
    let hub = tempfile::tempdir().unwrap();
    let datasets = tempfile::tempdir().unwrap();
    let xet = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        degu()
            .env("HOME", home.path())
            .env("HF_HUB_CACHE", hub.path())
            .env("HF_DATASETS_CACHE", datasets.path())
            .env("HF_XET_CACHE", xet.path())
            .args(args)
            .output()
            .unwrap()
    };

    let out = run(&["relocate", "--json", "/scratch/x"]);
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let exports = report["exports"].as_array().unwrap();
    for (var, dir) in [
        ("HF_HUB_CACHE", hub.path()),
        ("HF_DATASETS_CACHE", datasets.path()),
        ("HF_XET_CACHE", xet.path()),
    ] {
        let export = exports.iter().find(|e| e["var"] == var).unwrap();
        assert_eq!(
            export["current"],
            serde_json::json!([dir.to_string_lossy().to_string()]),
            "{var} must list exactly its own root"
        );
    }

    let out = run(&["relocate", "/scratch/x"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for (label, dir) in [
        ("huggingface/hub", hub.path()),
        ("huggingface/datasets", datasets.path()),
        ("huggingface/xet", xet.path()),
    ] {
        let path = dir.to_string_lossy();
        let lines: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains(path.as_ref()) && line.starts_with("# huggingface/"))
            .collect();
        assert_eq!(
            lines,
            vec![format!("# {label}: {path}").as_str()],
            "each root must appear once, under its own label"
        );
    }
}
