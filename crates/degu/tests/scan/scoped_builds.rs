use super::support::*;

#[test]
fn scan_json_reports_scoped_build_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let cargo_project = root.path().join("proj");
    std::fs::create_dir_all(cargo_project.join("target")).unwrap();
    std::fs::write(cargo_project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        cargo_project.join("target/CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(cargo_project.join("target/.rustc_info.json"), "{}").unwrap();
    std::fs::write(cargo_project.join("target/debug.bin"), [0u8; 1024]).unwrap();

    let web_project = root.path().join("web");
    std::fs::create_dir_all(web_project.join("node_modules")).unwrap();
    std::fs::write(
        web_project.join("package.json"),
        r#"{"name":"web","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        web_project.join("package-lock.json"),
        r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web","version":"1.0.0"}}}"#,
    )
    .unwrap();
    std::fs::write(web_project.join("node_modules/lib.js"), [0u8; 1024]).unwrap();

    let py_project = root.path().join("py");
    std::fs::create_dir_all(py_project.join("__pycache__")).unwrap();
    std::fs::write(py_project.join("__pycache__/mod.pyc"), [0u8; 1024]).unwrap();

    let decoy = root.path().join("decoy");
    std::fs::create_dir_all(decoy.join("target")).unwrap();
    std::fs::write(decoy.join("target/x.bin"), [0u8; 1024]).unwrap();

    let cargo_decoy = root.path().join("cargo-decoy");
    std::fs::create_dir_all(cargo_decoy.join("target")).unwrap();
    std::fs::write(cargo_decoy.join("Cargo.toml"), "").unwrap();
    std::fs::write(cargo_decoy.join("target/x.bin"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(root.path())
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert!(
        arr.iter()
            .all(|finding| finding["ecosystem"] == "artifacts")
    );
    assert!(
        arr.iter()
            .all(|finding| finding["kind"] == "build_artifact")
    );
    assert!(
        arr.iter()
            .all(|finding| !finding["path"].as_str().unwrap().contains("decoy"))
    );
}

#[test]
fn scan_json_reports_untagged_cargo_target_root_once() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    // The a3f899c field case: a reused target directory whose ROOT carries no
    // valid CACHEDIR.TAG, only a real manifest, a build marker, and
    // valid-signature CHILD tags under cross-target directories. A child tag
    // declares only its own subtree, so the untagged root is surfaced as
    // report-only (never eligible) and its user data is never auto-cleaned.
    let project = root.join("proj");
    let target = project.join("target");
    std::fs::create_dir_all(target.join("debug")).unwrap();
    std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("debug/.cargo-lock"), "").unwrap();
    std::fs::write(target.join("debug/payload.bin"), [0u8; 4096]).unwrap();

    let cross_targets = [
        target.join("aarch64-unknown-linux-musl"),
        target.join("x86_64-unknown-linux-musl"),
    ];
    for cross in &cross_targets {
        std::fs::create_dir_all(cross.join("release")).unwrap();
        std::fs::write(
            cross.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        std::fs::write(cross.join("release/payload.bin"), [0u8; 1024]).unwrap();
    }

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(&root)
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "other");
    assert_eq!(arr[0]["recovery"]["kind"], "unknown");
    assert_eq!(arr[0]["ownership"], "unknown");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], target.display().to_string());
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 4096 + 2 * 1024);
    assert!(
        arr.iter()
            .all(|finding| !finding["path"].as_str().unwrap().contains("musl"))
    );
}

#[test]
fn tagged_target_without_cargo_evidence_is_report_only_and_never_planned() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    // The field repro: a directory named `target` carrying a valid generic
    // CACHEDIR.TAG but NO Cargo manifest and NO build marker, holding an
    // ordinary user file. The tag proves "this is cache storage", not
    // "this is regenerable cargo output", so the root falls through to the
    // generic cache-tag tier: report-only (`kind:"other"`, recovery unknown),
    // never build-artifact eligible, and its user data is never auto-cleaned.
    let target = root.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join("important.db"), [0u8; 4096]).unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = scan_findings(&scan.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "other");
    assert_eq!(arr[0]["recovery"]["kind"], "unknown");
    assert_eq!(arr[0]["ownership"], "unknown");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], target.display().to_string());

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--include-review", "--json"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert!(
        report["planned"].as_array().unwrap().is_empty(),
        "a non-cargo tagged target must never be planned: {report}"
    );
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(target.join("important.db").exists());
}

#[test]
fn untagged_cargo_target_is_report_only_and_never_planned() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    // A live decoy: a mis-named target holding user data behind an unparseable
    // manifest, a build marker, and no valid tag. It must never be eligible.
    let decoy = root.join("decoy");
    let decoy_target = decoy.join("target");
    std::fs::create_dir_all(&decoy_target).unwrap();
    std::fs::write(decoy.join("Cargo.toml"), "this is not = valid = toml").unwrap();
    std::fs::write(decoy_target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(decoy_target.join("important.db"), [0u8; 4096]).unwrap();

    // The a3f899c field case: a reused target with a real manifest, a build
    // marker, no valid ROOT tag, and a valid-signature CHILD tag. The root is
    // surfaced as report-only so its user data is never auto-cleaned.
    let reused = root.join("reused");
    let reused_target = reused.join("target");
    std::fs::create_dir_all(reused_target.join("x86_64-unknown-linux-musl")).unwrap();
    std::fs::write(reused.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(reused_target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(reused_target.join("important.db"), [0u8; 4096]).unwrap();
    std::fs::write(
        reused_target.join("x86_64-unknown-linux-musl/CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();

    let scan = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "artifacts", "--json"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(scan.status.success());
    let findings = scan_findings(&scan.stdout);
    let arr = findings.as_array().unwrap();
    let reused_finding = arr
        .iter()
        .find(|finding| finding["path"] == reused_target.display().to_string())
        .expect("the untagged reused root must be surfaced");
    assert_eq!(reused_finding["kind"], "other");
    assert_eq!(reused_finding["disposition"]["mode"], "report_only");
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != decoy_target.display().to_string()),
        "the unparseable-manifest decoy must not be surfaced: {findings}"
    );

    let clean = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--include-review", "--json"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert!(
        report["planned"].as_array().unwrap().is_empty(),
        "no untagged target may be planned: {report}"
    );
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(decoy_target.join("important.db").exists());
    assert!(reused_target.join("important.db").exists());
}

fn seed_unknown_cachedir_roots(
    root: &std::path::Path,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let tagged = root.join("standalone-cache");
    std::fs::create_dir_all(&tagged).unwrap();
    std::fs::write(
        tagged.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\nmetadata follows\n"),
    )
    .unwrap();
    std::fs::write(tagged.join("payload.bin"), [0u8; 1024]).unwrap();

    let wrong = root.join("wrong-tag");
    std::fs::create_dir_all(&wrong).unwrap();
    std::fs::write(wrong.join("CACHEDIR.TAG"), "Signature: wrong\n").unwrap();
    std::fs::write(wrong.join("payload.bin"), [0u8; 1024]).unwrap();

    let empty = root.join("empty-tag");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::write(empty.join("CACHEDIR.TAG"), "").unwrap();
    std::fs::write(empty.join("payload.bin"), [0u8; 1024]).unwrap();

    let venv = root.join("venv");
    std::fs::create_dir_all(&venv).unwrap();
    std::fs::write(
        venv.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(venv.join("pyvenv.cfg"), "").unwrap();
    std::fs::write(venv.join("payload.bin"), [0u8; 1024]).unwrap();
    (tagged, wrong, empty, venv)
}

#[test]
fn scan_json_reports_unknown_cachedir_tag_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let (tagged, wrong, empty, venv) = seed_unknown_cachedir_roots(&root);
    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(&root)
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "other");
    assert_eq!(arr[0]["recovery"]["kind"], "unknown");
    assert_eq!(arr[0]["ownership"], "unknown");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert!(arr[0]["disposition"]["reason"].is_string());
    assert_eq!(arr[0]["path"], tagged.display().to_string());
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != wrong.display().to_string())
    );
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != empty.display().to_string())
    );
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != venv.display().to_string())
    );
}

#[test]
fn explicit_root_scan_points_unmanaged_artifacts_at_details() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    seed_unknown_cachedir_roots(&root);
    let hint = "Rerun with --details for each Not managed location's full reason.";

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(hint), "stdout: {stdout}");

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--details"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(hint), "stdout: {stdout}");
}

#[test]
fn scan_json_reports_cmake_build_tree_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("CMakeLists.txt"), "").unwrap();

    let build = root.join("build");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(
        build.join("CMakeCache.txt"),
        format!("CMAKE_HOME_DIRECTORY:INTERNAL={}\n", src.display()),
    )
    .unwrap();
    std::fs::write(build.join("artifact.o"), [0u8; 1024]).unwrap();

    let in_source = root.join("in-source");
    std::fs::create_dir_all(&in_source).unwrap();
    std::fs::write(in_source.join("CMakeLists.txt"), "").unwrap();
    std::fs::write(
        in_source.join("CMakeCache.txt"),
        format!("CMAKE_HOME_DIRECTORY:INTERNAL={}\n", in_source.display()),
    )
    .unwrap();
    std::fs::write(in_source.join("artifact.o"), [0u8; 1024]).unwrap();
    crate::common::make_tree_non_shared_writable(&root).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(&root)
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "build_artifact");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert_eq!(arr[0]["path"], build.display().to_string());
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != in_source.display().to_string())
    );
}

#[test]
fn scan_json_reports_legacy_tox_as_report_only() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();

    let tox = root.join("good/.tox");
    let tox_env = tox.join("py311");
    std::fs::create_dir_all(&tox_env).unwrap();
    std::fs::write(
        tox_env.join(".tox-info.json"),
        r#"{"tox_version":"4.11.0"}"#,
    )
    .unwrap();
    std::fs::write(tox_env.join("payload.bin"), [0u8; 1024]).unwrap();

    let decoy = root.join("bad/.tox");
    std::fs::create_dir_all(decoy.join("py311")).unwrap();
    std::fs::write(decoy.join("py311/payload.bin"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(&root)
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "other");
    assert_eq!(arr[0]["recovery"]["kind"], "unknown");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(arr[0]["path"], tox.display().to_string());
    assert!(
        arr.iter()
            .all(|finding| finding["path"] != decoy.display().to_string())
    );
}

#[test]
fn scan_json_uses_configured_project_roots_for_build_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config_home.path().join("degu")).unwrap();
    std::fs::write(
        config_home.path().join("degu/config.toml"),
        "roots = [\"~/projects\"]\n",
    )
    .unwrap();

    let target = home.path().join("projects/app/target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.parent().unwrap().join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        target.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
    std::fs::write(target.join("debug.bin"), [0u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "artifacts");
    assert_eq!(arr[0]["kind"], "build_artifact");
    assert!(arr[0]["path"].as_str().unwrap().ends_with("app/target"));
}

fn seed_web_project(
    root: &std::path::Path,
    name: &str,
    manifest: &str,
    lockfiles: &[(&str, &str)],
) -> std::path::PathBuf {
    let project = root.join(name);
    std::fs::create_dir_all(project.join("node_modules")).unwrap();
    std::fs::write(project.join("node_modules/irreplaceable"), [0u8; 4096]).unwrap();
    std::fs::write(project.join("package.json"), manifest).unwrap();
    for (lockfile, contents) in lockfiles {
        std::fs::write(project.join(lockfile), contents).unwrap();
    }
    project.join("node_modules").canonicalize().unwrap()
}

fn disposition_mode<'a>(
    findings: &'a [serde_json::Value],
    node_modules: &std::path::Path,
) -> Option<&'a str> {
    findings
        .iter()
        .find(|finding| finding["path"].as_str() == node_modules.to_str())
        .and_then(|finding| finding["disposition"]["mode"].as_str())
}

// End-to-end: a node_modules reaches the eligible disposition only with a
// schema-valid lockfile that names this project. Unknown versions and an
// authoritative-but-broken shrinkwrap must degrade to report-only, never eligible.
#[test]
fn node_modules_reaches_eligible_only_with_a_valid_lockfile() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let eligible = seed_web_project(
        root.path(),
        "good",
        r#"{"name":"good","version":"1.0.0"}"#,
        &[(
            "package-lock.json",
            r#"{"name":"good","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"good","version":"1.0.0"}}}"#,
        )],
    );
    let unknown_version = seed_web_project(
        root.path(),
        "unknown",
        r#"{"name":"unknown"}"#,
        &[(
            "package-lock.json",
            r#"{"name":"unknown","lockfileVersion":999,"packages":{"":{}}}"#,
        )],
    );
    let masked_by_broken_shrinkwrap = seed_web_project(
        root.path(),
        "masked",
        r#"{"name":"masked"}"#,
        &[
            (
                "package-lock.json",
                r#"{"name":"masked","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"masked","version":"1.0.0"}}}"#,
            ),
            ("npm-shrinkwrap.json", r#"{"broken":true}"#),
        ],
    );
    let wrong_typed_descriptor = seed_web_project(
        root.path(),
        "typed",
        r#"{"name":"typed","version":"1.0.0"}"#,
        &[(
            "package-lock.json",
            r#"{"name":"typed","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"typed","version":"1.0.0"},"node_modules/x":{"version":7}}}"#,
        )],
    );
    let malformed_manifest = seed_web_project(
        root.path(),
        "badman",
        r#"{"name":"badman","version":"1.0.0","dependencies":{"x":7}}"#,
        &[(
            "package-lock.json",
            r#"{"name":"badman","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"badman","version":"1.0.0"}}}"#,
        )],
    );
    // Manifest omits identity; the v1 lock top level carries wrong-typed identity.
    let v1_wrong_identity = seed_web_project(
        root.path(),
        "v1bad",
        "{}",
        &[(
            "package-lock.json",
            r#"{"name":7,"version":false,"lockfileVersion":1,"requires":true,"dependencies":{"x":{"version":"1.0.0"}}}"#,
        )],
    );
    crate::common::make_tree_non_shared_writable(root.path()).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(root.path())
        .arg("--json")
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();

    assert_eq!(
        disposition_mode(arr, &eligible),
        Some("eligible"),
        "{findings}"
    );
    assert_ne!(
        disposition_mode(arr, &unknown_version),
        Some("eligible"),
        "unknown lockfileVersion must not be eligible: {findings}"
    );
    assert_ne!(
        disposition_mode(arr, &masked_by_broken_shrinkwrap),
        Some("eligible"),
        "a broken authoritative shrinkwrap must not be eligible: {findings}"
    );
    assert_ne!(
        disposition_mode(arr, &wrong_typed_descriptor),
        Some("eligible"),
        "a wrong-typed package descriptor must not be eligible: {findings}"
    );
    assert_ne!(
        disposition_mode(arr, &malformed_manifest),
        Some("eligible"),
        "a malformed package.json must not be eligible: {findings}"
    );
    assert_ne!(
        disposition_mode(arr, &v1_wrong_identity),
        Some("eligible"),
        "a v1 lock with wrong-typed top-level identity must not be eligible: {findings}"
    );
}
