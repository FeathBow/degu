use assert_cmd::Command;

#[path = "disablement/adapter_boundaries.rs"]
mod adapter_boundaries;
#[allow(dead_code)]
#[path = "support/mod.rs"]
mod common;
#[path = "support/pty.rs"]
mod pty;
#[path = "disablement/revalidation.rs"]
mod revalidation;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";
const VALID_ADAPTER_IDS: &str = "apptainer, cargo, ccache, computecache, conda, docker, go-build, helm, huggingface, inductor, jax, npm, ollama, orbstack, pip, pixi, podman, sccache, shm, spack, tmp, torch, torchext, triton, uv, vllm, vscode";

fn degu(home: &std::path::Path, config: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("degu").unwrap();
    cmd.env_clear()
        .env("HOME", home)
        .env("LOGNAME", home)
        .env("XDG_CONFIG_HOME", config);
    cmd
}

fn config_home(disabled: &[&str]) -> tempfile::TempDir {
    let config = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config.path().join("degu")).unwrap();
    let ids = disabled
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        config.path().join("degu/config.toml"),
        format!("disable = [{ids}]\n"),
    )
    .unwrap();
    config
}

fn tagged_cache(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(
        path.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(path.join("payload.bin"), [0_u8; 4096]).unwrap();
}

// A directory named `target` earns build-artifact eligibility only with cargo
// evidence: a sibling `[package]` manifest and a build marker beside the tag.
fn eligible_cargo_target(target: &std::path::Path) {
    tagged_cache(target);
    std::fs::write(target.parent().unwrap().join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
}

fn json_stdout(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn invalid_disable_ids_fail_before_discovery() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["pipp", "uvv"]);
    let missing_root = home.path().join("must-not-be-discovered");
    let commands: [&[&str]; 3] = [
        &["scan", "--json"],
        &["scan", "--summary", "--json"],
        &["clean", "--dry-run", "--json"],
    ];

    for args in commands {
        let out = degu(home.path(), config.path())
            .args(args)
            .arg(&missing_root)
            .output()
            .unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        assert!(out.stdout.is_empty());
        assert!(stderr.contains("pipp") && stderr.contains("uvv"));
        assert!(stderr.contains(&format!("valid adapter ids: {VALID_ADAPTER_IDS}")));
        assert!(!stderr.contains(&missing_root.display().to_string()));
    }
}

#[test]
fn project_source_ids_are_not_configurable_adapters() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["artifacts", "checkpoints"]);
    let out = degu(home.path(), config.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("artifacts") && stderr.contains("checkpoints"));
    assert!(stderr.contains(&format!("valid adapter ids: {VALID_ADAPTER_IDS}")));
}

#[test]
fn only_rejects_sources_disabled_by_configuration() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["pip", "tmp"]);
    let cases: [(&[&str], &str); 3] = [
        (&["scan", "--only", "pip", "--json"], "pip"),
        (&["clean", "--only", "pip", "--dry-run", "--json"], "pip"),
        (&["scan", "--runtime", "--only", "tmp", "--json"], "tmp"),
    ];

    for (args, source) in cases {
        let out = degu(home.path(), config.path())
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        assert!(out.stdout.is_empty());
        assert!(stderr.contains(&format!("source \"{source}\" is disabled")));
    }
}

struct DisabledFixture {
    home: tempfile::TempDir,
    config: tempfile::TempDir,
    state: tempfile::TempDir,
    scan_root: std::path::PathBuf,
    uv_cache: std::path::PathBuf,
    ccache: std::path::PathBuf,
}

impl DisabledFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let scan_root = home.path().join("project-caches");
        let uv_cache = scan_root.join("uv-cache");
        let tagged_ancestor = scan_root.join("compiler-caches");
        let ccache = tagged_ancestor.join("ccache");
        tagged_cache(&uv_cache);
        tagged_cache(&tagged_ancestor);
        eligible_cargo_target(&scan_root.join("project/target"));
        std::fs::write(tagged_ancestor.join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(tagged_ancestor.join("node_modules")).unwrap();
        std::fs::write(tagged_ancestor.join("node_modules/module.js"), [0_u8; 4096]).unwrap();
        std::fs::create_dir_all(&ccache).unwrap();
        std::fs::write(ccache.join("object.o"), [0_u8; 4096]).unwrap();
        common::make_tree_non_shared_writable(home.path()).unwrap();
        Self {
            home,
            config: config_home(&["uv", "ccache"]),
            state: tempfile::tempdir().unwrap(),
            scan_root,
            uv_cache,
            ccache,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = degu(self.home.path(), self.config.path());
        cmd.env("XDG_STATE_HOME", self.state.path())
            .env("UV_CACHE_DIR", &self.uv_cache)
            .env("CCACHE_DIR", &self.ccache);
        cmd
    }
}

#[test]
fn disabled_roots_and_claiming_ancestors_are_not_rediscovered() {
    let fixture = DisabledFixture::new();
    let target = std::fs::canonicalize(fixture.scan_root.join("project/target")).unwrap();
    let scan = fixture
        .command()
        .args(["scan", "--json"])
        .arg(&fixture.scan_root)
        .output()
        .unwrap();
    assert!(scan.status.success());
    let findings = json_stdout(&scan)["findings"].as_array().unwrap().clone();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["path"], target.display().to_string());

    let clean = fixture
        .command()
        .args(["clean", "--yes", "--include-review", "--json"])
        .arg(&fixture.scan_root)
        .output()
        .unwrap();
    assert!(clean.status.success());
    let report = json_stdout(&clean);
    let planned = report["planned"].as_array().unwrap();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0]["path"], target.display().to_string());
    assert!(report["excluded"].as_array().unwrap().is_empty());
    assert!(fixture.uv_cache.exists() && fixture.ccache.exists());
    assert!(!target.exists());
}

#[test]
fn unknown_tagged_cache_is_report_only_and_never_planned() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&[]);
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("unknown-cache");
    tagged_cache(&cache);
    std::fs::write(cache.join("package.json"), "{}").unwrap();
    std::fs::create_dir_all(cache.join("node_modules")).unwrap();
    std::fs::write(cache.join("node_modules/module.js"), [0_u8; 4096]).unwrap();
    let canonical_cache = cache.canonicalize().unwrap();

    let scan = degu(home.path(), config.path())
        .args(["scan", "--json"])
        .arg(&cache)
        .output()
        .unwrap();
    assert!(scan.status.success());
    let findings = json_stdout(&scan)["findings"].as_array().unwrap().clone();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["path"], canonical_cache.display().to_string());
    assert_eq!(findings[0]["kind"], "other");
    assert_eq!(findings[0]["recovery"]["kind"], "unknown");
    assert_eq!(findings[0]["ownership"], "unknown");
    assert_eq!(findings[0]["disposition"]["mode"], "report_only");

    let clean = degu(home.path(), config.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--dry-run", "--include-review", "--json"])
        .arg(root.path())
        .arg(cache.join("node_modules"))
        .output()
        .unwrap();
    assert!(clean.status.success());
    let report = json_stdout(&clean);
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
    assert!(canonical_cache.exists());
}

#[test]
fn disabled_root_cannot_be_reclassified_by_another_adapter() {
    let home = tempfile::tempdir().unwrap();
    let config = config_home(&["uv"]);
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared-cache");
    let real = root.path().join("real");
    let target = real.join("target");
    let ccache = real.join("container");
    let uv_alias = root.path().join("alias/../container/uv-cache");
    let pip_child = shared.join("pip-cache");
    tagged_cache(&shared);
    tagged_cache(&target);
    tagged_cache(&ccache);
    tagged_cache(&pip_child);
    std::os::unix::fs::symlink(&target, root.path().join("alias")).unwrap();
    std::os::unix::fs::symlink(&shared, ccache.join("uv-cache")).unwrap();

    let command = || {
        let mut cmd = degu(home.path(), config.path());
        cmd.env("XDG_STATE_HOME", state.path())
            .env("UV_CACHE_DIR", &uv_alias)
            .env("PIP_CACHE_DIR", &pip_child)
            .env("CCACHE_DIR", &ccache);
        cmd
    };
    let scan = command()
        .args(["scan", "--only", "pip", "--json"])
        .output()
        .unwrap();
    assert!(scan.status.success());
    let report = json_stdout(&scan);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["completeness"]["findings"], "incomplete");

    let clean = command()
        .args(["clean", "--only", "pip", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(clean.status.success());
    let stderr = String::from_utf8_lossy(&clean.stderr);
    assert!(
        stderr.contains("finding overlaps an excluded adapter root"),
        "{stderr}"
    );
    let report = json_stdout(&clean);
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert!(shared.exists() && pip_child.exists() && ccache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}
