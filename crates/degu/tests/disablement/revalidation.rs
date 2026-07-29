use crate::pty::{PtyRun, run as run_pty};
use std::os::unix::fs::symlink;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

struct Fixture {
    home: tempfile::TempDir,
    config: tempfile::TempDir,
    state: tempfile::TempDir,
    root: tempfile::TempDir,
    uv_alias: std::path::PathBuf,
    target: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let uv_cache = root.path().join("initial-uv-cache");
        let uv_alias = root.path().join("uv-alias");
        let target = root.path().join("project/target");
        std::fs::create_dir_all(config.path().join("degu")).unwrap();
        std::fs::write(
            config.path().join("degu/config.toml"),
            "disable = [\"uv\"]\n",
        )
        .unwrap();
        tagged_cache(&uv_cache);
        eligible_cargo_target(&target);
        symlink(&uv_cache, &uv_alias).unwrap();
        Self {
            home,
            config,
            state,
            root,
            uv_alias,
            target,
        }
    }

    fn run(&self) -> std::process::Output {
        let body = r#"
spawn $env(DEGU_BIN) clean $env(SCAN_ROOT)
expect -exact {Proceed? [y/N] }
file delete $env(UV_ALIAS)
file link -symbolic $env(UV_ALIAS) $env(PLANNED_TARGET)
send "y\r"
"#;
        let scan_root = self.root.path().join("project");
        let extra_env = [
            ("UV_CACHE_DIR", self.uv_alias.as_os_str()),
            ("SCAN_ROOT", scan_root.as_os_str()),
            ("PLANNED_TARGET", self.target.as_os_str()),
            ("UV_ALIAS", self.uv_alias.as_os_str()),
        ];
        run_pty(PtyRun {
            body,
            home: self.home.path(),
            config_home: self.config.path(),
            state_home: self.state.path(),
            extra_env: &extra_env,
        })
    }
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

#[test]
fn clean_revalidates_disabled_roots_after_confirmation() {
    let fixture = Fixture::new();
    let output = fixture.run();
    let transcript = String::from_utf8(output.stdout).unwrap();

    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("clean plan is no longer safe"),
        "{transcript}"
    );
    assert!(fixture.target.exists());
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!fixture.state.path().join("degu/ops.jsonl").exists());
}
