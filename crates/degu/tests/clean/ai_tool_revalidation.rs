use crate::pty::{PtyRun, run as run_pty};

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

struct Fixture {
    home: tempfile::TempDir,
    config: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
    target: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let target = project.path().join("target");
        std::fs::create_dir_all(config.path().join("degu")).unwrap();
        std::fs::write(config.path().join("degu/config.toml"), "").unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(project.path().join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        std::fs::write(target.join("artifact.o"), [0_u8; 4096]).unwrap();
        crate::common::make_tree_non_shared_writable(project.path()).unwrap();
        Self {
            home,
            config,
            state,
            project,
            target,
        }
    }

    fn run(&self) -> std::process::Output {
        let body = r#"
spawn $env(DEGU_BIN) clean $env(SCAN_ROOT)
expect -exact {Proceed? [y/N] }
file link -symbolic $env(AI_ALIAS) $env(PLANNED_TARGET)
send "y\r"
"#;
        let ai_alias = self.home.path().join(".claude");
        let extra_env = [
            ("SCAN_ROOT", self.project.path().as_os_str()),
            ("PLANNED_TARGET", self.target.as_os_str()),
            ("AI_ALIAS", ai_alias.as_os_str()),
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

#[test]
fn ai_tool_symlink_created_during_confirmation_invalidates_the_plan() {
    let fixture = Fixture::new();
    let output = fixture.run();
    let transcript = String::from_utf8(output.stdout).unwrap();

    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("overlaps protected path"),
        "{transcript}"
    );
    assert!(fixture.target.exists());
    assert!(fixture.home.path().join(".claude").is_symlink());
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!fixture.state.path().join("degu/ops.jsonl").exists());
}
