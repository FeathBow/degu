use super::support::*;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

struct ProjectRootFixture {
    home: tempfile::TempDir,
    config: tempfile::TempDir,
    state: tempfile::TempDir,
    root: std::path::PathBuf,
    target: String,
}

impl ProjectRootFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(config.path().join("degu")).unwrap();
        std::fs::write(
            config.path().join("degu/config.toml"),
            "roots = [\"~/projects\"]\n",
        )
        .unwrap();
        let root = home.path().join("projects");
        let project = root.join("app");
        let target = project.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        std::fs::write(target.join("artifact.bin"), [0u8; 1024]).unwrap();
        crate::common::make_tree_non_shared_writable(home.path()).unwrap();
        Self {
            target: canonical_path_string(&target),
            home,
            config,
            state,
            root,
        }
    }

    fn run(&self, root: bool) -> serde_json::Value {
        let mut command = degu();
        command
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.config.path())
            .env("XDG_STATE_HOME", self.state.path())
            .args(["clean", "--dry-run", "--json"]);
        if root {
            command.arg(&self.root);
        }
        let output = command.output().unwrap();
        assert!(output.status.success());
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[test]
fn configured_project_root_does_not_authorize_clean() {
    let fixture = ProjectRootFixture::new();
    let report = fixture.run(false);

    assert!(report["planned"].as_array().unwrap().is_empty());
}

#[test]
fn explicit_project_root_authorizes_clean_preview() {
    let fixture = ProjectRootFixture::new();
    let report = fixture.run(true);
    let planned = report["planned"].as_array().unwrap();

    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0]["ecosystem"], "artifacts");
    assert_eq!(planned[0]["path"], fixture.target);
}
