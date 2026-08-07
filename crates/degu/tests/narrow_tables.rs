#[allow(dead_code)]
#[path = "support/mod.rs"]
mod common;

use assert_cmd::Command;
use std::path::{Path, PathBuf};

const FIXTURE_FILE_BYTES: usize = 4096;

struct Fixture {
    _home: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    state: PathBuf,
    paths: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let config = temp.path().join("config");
        let state = temp.path().join("state");
        std::fs::create_dir_all(config.join("degu")).unwrap();
        std::fs::write(config.join("degu/config.toml"), "").unwrap();
        let mut paths = huggingface_paths(&home);
        paths.extend(conda_paths(&home));
        common::make_tree_non_shared_writable(&home).unwrap();
        Self {
            _home: temp,
            home,
            config,
            state,
            paths,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("degu").unwrap();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("LOGNAME", self._home.path())
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state);
        command
    }
}

#[test]
fn scan_pipe_is_deterministic_and_borderless() {
    let fixture = Fixture::new();

    let first = scan(&fixture, false);
    let second = scan(&fixture, false);

    assert_eq!(first, second);
    assert_borderless(&first);
    assert!(first.contains("checkpoint-alpha"));
    assert!(first.contains("checkpoint-beta"));
}

#[test]
fn clean_pipe_tables_are_borderless() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "clean",
            "--dry-run",
            "--include-review",
            "--only",
            "conda",
            "--only",
            "huggingface",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_borderless(&stdout);
    assert!(stdout.contains("Needs review (included by --include-review) - "));
    assert!(stdout.contains("Excluded:"));
}

#[test]
fn json_keeps_realistic_long_paths_exact() {
    let fixture = Fixture::new();
    let stdout = scan(&fixture, true);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let mut actual = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| PathBuf::from(finding["path"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let mut expected = fixture.paths;
    actual.sort();
    expected.sort();

    assert_eq!(actual, expected);
}

// The default view middle-truncates long paths, so only --details (which
// keeps full paths) can pin every escaped marker; the default view keeps the
// escaped basename tail and must never contain raw controls.
#[test]
fn scan_human_views_escape_terminal_control_paths() {
    let fixture = Fixture::new();
    let default = scan(&fixture, false);
    let details = scan_details(&fixture);

    assert_no_raw_controls(&default);
    assert!(default.contains("\\u{2029}txt"), "{default}");
    assert_escaped_controls(&details);
}

fn scan(fixture: &Fixture, json: bool) -> String {
    let mut command = fixture.command();
    command.args(["scan", "--only", "conda", "--only", "huggingface"]);
    if json {
        command.arg("--json");
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn scan_details(fixture: &Fixture) -> String {
    let output = fixture
        .command()
        .args([
            "scan",
            "--details",
            "--only",
            "conda",
            "--only",
            "huggingface",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn assert_borderless(output: &str) {
    assert!(
        !output.lines().any(is_rule),
        "unexpected table rule:\n{output}"
    );
}

fn is_rule(line: &str) -> bool {
    !line.is_empty() && line.chars().all(|character| matches!(character, '-' | '='))
}

fn assert_no_raw_controls(output: &str) {
    assert!(!output.contains("\u{1b}[2J"), "{output:?}");
    assert!(!output.contains('\t'), "{output:?}");
    assert!(!output.contains('\r'), "{output:?}");
    assert!(!output.contains('\u{202e}'), "{output:?}");
    for invisible in ['\u{200b}', '\u{2060}', '\u{feff}', '\u{2028}', '\u{2029}'] {
        assert!(!output.contains(invisible), "{output:?}");
    }
}

fn assert_escaped_controls(output: &str) {
    assert_no_raw_controls(output);
    let compact = output
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    for escaped in [
        "\\u{1b}[2J",
        "\\n",
        "\\r",
        "\\t",
        "\\\\literal",
        "\\u{202e}",
        "\\u{200b}",
        "\\u{2060}",
        "\\u{feff}",
        "\\u{2028}",
        "\\u{2029}",
    ] {
        assert!(compact.contains(escaped), "missing {escaped:?}:\n{output}");
    }
}

fn huggingface_paths(home: &Path) -> Vec<PathBuf> {
    [
        "models--meta-llama--Llama-3.3-70B-Instruct-experimental-checkpoint-alpha",
        "models--meta-llama--Llama-3.3-70B-Instruct-experimental-checkpoint-beta",
        "models--escape-\u{1b}[2J-newline-\n-carriage-\r-tab-\t-backslash-\\literal-bidi-\u{202e}-zero-\u{200b}-joiner-\u{2060}-bom-\u{feff}-line-\u{2028}-paragraph-\u{2029}txt",
    ]
    .into_iter()
    .map(|name| {
        let path = home.join(".cache/huggingface/hub").join(name);
        let snapshot = path.join("snapshots/main");
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::write(
            snapshot.join("model.safetensors"),
            [0_u8; FIXTURE_FILE_BYTES],
        )
        .unwrap();
        std::fs::canonicalize(path).unwrap()
    })
    .collect()
}

fn conda_paths(home: &Path) -> Vec<PathBuf> {
    [
        "llm-finetuning-cuda-12-4-pytorch-2-6-production-alpha",
        "llm-finetuning-cuda-12-4-pytorch-2-6-production-beta",
    ]
    .into_iter()
    .map(|name| {
        let path = home.join(".conda/envs").join(name);
        std::fs::create_dir_all(path.join("conda-meta")).unwrap();
        std::fs::write(path.join("conda-meta/history"), "# conda history\n").unwrap();
        std::fs::canonicalize(path).unwrap()
    })
    .collect()
}

// Piped table cells never wrap or truncate: a path wider than any assumed
// terminal width survives whole on a single line.
#[test]
fn piped_scan_emits_full_long_paths_on_single_lines() {
    let fixture = Fixture::new();
    let name = format!("models--org--{}", "long-segment-".repeat(10));
    let snapshot = fixture
        .home
        .join(".cache/huggingface/hub")
        .join(&name)
        .join("snapshots/main");
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(
        snapshot.join("model.safetensors"),
        [0_u8; FIXTURE_FILE_BYTES],
    )
    .unwrap();

    let stdout = scan(&fixture, false);

    let display = format!("~/.cache/huggingface/hub/{name}");
    assert!(
        stdout.lines().any(|line| line.contains(&display)),
        "full path must survive piping on one line:\n{stdout}"
    );
    assert!(
        !stdout.contains("..."),
        "piped cells must not truncate:\n{stdout}"
    );
}
