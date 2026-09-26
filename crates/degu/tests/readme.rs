//! Documentation contracts for the primary user journeys.

use assert_cmd::Command;

#[path = "support/mod.rs"]
mod common;
#[path = "readme/configuration.rs"]
mod configuration;
#[path = "readme/installation.rs"]
mod installation;

const README: &str = include_str!("../../../README.md");
const USAGE: &str = include_str!("../../../docs/usage.md");
const SAFETY: &str = include_str!("../../../docs/safety.md");
const MIB: usize = 1024 * 1024;

#[test]
fn readme_scan_demo_matches_real_cli_output() {
    let demo = fenced_blocks(README, "console")
        .into_iter()
        .find_map(|block| block.strip_prefix("$ degu scan\n"))
        .expect("missing README scan demo");
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    // Ready to clean: a pip cache under the well-known base is eligible.
    let pip = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip).unwrap();
    std::fs::write(pip.join("wheel-cache.bin"), vec![b'x'; 6 * MIB]).unwrap();

    // Needs review: a HuggingFace hub model is regenerable but costly.
    let model = home
        .path()
        .join(".cache/huggingface/hub/models--bert--base/blobs");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(model.join("model.bin"), vec![b'x'; 12 * MIB]).unwrap();

    // Not managed: a uv cache is tool-coordinated and reported only.
    let uv = home.path().join(".cache/uv");
    std::fs::create_dir_all(&uv).unwrap();
    std::fs::write(uv.join("cache.bin"), vec![b'x'; 4 * MIB]).unwrap();

    crate::common::make_tree_non_shared_writable(home.path()).unwrap();

    let output = common::isolated_degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["--color", "never", "scan"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The README documents the XDG pip path; on macOS the CLI renders the
    // platform default, so normalize just that one path for the comparison.
    #[cfg(target_os = "macos")]
    let stdout = stdout.replace("~/Library/Caches/pip", "~/.cache/pip");
    assert_eq!(stdout.trim(), demo.trim());
}

#[test]
fn cli_examples_in_readme_and_usage_parse_against_the_real_cli() {
    for (name, document) in [("README.md", README), ("docs/usage.md", USAGE)] {
        let examples = cli_examples(document);
        assert!(
            !examples.is_empty(),
            "extracted no CLI examples from {name}"
        );
        for args in examples {
            assert_cli_help(&args);
        }
    }
}

/// Every subcommand the binary offers is named somewhere a reader can find it.
///
/// `degu ops` once shipped documented only in files that never enter git. The
/// command list is read back from the binary rather than restated here, so a new
/// subcommand cannot be added without this failing until it is documented.
#[test]
fn every_subcommand_is_named_in_the_published_docs() {
    let help = Command::cargo_bin("degu")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(help).expect("help is text");
    let commands = subcommands(&help);
    assert!(
        commands.len() >= 10,
        "read {commands:?} out of the command list"
    );

    let documents = [
        README,
        USAGE,
        SAFETY,
        installation::INSTALLATION,
        configuration::CONFIGURATION,
    ];
    for command in commands {
        let named = format!("degu {command}");
        assert!(
            documents.iter().any(|document| document.contains(&named)),
            "no published document names `{named}`"
        );
    }
}

/// The names in `--help`, which indents each one by exactly two spaces and
/// separates it from its summary by two more. Group headings carry no
/// indentation and wrapped summaries carry more, so both fall out.
fn subcommands(help: &str) -> Vec<&str> {
    help.split("\nOptions:")
        .next()
        .expect("help lists its options")
        .lines()
        .filter_map(|line| line.strip_prefix("  ")?.split_once("  "))
        .map(|(name, _)| name)
        .filter(|name| !name.is_empty() && !name.starts_with(' ') && *name != "help")
        .collect()
}

fn assert_cli_help(args: &[String]) {
    let (bin, rest) = args.split_first().unwrap();
    Command::cargo_bin(bin)
        .unwrap()
        .args(rest)
        .arg("--help")
        .assert()
        .success();
}

fn fenced_blocks<'a>(document: &'a str, language: &str) -> Vec<&'a str> {
    let opening = format!("```{language}\n");
    document
        .split(&opening)
        .skip(1)
        .filter_map(|remainder| remainder.split_once("\n```").map(|(block, _)| block))
        .collect()
}

fn cli_examples(document: &str) -> Vec<Vec<String>> {
    fenced_blocks(document, "sh")
        .into_iter()
        .flat_map(str::lines)
        .filter_map(parse_cli_line)
        .collect()
}

fn parse_cli_line(line: &str) -> Option<Vec<String>> {
    let line = line.trim().strip_prefix("$ ").unwrap_or(line.trim());
    if !line.starts_with("degu ") && !line.starts_with("dg ") {
        return None;
    }
    let command = line.split('#').next().unwrap();
    let command = command.split(['|', '>']).next().unwrap();
    Some(command.split_whitespace().map(documented_arg).collect())
}

fn documented_arg(arg: &str) -> String {
    arg.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(arg)
        .to_owned()
}
