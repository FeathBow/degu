use assert_cmd::Command;
use std::process::Output;

const JSON: &str = "--json";
const BUDGET: &str = "--budget";
const MAX_CONCURRENCY: &str = "--max-concurrency";

#[derive(Clone, Copy)]
struct HelpCase {
    args: &'static [&'static str],
    json: bool,
    scan_controls: bool,
}

impl HelpCase {
    const fn new(args: &'static [&'static str], json: bool, scan_controls: bool) -> Self {
        Self {
            args,
            json,
            scan_controls,
        }
    }
}

const HELP_CASES: &[HelpCase] = &[
    HelpCase::new(&["--help"], false, false),
    HelpCase::new(&["completions", "--help"], false, false),
    HelpCase::new(&["man", "--help"], false, false),
];

const UNSUPPORTED_CASES: &[(&[&str], &str)] = &[
    (&["completions", "bash", JSON], JSON),
    (&["completions", "bash", BUDGET, "1s"], BUDGET),
    (
        &["completions", "bash", MAX_CONCURRENCY, "1"],
        MAX_CONCURRENCY,
    ),
    (&["man", JSON], JSON),
    (&["man", BUDGET, "1s"], BUDGET),
    (&["man", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
];

#[derive(Clone, Copy)]
struct CompletionCase {
    condition: &'static str,
    json: bool,
    scan_controls: bool,
}

impl CompletionCase {
    const fn new(condition: &'static str, json: bool, scan_controls: bool) -> Self {
        Self {
            condition,
            json,
            scan_controls,
        }
    }
}

const COMPLETION_CASES: &[CompletionCase] = &[
    CompletionCase::new("__fish_degu_needs_command", false, false),
    CompletionCase::new("__fish_degu_using_subcommand completions", false, false),
    CompletionCase::new("__fish_degu_using_subcommand man", false, false),
];

fn run(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::cargo_bin("degu")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("LOGNAME", home.path())
        .env("DEGU_ALLOW_ROOT", "1")
        .args(args)
        .output()
        .unwrap()
}

fn declares_option(help: &str, option: &str) -> bool {
    help.lines().any(|line| {
        let declaration = line.trim_start();
        declaration.starts_with('-')
            && declaration
                .split_whitespace()
                .take(2)
                .any(|word| word.trim_end_matches(',') == option)
    })
}

fn completion_declares(script: &str, condition: &str, option: &str) -> bool {
    let condition = format!("-n \"{condition}\"");
    let option = format!("-l {}", option.trim_start_matches('-'));
    script
        .lines()
        .any(|line| line.contains(&condition) && line.contains(&option))
}

#[test]
fn command_help_lists_only_effective_options() {
    for case in HELP_CASES {
        let output = run(case.args);
        assert!(output.status.success(), "help failed for {:?}", case.args);
        let help = String::from_utf8(output.stdout).unwrap();
        for (option, expected) in [
            (JSON, case.json),
            (BUDGET, case.scan_controls),
            (MAX_CONCURRENCY, case.scan_controls),
        ] {
            assert_eq!(
                declares_option(&help, option),
                expected,
                "unexpected {option} visibility for {:?}",
                case.args
            );
        }
    }
}

#[test]
fn unsupported_options_and_root_prefix_forms_are_rejected() {
    for (args, option) in UNSUPPORTED_CASES {
        let output = run(args);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "args were accepted: {args:?}"
        );
        assert!(stderr.contains("unexpected argument"), "{stderr}");
        assert!(stderr.contains(option), "{stderr}");
    }
}

#[test]
fn fish_completions_scope_options_by_command() {
    let output = run(&["completions", "fish"]);
    assert!(output.status.success());
    let script = String::from_utf8(output.stdout).unwrap();
    for case in COMPLETION_CASES {
        for (option, expected) in [
            (JSON, case.json),
            (BUDGET, case.scan_controls),
            (MAX_CONCURRENCY, case.scan_controls),
        ] {
            assert_eq!(
                completion_declares(&script, case.condition, option),
                expected,
                "unexpected {option} completion for {}",
                case.condition
            );
        }
    }
}
