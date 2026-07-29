use assert_cmd::Command;
use std::process::Output;

const JSON: &str = "--json";
const BUDGET: &str = "--budget";
const MAX_CONCURRENCY: &str = "--max-concurrency";
const LONG: &str = "--long";
const OPT_IN: &str = "--opt-in";

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
    HelpCase::new(&["scan", "--help"], true, true),
    HelpCase::new(&["clean", "--help"], true, true),
    HelpCase::new(&["trash", "--help"], false, false),
    HelpCase::new(&["trash", "list", "--help"], true, false),
    HelpCase::new(&["trash", "purge", "--help"], true, false),
    HelpCase::new(&["undo", "--help"], true, false),
    HelpCase::new(&["ops", "--help"], true, false),
];

const SUPPORTED_CASES: &[&[&str]] = &[
    &["scan", JSON, BUDGET, "1h", MAX_CONCURRENCY, "1"],
    &[
        "scan",
        "--summary",
        JSON,
        BUDGET,
        "1h",
        MAX_CONCURRENCY,
        "1",
    ],
    &[
        "clean",
        JSON,
        BUDGET,
        "1h",
        MAX_CONCURRENCY,
        "1",
        "--dry-run",
    ],
    &["trash", "list", JSON, "--help"],
    &["trash", "purge", JSON, "--help"],
    &["undo", JSON, "--help"],
    &["ops", JSON, "--help"],
];

const UNSUPPORTED_CASES: &[(&[&str], &str)] = &[
    (&["scan", LONG], LONG),
    (&["clean", LONG, "--dry-run"], LONG),
    (&["clean", OPT_IN, "--dry-run"], OPT_IN),
    (&[JSON, "scan"], JSON),
    (&[BUDGET, "1s", "scan"], BUDGET),
    (&[MAX_CONCURRENCY, "1", "scan"], MAX_CONCURRENCY),
    (&["completions", "bash", JSON], JSON),
    (&["completions", "bash", BUDGET, "1s"], BUDGET),
    (
        &["completions", "bash", MAX_CONCURRENCY, "1"],
        MAX_CONCURRENCY,
    ),
    (&["man", JSON], JSON),
    (&["man", BUDGET, "1s"], BUDGET),
    (&["man", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
    (&["trash", "list", BUDGET, "1s"], BUDGET),
    (&["trash", "list", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
    (&["trash", "purge", BUDGET, "1s"], BUDGET),
    (&["trash", "purge", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
    (&["undo", BUDGET, "1s"], BUDGET),
    (&["undo", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
    (&["ops", BUDGET, "1s"], BUDGET),
    (&["ops", MAX_CONCURRENCY, "1"], MAX_CONCURRENCY),
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
    CompletionCase::new("__fish_degu_using_subcommand scan", true, true),
    CompletionCase::new("__fish_degu_using_subcommand clean", true, true),
    CompletionCase::new(
        "__fish_degu_using_subcommand trash; and not __fish_seen_subcommand_from list purge help",
        false,
        false,
    ),
    CompletionCase::new(
        "__fish_degu_using_subcommand trash; and __fish_seen_subcommand_from list",
        true,
        false,
    ),
    CompletionCase::new(
        "__fish_degu_using_subcommand trash; and __fish_seen_subcommand_from purge",
        true,
        false,
    ),
    CompletionCase::new("__fish_degu_using_subcommand ops", true, false),
    CompletionCase::new("__fish_degu_using_subcommand undo", true, false),
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
fn human_review_options_use_task_oriented_names() {
    let scan = String::from_utf8(run(&["scan", "--help"]).stdout).unwrap();
    assert!(declares_option(&scan, "--details"), "{scan}");
    assert!(!declares_option(&scan, "--long"), "{scan}");

    let clean = String::from_utf8(run(&["clean", "--help"]).stdout).unwrap();
    assert!(declares_option(&clean, "--details"), "{clean}");
    assert!(declares_option(&clean, "--include-review"), "{clean}");
    assert!(!declares_option(&clean, "--long"), "{clean}");
    assert!(!declares_option(&clean, "--opt-in"), "{clean}");
}

#[test]
fn max_concurrency_zero_is_rejected_for_scan_and_clean() {
    for args in [
        &["scan", MAX_CONCURRENCY, "0"][..],
        &["clean", MAX_CONCURRENCY, "0", "--dry-run"],
    ] {
        let output = run(args);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "zero was accepted: {args:?}");
        assert!(stderr.contains(MAX_CONCURRENCY), "{stderr}");
        assert!(stderr.contains('0'), "{stderr}");
        assert!(
            stderr.contains("nonzero") || stderr.contains("non-zero"),
            "{stderr}"
        );
    }
}

#[test]
fn supported_options_are_accepted_after_their_commands() {
    for args in SUPPORTED_CASES {
        let output = run(args);
        assert!(output.status.success(), "supported args failed: {args:?}");
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
