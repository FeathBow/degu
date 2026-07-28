use assert_cmd::Command;

const TOP_LEVEL_MAN_COMMANDS: &[&[&str]] = &[&["scan"], &["adapters"], &["completions"], &["man"]];

fn degu() -> Command {
    let mut command = Command::cargo_bin("degu").unwrap();
    command.env_remove("RUST_LOG");
    command
}

#[test]
fn verbose_is_effective_for_reference_commands() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["-v", "completions", "bash"],
            "completion script generated",
        ),
        (&["-v", "man"], "manual page generated"),
        (&["-v", "adapters"], "adapter registry listed"),
    ];

    for (args, message) in cases {
        let out = degu().args(*args).output().unwrap();
        assert!(out.status.success(), "reference command failed: {args:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(message), "{args:?}: {stderr}");
        assert!(!stderr.contains("running as root"), "{args:?}: {stderr}");
    }
}

#[test]
fn adapters_lists_the_complete_registry_and_the_built_in_source_ids() {
    let out = degu().arg("adapters").output().unwrap();
    assert!(out.status.success());
    let actual = String::from_utf8(out.stdout).unwrap();
    let (registry, built_in) = actual
        .split_once("\n\n")
        .unwrap_or_else(|| panic!("missing built-in source section: {actual}"));
    assert!(
        !registry
            .lines()
            .any(|id| matches!(id, "artifacts" | "checkpoints"))
    );
    let mut expected = degu_adapters::all()
        .iter()
        .map(degu_adapters::RegisteredAdapter::id)
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(registry, expected.join("\n"));
    let mut built_in_lines = built_in.lines();
    assert_eq!(
        built_in_lines.next(),
        Some("Built-in source IDs (accepted by --only):")
    );
    for id in ["artifacts", "checkpoints"] {
        let line = built_in_lines
            .next()
            .unwrap_or_else(|| panic!("missing built-in source {id:?}: {actual}"));
        assert!(
            line.trim_start().starts_with(id),
            "expected {id:?} first on {line:?}"
        );
        assert!(
            line.trim_end().len() > line.find(id).unwrap() + id.len(),
            "missing description for {id:?}: {line:?}"
        );
    }
    assert_eq!(built_in_lines.next(), None, "unexpected trailing lines");
}

#[test]
fn generated_surfaces_prioritize_the_progressive_workflow() {
    assert_top_help_order();
    assert_man_order();
    for shell in ["bash", "zsh", "fish"] {
        assert_completion_order(shell);
    }
}

#[test]
fn man_renders_every_shipped_command_page() {
    for path in TOP_LEVEL_MAN_COMMANDS.iter() {
        let output = generated_man(path);
        let title = format!(".TH degu{} 1", page_suffix(path));
        assert!(output.contains(&title), "missing {title:?}");
        let name = canonical_roff_name(path);
        assert!(output.contains(&format!(".SH NAME\n{name} \\-")));
        assert!(output.contains(&format!(".SH SYNOPSIS\n\\fBdegu {}\\fR", path.join(" "))));
        assert!(!output.contains("\\-help(1)"));
    }
}

#[test]
fn man_references_only_pages_in_the_release_contract() {
    assert_eq!(
        man_references(&generated_man(&[])),
        expected_man_references(TOP_LEVEL_MAN_COMMANDS)
    );
}

fn assert_top_help_order() {
    let output = generated(&["--help"]);
    assert_order(
        &output,
        &[
            "Inspect:",
            "Clean and recover:",
            "Configure:",
            "Reference:",
            "Options:",
        ],
    );
    assert_order(
        &output,
        &[
            "\n  scan",
            "\n  quota",
            "\n  clean",
            "\n  undo",
            "\n  trash",
            "\n  relocate",
            "\n  ops",
            "\n  adapters",
            "\n  completions",
            "\n  man",
        ],
    );
    assert!(!output.contains("\n  usage "));
}

fn assert_man_order() {
    let output = generated(&["man"]);
    assert!(output.contains(".TH degu 1"));
    assert_order(
        &output,
        &[
            "degu\\-scan(1)",
            "degu\\-adapters(1)",
            "degu\\-completions(1)",
            "degu\\-man(1)",
        ],
    );
    assert!(!output.contains("degu\\-usage(1)"));
    assert!(!output.contains("\\-help(1)"));
}

fn assert_completion_order(shell: &str) {
    let output = generated(&["completions", shell]);
    assert!(!output.is_empty());
    if shell == "bash" {
        assert!(output.contains("complete -F") || output.contains("_degu"));
        assert!(output.contains("scan adapters completions man help"));
        assert!(!output.contains("degu,usage)"));
        return;
    }
    let markers: &[&str] = match shell {
        "zsh" => {
            assert!(output.contains("#compdef") || output.contains("_degu"));
            &["(scan)", "(adapters)", "(completions)", "(man)"]
        }
        "fish" => {
            assert!(output.contains("complete"));
            &[
                "-a \"scan\"",
                "-a \"adapters\"",
                "-a \"completions\"",
                "-a \"man\"",
            ]
        }
        _ => unreachable!(),
    };
    assert_order(&output, markers);
    assert!(!output.contains("review-first"));
}

fn generated(args: &[&str]) -> String {
    let out = degu().args(args).output().unwrap();
    assert!(out.status.success(), "generation failed for {args:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn generated_man(path: &[&str]) -> String {
    let mut args = vec!["man"];
    args.extend_from_slice(path);
    generated(&args)
}

fn page_suffix(path: &[&str]) -> String {
    path.iter().map(|segment| format!("-{segment}")).collect()
}

fn canonical_roff_name(path: &[&str]) -> String {
    format!("degu\\-{}", path.join("\\-"))
}

fn man_references(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.starts_with("degu\\-") && line.ends_with("(1)"))
        .map(str::to_owned)
        .collect()
}

fn expected_man_references(paths: &[&[&str]]) -> Vec<String> {
    paths
        .iter()
        .map(|path| format!("{}(1)", canonical_roff_name(path)))
        .collect()
}

fn assert_order(output: &str, markers: &[&str]) {
    let positions = markers
        .iter()
        .map(|marker| {
            output
                .find(marker)
                .unwrap_or_else(|| panic!("missing {marker:?} in generated output"))
        })
        .collect::<Vec<_>>();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "markers are out of order: {positions:?}"
    );
}
