use assert_cmd::Command;

const TOP_LEVEL_MAN_COMMANDS: &[&[&str]] = &[
    &["scan"],
    &["doctor"],
    &["quota"],
    &["reclaim"],
    &["clean"],
    &["undo"],
    &["trash"],
    &["relocate"],
    &["admin"],
    &["ops"],
    &["adapters"],
    &["completions"],
    &["man"],
];
const NESTED_MAN_COMMANDS: &[&[&str]] = &[&["trash", "list"], &["trash", "purge"]];
const ADMIN_MAN_COMMANDS: &[&[&str]] = &[
    &["admin"],
    &["admin", "activation-anchor"],
    &["admin", "activation-anchor", "provision"],
];
const RECLAIM_MAN_COMMANDS: &[&[&str]] = &[&["reclaim", "uv"]];

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
    for path in TOP_LEVEL_MAN_COMMANDS
        .iter()
        .chain(NESTED_MAN_COMMANDS)
        .chain(RECLAIM_MAN_COMMANDS)
        .chain(ADMIN_MAN_COMMANDS)
    {
        let output = generated_man(path);
        let title = format!(".TH degu{} 1", page_suffix(path));
        assert!(output.contains(&title), "missing {title:?}");
        let name = canonical_roff_name(path);
        assert!(output.contains(&format!(".SH NAME\n{name} \\-")));
        let synopsis = path
            .iter()
            .map(|segment| segment.replace('-', "\\-"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(output.contains(&format!(".SH SYNOPSIS\n\\fBdegu {synopsis}\\fR")));
        assert!(!output.contains("\\-help(1)"));
    }
    assert!(generated_man(&["scan"]).contains("\\-\\-summary"));
    assert!(generated_man(&["quota"]).contains("quota data as JSON"));
    let reclaim = generated_man(&["reclaim"]);
    assert!(reclaim.contains("degu\\-reclaim\\-uv(1)"));
    assert!(generated_man(&["reclaim", "uv"]).contains("selected binary is not"));
    let trash = generated_man(&["trash"]);
    assert!(trash.contains("degu\\-trash\\-list(1)"));
    assert!(trash.contains("degu\\-trash\\-purge(1)"));
    assert!(generated_man(&["trash", "purge"]).contains("\\-\\-yes"));
}

#[test]
fn man_references_only_pages_in_the_release_contract() {
    assert_eq!(
        man_references(&generated_man(&[])),
        expected_man_references(TOP_LEVEL_MAN_COMMANDS)
    );
    assert_eq!(
        man_references(&generated_man(&["trash"])),
        expected_man_references(NESTED_MAN_COMMANDS)
    );
    assert_eq!(
        man_references(&generated_man(&["reclaim"])),
        expected_man_references(RECLAIM_MAN_COMMANDS)
    );
    assert_eq!(
        man_references(&generated_man(&["admin"])),
        expected_man_references(&ADMIN_MAN_COMMANDS[1..2])
    );
    assert_eq!(
        man_references(&generated_man(&["admin", "activation-anchor"])),
        expected_man_references(&ADMIN_MAN_COMMANDS[2..])
    );
}

#[test]
fn man_rejects_an_unknown_command_path() {
    let output = degu().args(["man", "trash", "unknown"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("no man page for command path 'trash unknown'")
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
            "Administration:",
            "Reference:",
            "Options:",
        ],
    );
    assert_order(
        &output,
        &[
            "\n  scan",
            "\n  doctor",
            "\n  quota",
            "\n  reclaim",
            "\n  clean",
            "\n  undo",
            "\n  trash",
            "\n  relocate",
            "\n  admin",
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
            "degu\\-doctor(1)",
            "degu\\-quota(1)",
            "degu\\-reclaim(1)",
            "degu\\-clean(1)",
            "degu\\-undo(1)",
            "degu\\-trash(1)",
            "degu\\-relocate(1)",
            "degu\\-admin(1)",
            "degu\\-ops(1)",
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
        assert!(output.contains(
            "scan doctor quota reclaim clean undo trash relocate admin ops adapters completions man help"
        ));
        assert!(!output.contains("degu,usage)"));
        return;
    }
    let markers: &[&str] = match shell {
        "zsh" => {
            assert!(output.contains("#compdef") || output.contains("_degu"));
            &[
                "(scan)",
                "(doctor)",
                "(quota)",
                "(reclaim)",
                "(clean)",
                "(undo)",
                "(trash)",
                "(relocate)",
                "(admin)",
                "(ops)",
                "(adapters)",
                "(completions)",
                "(man)",
            ]
        }
        "fish" => {
            assert!(output.contains("complete"));
            &[
                "-a \"scan\"",
                "-a \"doctor\"",
                "-a \"quota\"",
                "-a \"reclaim\"",
                "-a \"clean\"",
                "-a \"undo\"",
                "-a \"trash\"",
                "-a \"relocate\"",
                "-a \"admin\"",
                "-a \"ops\"",
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
    format!(
        "degu\\-{}",
        path.iter()
            .map(|segment| segment.replace('-', "\\-"))
            .collect::<Vec<_>>()
            .join("\\-")
    )
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
