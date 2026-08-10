//! degu command-line implementation (`degu` and the short alias `dg` are both
//! one-line shells over this).
//!
//! Output discipline: stdout carries command data only; diagnostics and logs go to stderr so machine-readable output remains pipe-safe.

#[allow(dead_code)]
// Contract types only; the cleanup lifecycle and quota-observation wiring land separately.
mod action_result;
mod cli;
mod collection;
mod commands;
mod configuration;
mod filters;
mod finding_filter;
mod findings_table;
mod lifecycle;
#[allow(dead_code)]
// Native capability execution and its quota-observation bridge; no caller wired up yet.
mod native_action;
#[allow(dead_code)]
// Native execution foundation; some execution helpers are not exercised until a native action runs.
mod native_runner;
mod output;
mod presentation;
mod quota;
mod quota_observation;
mod runtime;
mod source_selection;
#[allow(dead_code)]
// Descriptor-bound uv cache-root authority; one safety bound is not exercised until execution lands.
mod uv_cache_root;
mod uv_executable;
mod uv_prune_plan;
mod value_parser;

use anyhow::Result;
use cli::{Cli, ColorPolicy, Command};
use std::io::IsTerminal;
use std::process::ExitCode;

pub fn entrypoint() -> ExitCode {
    let Cli {
        verbose,
        color,
        command,
    } = cli::parse();
    let policy = ColorPolicy::current(color);
    let colors = runtime::OutputColors {
        stdout: policy.enabled(std::io::stdout().is_terminal()),
        stderr: policy.enabled(std::io::stderr().is_terminal()),
    };
    match run(verbose, command, policy) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if output::is_stdout_closed(&error) => ExitCode::SUCCESS,
        Err(error) => {
            presentation::print_stderr_note(
                presentation::Severity::Error,
                &render_error(&error),
                colors,
            );
            ExitCode::FAILURE
        }
    }
}

/// Multi-line sub-errors (a TOML parse error with caret lines, say) keep
/// their line structure: controls are escaped per line and the newlines
/// survive for [`presentation::print_stderr_note`] to indent.
fn render_error(error: &anyhow::Error) -> String {
    format!("{error:#}")
        .trim_end_matches('\n')
        .lines()
        .map(presentation::escape_terminal_controls)
        .collect::<Vec<_>>()
        .join("\n")
}

fn run(verbose: u8, command: Command, policy: ColorPolicy) -> Result<()> {
    let ui = runtime::initialize(verbose, policy)?;

    match command {
        Command::Completions { shell } => commands::completions::run(shell),
        Command::Man { command } => commands::man::run(command),
        Command::Adapters => commands::adapters::run(),
        command => {
            runtime::enforce_root_policy(ui.colors)?;
            dispatch(command, ui)
        }
    }
}

fn dispatch(command: Command, ui: runtime::Ui) -> Result<()> {
    match command {
        Command::Scan(args) => commands::scan::run(args, ui),
        Command::Quota(args) => commands::quota::run(args, ui),
        Command::Reclaim { command } => commands::reclaim::run(command, ui),
        Command::Clean(args) => commands::clean::run(args, ui),
        Command::Trash { command } => commands::trash::run(command, ui),
        Command::Ops { output } => commands::ops::run(output.json, ui),
        Command::Undo { output } => commands::undo::run(output.json, ui),
        Command::Relocate(args) => {
            commands::relocate::run(args.output.json, args.init, args.target)
        }
        Command::Completions { .. } | Command::Man { .. } | Command::Adapters => {
            unreachable!("handled before guarded run")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::render_error;

    #[test]
    fn top_level_errors_escape_raw_terminal_controls_but_keep_newlines() {
        let error = anyhow::anyhow!("path /cache\u{1b}[31m\nsecond\tline\n");
        let rendered = render_error(&error);

        assert!(
            !rendered
                .chars()
                .any(|character| character.is_control() && character != '\n')
        );
        assert_eq!(rendered, "path /cache\\u{1b}[31m\nsecond\\tline");
    }
}
