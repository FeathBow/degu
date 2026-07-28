//! degu command-line implementation (`degu` and the short alias `dg` are both
//! one-line shells over this).
//!
//! Output discipline: stdout carries command data only; diagnostics and logs go to stderr so machine-readable output remains pipe-safe.

mod cli;
mod commands;
mod configuration;
mod output;
mod presentation;
mod runtime;

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
    runtime::initialize(verbose, policy)?;

    match command {
        Command::Completions { shell } => commands::completions::run(shell),
        Command::Man { command } => commands::man::run(command),
        Command::Adapters => commands::adapters::run(),
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
