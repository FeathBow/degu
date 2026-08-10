use anyhow::Result;
use std::io::{IsTerminal, Write};

use crate::presentation::semantic::{self, Tone};
use crate::runtime::OutputColors;

pub(crate) fn confirm_required(message: &str) -> Result<bool> {
    confirm(Confirmation {
        non_tty_error: message,
        prompt: "Proceed? [y/N] ",
        accepted: Accepted::Yes,
    })
}

pub(crate) fn confirm_permanent_delete(colors: OutputColors) -> Result<bool> {
    crossterm::style::force_color_output(colors.stderr);
    let prompt = semantic::paint(
        "Type 'purge' to permanently delete this plan: ",
        Tone::Destructive,
        colors.stderr,
    );
    crossterm::style::force_color_output(colors.stdout);
    confirm(Confirmation {
        non_tty_error: "permanent deletion requires --yes when stdin is not a terminal",
        prompt: &prompt,
        accepted: Accepted::Purge,
    })
}

pub(crate) fn confirm_native_reclaim(colors: OutputColors) -> Result<bool> {
    crossterm::style::force_color_output(colors.stderr);
    let prompt = semantic::paint(
        "Type 'prune' to run irreversible uv cache prune: ",
        Tone::Destructive,
        colors.stderr,
    );
    crossterm::style::force_color_output(colors.stdout);
    confirm(Confirmation {
        non_tty_error: "uv cache prune requires --yes when stdin is not a terminal",
        prompt: &prompt,
        accepted: Accepted::Prune,
    })
}

struct Confirmation<'a> {
    non_tty_error: &'a str,
    prompt: &'a str,
    accepted: Accepted,
}

enum Accepted {
    Yes,
    Purge,
    Prune,
}

impl Accepted {
    fn matches(&self, input: &str) -> bool {
        match self {
            Self::Yes => matches!(input, "y" | "Y"),
            Self::Purge => input == "purge",
            Self::Prune => input == "prune",
        }
    }
}

fn confirm(request: Confirmation<'_>) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        anyhow::bail!("{}", request.non_tty_error);
    }
    eprint!("{}", request.prompt);
    std::io::stderr().flush()?;
    let mut input = String::new();
    stdin.read_line(&mut input)?;
    Ok(request.accepted.matches(input.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irreversible_tokens_are_exact_and_not_interchangeable() {
        assert!(Accepted::Prune.matches("prune"));
        assert!(!Accepted::Prune.matches("Prune"));
        assert!(!Accepted::Prune.matches("purge"));
        assert!(Accepted::Purge.matches("purge"));
        assert!(!Accepted::Purge.matches("prune"));
    }
}
