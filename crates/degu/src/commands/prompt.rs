use anyhow::Result;
use std::io::{IsTerminal, Write};

pub(crate) fn confirm_required(message: &str) -> Result<bool> {
    confirm(Confirmation {
        non_tty_error: message,
        prompt: "Proceed? [y/N] ",
        accepted: Accepted::Yes,
    })
}

struct Confirmation<'a> {
    non_tty_error: &'a str,
    prompt: &'a str,
    accepted: Accepted,
}

enum Accepted {
    Yes,
}

impl Accepted {
    fn matches(&self, input: &str) -> bool {
        match self {
            Self::Yes => matches!(input, "y" | "Y"),
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
