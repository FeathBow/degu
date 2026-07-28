use crate::cli::ColorPolicy;
use anyhow::Result;
use std::io::IsTerminal;

const WARN_VERBOSITY: u8 = 0;
const INFO_VERBOSITY: u8 = 1;
const DEBUG_VERBOSITY: u8 = 2;

#[derive(Clone, Copy)]
pub(crate) struct OutputColors {
    pub(crate) stdout: bool,
    pub(crate) stderr: bool,
}

pub(crate) fn initialize(verbose: u8, policy: ColorPolicy) -> Result<()> {
    let stdout_is_terminal = std::io::stdout().is_terminal();
    let colors = OutputColors {
        stdout: policy.enabled(stdout_is_terminal),
        stderr: policy.enabled(std::io::stderr().is_terminal()),
    };
    crossterm::style::force_color_output(colors.stdout);
    init_tracing(verbose, colors.stderr)?;
    Ok(())
}

fn init_tracing(verbose: u8, ansi: bool) -> Result<()> {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;

    let default_level = match verbose {
        WARN_VERBOSITY => LevelFilter::WARN,
        INFO_VERBOSITY => LevelFilter::INFO,
        DEBUG_VERBOSITY => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) => value
            .parse::<Targets>()
            .map_err(|error| anyhow::anyhow!("invalid RUST_LOG directive {value:?}: {error}"))?,
        Err(std::env::VarError::NotPresent) => Targets::new().with_default(default_level),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("RUST_LOG contains invalid UTF-8")
        }
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(ansi),
        )
        .init();
    Ok(())
}
