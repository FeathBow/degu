use crate::cli::ColorPolicy;
use anyhow::Result;
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::Path;

const ROOT_OVERRIDE: &str = "1";
const WARN_VERBOSITY: u8 = 0;
const INFO_VERBOSITY: u8 = 1;
const DEBUG_VERBOSITY: u8 = 2;

/// Immutable presentation facts captured once at startup and threaded as one
/// value through every human-output renderer.
#[derive(Clone, Copy)]
pub(crate) struct Ui {
    pub(crate) colors: OutputColors,
}

#[derive(Clone, Copy)]
pub(crate) struct OutputColors {
    pub(crate) stdout: bool,
    pub(crate) stderr: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPolicy {
    Proceed,
    Warn,
    Refuse,
}

pub(crate) fn initialize(verbose: u8, policy: ColorPolicy) -> Result<Ui> {
    let stdout_is_terminal = std::io::stdout().is_terminal();
    let colors = OutputColors {
        stdout: policy.enabled(stdout_is_terminal),
        stderr: policy.enabled(std::io::stderr().is_terminal()),
    };
    crossterm::style::force_color_output(colors.stdout);
    init_tracing(verbose, colors.stderr)?;
    Ok(Ui { colors })
}

pub(crate) fn enforce_root_policy(colors: OutputColors) -> Result<()> {
    let in_container =
        Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
    let allow_env =
        std::env::var_os("DEGU_ALLOW_ROOT").as_deref() == Some(OsStr::new(ROOT_OVERRIDE));
    match root_policy(
        rustix::process::geteuid().is_root(),
        in_container,
        allow_env,
    ) {
        RootPolicy::Proceed => Ok(()),
        RootPolicy::Warn => {
            crate::presentation::print_stderr_note(
                crate::presentation::Severity::Warning,
                "degu is running as root; root changes degu semantics ($HOME, guard defaults, and trash anchor ownership); proceeding because a container marker or DEGU_ALLOW_ROOT=1 allowed it",
                colors,
            );
            Ok(())
        }
        RootPolicy::Refuse => anyhow::bail!(
            "refusing to run as root: root changes degu semantics ($HOME, guard defaults, and trash anchor ownership); run as a normal user or set DEGU_ALLOW_ROOT=1 to override"
        ),
    }
}

fn root_policy(euid_is_root: bool, in_container: bool, allow_env: bool) -> RootPolicy {
    if !euid_is_root {
        RootPolicy::Proceed
    } else if allow_env || in_container {
        RootPolicy::Warn
    } else {
        RootPolicy::Refuse
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_root_proceeds() {
        assert_eq!(root_policy(false, false, false), RootPolicy::Proceed);
    }

    #[test]
    fn root_warns_when_explicitly_allowed() {
        assert_eq!(root_policy(true, false, true), RootPolicy::Warn);
    }

    #[test]
    fn root_warns_in_container() {
        assert_eq!(root_policy(true, true, false), RootPolicy::Warn);
    }

    #[test]
    fn unconfined_root_is_refused() {
        assert_eq!(root_policy(true, false, false), RootPolicy::Refuse);
    }
}
