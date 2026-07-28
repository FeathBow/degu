use crate::value_parser::parse_duration;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

mod color;
mod help;
pub(crate) use color::{ColorPolicy, ColorWhen};
use help::TOP_LEVEL_HELP_TEMPLATE;

const TOP_LEVEL_EXAMPLES: &str = "Workflow:
  degu scan

Run 'degu <command> --help' for command details.";

const SCAN_EXAMPLES: &str = "Examples:
  degu scan .
      Scan known caches and include build artifacts under the current project
  degu scan --only artifacts .
      Scan only build artifacts under the current project
  degu scan --json | jq .
      Emit machine-readable data";

const MAN_EXAMPLES: &str = "Examples:
  degu man
      Print the top-level page
  degu man scan
      Print the scan page
  degu man trash purge
      Print a nested command page";

const MAX_CONCURRENCY_HELP: &str = "Override the per-filesystem directory-read limit";

#[cfg(target_os = "linux")]
const RUNTIME_HELP: &str = "Include /dev/shm and temporary-directory diagnostics. Findings are Not managed and never join cache totals.";

#[cfg(not(target_os = "linux"))]
const RUNTIME_HELP: &str = "Include temporary-directory diagnostics. Shared-memory diagnostics are available on Linux only. Findings are Not managed and never join cache totals.";

#[derive(Parser)]
#[command(
    name = "degu",
    version,
    about = env!("CARGO_PKG_DESCRIPTION"),
    help_template = TOP_LEVEL_HELP_TEMPLATE,
    after_help = TOP_LEVEL_EXAMPLES
)]
pub(crate) struct Cli {
    /// Log verbosity (-v info, -vv debug, -vvv trace); simple RUST_LOG directives override
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,
    /// Colorize human output: auto, always, or never
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub(crate) color: ColorWhen,
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(crate) fn parse() -> Cli {
    let args = std::env::args_os().collect::<Vec<_>>();
    let matches = Cli::command()
        .styles(color::help_styles())
        .color(color::clap_color_choice(&args))
        .get_matches_from(args);
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[derive(Args)]
pub(crate) struct JsonArgs {
    /// Emit machine-readable JSON to stdout
    #[arg(long, required = true)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct ScanLimitArgs {
    #[arg(long, value_name = "N", help = MAX_CONCURRENCY_HELP)]
    pub(crate) max_concurrency: Option<NonZeroUsize>,
    /// Stop starting new scan work after this wall-clock budget; in-flight filesystem operations may finish (bare integer seconds, or Ns/Nm/Nh)
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) budget: Option<Duration>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Report known cache sources and, when project roots are available, build artifacts (read-only)
    #[command(after_help = SCAN_EXAMPLES)]
    Scan(ScanArgs),
    /// List adapter IDs accepted by --only and configuration, plus the built-in source IDs accepted by --only
    Adapters,
    /// Print shell completion script to stdout
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page for degu or one command path to stdout
    #[command(after_help = MAN_EXAMPLES)]
    Man {
        /// Command path to render, for example `scan` or `trash purge`
        command: Vec<String>,
    },
}

#[derive(Args)]
pub(crate) struct ScanArgs {
    #[command(flatten)]
    pub(crate) output: JsonArgs,
    #[command(flatten)]
    pub(crate) limits: ScanLimitArgs,
    /// Show only findings from this source ID; repeatable
    #[arg(long)]
    pub(crate) only: Vec<String>,
    #[arg(long, help = RUNTIME_HELP)]
    pub(crate) runtime: bool,
    /// Project roots whose build artifacts are added to the usual cache scan
    pub(crate) roots: Vec<PathBuf>,
}
