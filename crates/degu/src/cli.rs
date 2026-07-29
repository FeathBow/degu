use crate::value_parser::{parse_duration, parse_size};
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
  degu clean --dry-run
  degu clean

After staging, choose one outcome:
  degu undo
  degu trash purge

Run 'degu <command> --help' for command details.";

const SCAN_EXAMPLES: &str = "Examples:
  degu scan .
      Scan known caches and include build artifacts under the current project
  degu scan --only artifacts .
      Scan only build artifacts under the current project
  degu scan --json | jq .
      Emit machine-readable data";

const QUOTA_EXAMPLES: &str = "Examples:
  degu quota
      Inspect the current user's quota for HOME
  degu quota /scratch/$USER
      Inspect the filesystem containing one path
  degu quota --json | jq .
      Emit authoritative quota data as JSON";

const MAN_EXAMPLES: &str = "Examples:
  degu man
      Print the top-level page
  degu man scan
      Print the scan page
  degu man trash purge
      Print a nested command page";

const CLEAN_HELP: &str = "Safety:
  Clean also selects trash entries at least seven days old for permanent
  deletion. Dry runs preview both the clean plan and expired trash without
  changing either. A mutating run displays and authorizes the fixed expiry
  plan before deleting it.

Examples:
  degu clean --dry-run
      Preview cleanup without changing files
  degu clean --details --dry-run --include-review --path ~/.cache/huggingface/datasets
      Preview one reviewed location
  degu clean ~/code --dry-run
      Include project build artifacts";

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
    #[arg(long)]
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
    /// Report the current user's authoritative filesystem quota for one path
    #[command(after_help = QUOTA_EXAMPLES)]
    Quota(QuotaArgs),
    /// Preview or execute a cleanup plan
    #[command(after_help = CLEAN_HELP)]
    Clean(CleanArgs),
    /// Restore the latest staged clean operation
    Undo {
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Inspect or permanently purge degu trash
    Trash {
        #[command(subcommand)]
        command: TrashCommand,
    },
    /// Show recorded clean, restore, and purge operations
    Ops {
        #[command(flatten)]
        output: JsonArgs,
    },
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
    /// Show each finding with its full absolute path, kind, rationale, and cleanup reason; ignored by --json
    #[arg(short, long)]
    pub(crate) details: bool,
    /// Group findings by source instead of listing individual paths
    #[arg(long, conflicts_with = "details")]
    pub(crate) summary: bool,
    /// Keep only findings using at least this much space on disk (bytes, K, M, G, T)
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    pub(crate) min_size: Option<u64>,
    /// Keep only the N largest findings; applies per section (cache findings and node-runtime findings are filtered independently)
    #[arg(long, value_name = "N")]
    pub(crate) top: Option<usize>,
    /// Keep only findings untouched for at least this many days
    #[arg(long, value_name = "DAYS")]
    pub(crate) older_than: Option<u64>,
    /// Show only findings from this source ID; repeatable
    #[arg(long)]
    pub(crate) only: Vec<String>,
    #[arg(long, help = RUNTIME_HELP)]
    pub(crate) runtime: bool,
    /// Project roots whose build artifacts are added to the usual cache scan
    pub(crate) roots: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct QuotaArgs {
    #[command(flatten)]
    pub(crate) output: JsonArgs,
    /// Path whose containing filesystem should be queried; defaults to HOME
    pub(crate) path: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct CleanArgs {
    #[command(flatten)]
    pub(crate) output: JsonArgs,
    #[command(flatten)]
    pub(crate) limits: ScanLimitArgs,
    /// Show each finding with its full absolute path, kind, rationale, and cleanup reason; ignored by --json
    #[arg(short, long)]
    pub(crate) details: bool,
    /// Project roots explicitly authorized for this clean; configured scan roots are excluded
    pub(crate) roots: Vec<PathBuf>,
    /// Include Needs review findings in the clean plan after inspecting them
    #[arg(long)]
    pub(crate) include_review: bool,
    /// Proceed without prompting
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show the plan without staging findings or purging expired trash
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Stage then immediately purge clean items; use with --yes in non-interactive runs
    #[arg(long)]
    pub(crate) purge: bool,
    /// Keep only findings untouched for at least this many days
    #[arg(long, value_name = "DAYS")]
    pub(crate) older_than: Option<u64>,
    /// Restrict the clean plan to this source ID; repeatable
    #[arg(long)]
    pub(crate) only: Vec<String>,
    /// Keep only findings using at least this much space on disk (bytes, K, M, G, T)
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    pub(crate) min_size: Option<u64>,
    /// Keep only the N largest findings
    #[arg(long, value_name = "N")]
    pub(crate) top: Option<usize>,
    /// Keep only findings at or under this path; repeatable
    #[arg(long)]
    pub(crate) path: Vec<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum TrashCommand {
    /// List trash entries
    List {
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Permanently remove all trash entries
    Purge {
        #[command(flatten)]
        output: JsonArgs,
        /// Proceed without prompting
        #[arg(long)]
        yes: bool,
    },
}
