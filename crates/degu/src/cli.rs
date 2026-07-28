use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

mod color;
mod help;
pub(crate) use color::{ColorPolicy, ColorWhen};
use help::TOP_LEVEL_HELP_TEMPLATE;

const TOP_LEVEL_EXAMPLES: &str = "Run 'degu <command> --help' for command details.";

const MAN_EXAMPLES: &str = "Examples:
  degu man
      Print the top-level page
  degu man scan
      Print the scan page
  degu man trash purge
      Print a nested command page";

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

#[derive(Subcommand)]
pub(crate) enum Command {
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
