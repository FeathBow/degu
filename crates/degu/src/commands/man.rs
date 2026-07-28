use crate::cli::Cli;
use anyhow::{Result, anyhow};
use clap::CommandFactory;

pub(crate) fn run(path: Vec<String>) -> Result<()> {
    let mut root = Cli::command().disable_help_subcommand(true);
    root.build();
    let command = select_command(&root, &path)?;
    let mut output = Vec::new();
    clap_mangen::Man::new(command.clone())
        .source(format!("degu {}", env!("CARGO_PKG_VERSION")))
        .render(&mut output)?;
    tracing::info!(?path, "manual page generated");
    crate::output::write_stdout(output)
}

fn select_command<'a>(root: &'a clap::Command, path: &[String]) -> Result<&'a clap::Command> {
    let mut command = root;
    for (index, segment) in path.iter().enumerate() {
        command = command.find_subcommand(segment).ok_or_else(|| {
            anyhow!(
                "no man page for command path '{}'",
                path[..=index].join(" ")
            )
        })?;
    }
    Ok(command)
}
