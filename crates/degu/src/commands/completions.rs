use crate::cli::Cli;
use anyhow::Result;
use clap::CommandFactory;
use std::ffi::OsStr;
use std::path::Path;

const COMMAND_NAME: &str = "degu";
const ALIAS_NAME: &str = "dg";

pub(crate) fn run(shell: clap_complete::Shell) -> Result<()> {
    let mut command = Cli::command();
    let mut output = Vec::new();
    let command_name = invoked_command_name();
    clap_complete::generate(shell, &mut command, command_name, &mut output);
    tracing::info!(?shell, command_name, "completion script generated");
    crate::output::write_stdout(output)
}

fn invoked_command_name() -> &'static str {
    if std::env::args_os()
        .next()
        .is_some_and(|argument| Path::new(&argument).file_name() == Some(OsStr::new(ALIAS_NAME)))
    {
        ALIAS_NAME
    } else {
        COMMAND_NAME
    }
}
