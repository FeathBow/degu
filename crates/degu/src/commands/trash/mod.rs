mod list;
pub(crate) mod output;
mod purge;

use anyhow::Result;

use crate::cli::TrashCommand;
use crate::runtime::Ui;

pub(crate) fn run(command: TrashCommand, ui: Ui) -> Result<()> {
    match command {
        TrashCommand::List { output } => list::run(output.json, ui),
        TrashCommand::Purge { output, yes, path } => purge::run(output.json, yes, &path, ui),
    }
}
