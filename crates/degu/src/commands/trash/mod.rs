mod list;
pub(crate) mod output;

use anyhow::Result;

use crate::cli::TrashCommand;
use crate::runtime::Ui;

pub(crate) fn run(command: TrashCommand, ui: Ui) -> Result<()> {
    match command {
        TrashCommand::List { output } => list::run(output.json, ui),
    }
}
