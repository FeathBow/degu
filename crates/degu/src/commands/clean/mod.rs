mod execution;
mod output;
mod preparation;

use crate::cli::CleanArgs;
use crate::runtime::Ui;
use anyhow::Result;

pub(crate) fn run(args: CleanArgs, ui: Ui) -> Result<()> {
    execution::run(preparation::prepare(args, ui)?)
}
