mod output;
mod preparation;

use crate::cli::CleanArgs;
use crate::runtime::Ui;
use anyhow::Result;

pub(crate) fn run(args: CleanArgs, ui: Ui) -> Result<()> {
    let prepared = preparation::prepare(args, ui)?;
    if prepared.settings.json {
        return output::print_json(&prepared);
    }
    output::print_plan(&prepared)
}
