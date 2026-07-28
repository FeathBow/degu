use crate::commands::next_action::{self, OutputMode, Request, TrashListState, Workflow};
use crate::lifecycle::Lifecycle;
use anyhow::Result;
use degu_core::ecosystem::DetectCtx;

use super::output;

pub(super) fn run(json: bool, ui: crate::runtime::Ui) -> Result<()> {
    let ctx = DetectCtx::from_process()?;
    let rows = Lifecycle::new(&ctx).trash_entries()?;
    if json {
        output::print_json(&rows)
    } else {
        output::print_human(&rows, &ctx.home, ui)?;
        next_action::print(Request {
            output: OutputMode::Human(ui),
            workflow: Workflow::TrashList(TrashListState {
                ambiguous: rows.iter().any(|row| row.ambiguous),
                interrupted_purge: rows.iter().any(|row| row.interrupted_purge),
            }),
            home: None,
        })
    }
}
