use crate::commands::guidance::{self, OutputMode, Request, TrashListState, Workflow};
use crate::lifecycle::Lifecycle;
use anyhow::Result;
use degu_core::ecosystem::DetectCtx;

use super::output;

pub(super) fn run(json: bool, ui: crate::runtime::Ui) -> Result<()> {
    let ctx = DetectCtx::from_process()?;
    let rows = Lifecycle::new(&ctx).trash_entries()?;
    let reachable = crate::lifecycle::activated_store_reachable(&ctx);
    if json {
        output::print_json(&rows, reachable)
    } else {
        if !reachable {
            crate::presentation::print_stderr_note(
                crate::presentation::Severity::Warning,
                output::UNREACHABLE_ACTIVATED_STORE,
                ui.colors,
            );
        }
        output::print_human(&rows, &ctx.home, ui)?;
        if should_print_outcomes(&rows, ui.stdout_is_terminal) {
            output::print_outcomes(&rows, ui)?;
        }
        guidance::print(Request {
            output: OutputMode::Human(ui),
            workflow: Workflow::TrashList(TrashListState {
                ambiguous: rows.iter().any(|row| row.ambiguous),
                interrupted_purge: rows.iter().any(|row| row.interrupted_purge),
            }),
            home: None,
        })
    }
}

fn should_print_outcomes(rows: &[crate::lifecycle::TrashEntry], stdout_is_terminal: bool) -> bool {
    stdout_is_terminal && !rows.is_empty() && rows.iter().all(|row| !row.ambiguous)
}
