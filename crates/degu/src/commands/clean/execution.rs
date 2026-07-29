use super::output;
use super::preparation::PreparedClean;
use crate::commands::next_action::{
    self, CleanPreviewState, CleanResultState, OutputMode, Request, Workflow,
};
use crate::commands::prompt::confirm_required;
use crate::lifecycle::{CleanExecution, MutationSession};
use anyhow::Result;
use degu_core::finding::Finding;

pub(super) fn run(prepared: PreparedClean) -> Result<()> {
    if prepared.settings.json {
        run_json(prepared)
    } else {
        run_human(prepared)
    }
}

/// A hung-up stdout means the invoker walked away; stop before the irreversible
/// mutation so `clean` never stages a delete no one asked to keep watching.
/// Checked at the mutation boundary (not just via earlier writes) so a kernel
/// send buffer that briefly accepts writes cannot race past the guard.
fn stop_if_stdout_closed() -> Result<()> {
    if crate::output::stdout_consumer_gone() {
        return Err(crate::output::stdout_closed_error());
    }
    Ok(())
}

fn boundary_recheck<'a>(
    prepared: &'a PreparedClean,
    session: &'a MutationSession,
) -> impl Fn(&Finding) -> Result<(), String> + 'a {
    move |finding| {
        prepared
            .recheck_finding(session, finding)
            .map_err(|error| error.to_string())
    }
}

fn run_json(prepared: PreparedClean) -> Result<()> {
    if prepared.settings.dry_run {
        return output::print_json(&prepared, &[]);
    }
    let session = prepared.lock()?;
    output::validate_json_prepared(&prepared)?;
    prepared.revalidate(&session)?;
    stop_if_stdout_closed()?;
    let recheck = boundary_recheck(&prepared, &session);
    let executed = session.execute_clean(&prepared.plan, &recheck);
    let clean_failed = executed.iter().any(CleanExecution::failed);
    let output_result = output::print_json(&prepared, &executed);
    ensure_clean_success(clean_failed)?;
    output_result
}

fn run_human(prepared: PreparedClean) -> Result<()> {
    if prepared.settings.dry_run {
        return run_human_preview(&prepared);
    }
    if prepared.plan.items().is_empty() {
        return output::print_plan(&prepared);
    }
    let session = prepared.lock()?;
    output::print_plan(&prepared)?;
    output::print_mutation_scope(&prepared)?;
    if !confirm_execution(&prepared)? {
        return output::print_cancelled(prepared.settings.ui);
    }
    prepared.revalidate(&session)?;
    execute_human_plan(prepared, session)
}

fn run_human_preview(prepared: &PreparedClean) -> Result<()> {
    output::print_plan(prepared)?;
    print_preview_next(prepared)
}

fn print_preview_next(prepared: &PreparedClean) -> Result<()> {
    next_action::print(Request {
        output: OutputMode::Human(prepared.settings.ui),
        workflow: Workflow::CleanPreview(CleanPreviewState {
            scope: &prepared.scope,
            planned: prepared.plan.items().len(),
        }),
        home: Some(&prepared.ctx.home),
    })
}

fn confirm_execution(prepared: &PreparedClean) -> Result<bool> {
    if !prepared.settings.yes
        && !confirm_required("clean requires --yes or --dry-run when stdin is not a terminal")?
    {
        return Ok(false);
    }
    Ok(true)
}

fn execute_human_plan(prepared: PreparedClean, session: MutationSession) -> Result<()> {
    stop_if_stdout_closed()?;
    let started = std::time::Instant::now();
    let recheck = boundary_recheck(&prepared, &session);
    let executed = session.execute_clean(&prepared.plan, &recheck);
    let elapsed = started.elapsed();
    let failed = executed.iter().any(CleanExecution::failed);
    let output_result = output::print_execution(&prepared, &executed, Some(elapsed))
        .and_then(|()| print_result_next(&prepared, &executed));
    ensure_clean_success(failed)?;
    output_result
}

fn print_result_next(
    prepared: &PreparedClean,
    executed: &[crate::lifecycle::CleanExecution],
) -> Result<()> {
    let trash_locations = executed
        .iter()
        .filter(|item| item.has_trash_location())
        .count();
    next_action::print(Request {
        output: OutputMode::Human(prepared.settings.ui),
        workflow: Workflow::CleanResult(CleanResultState { trash_locations }),
        home: None,
    })
}

fn ensure_clean_success(failed: bool) -> Result<()> {
    if failed {
        anyhow::bail!("one or more clean locations failed");
    }
    Ok(())
}
