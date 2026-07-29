use super::output;
use super::preparation::PreparedClean;
use crate::commands::next_action::{
    self, CleanPreviewState, CleanResultState, OutputMode, Request, Workflow,
};
use crate::commands::prompt::{confirm_permanent_delete, confirm_required};
use crate::lifecycle::{CleanExecution, ExpiryPlan, Lifecycle, MutationSession, PurgeReport};
use anyhow::Result;
use degu_core::finding::Finding;

pub(super) struct ExpiryExecution {
    pub(super) plan: ExpiryPlan,
    pub(super) report: Option<PurgeReport>,
}

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
        let expiry = ExpiryExecution {
            plan: Lifecycle::new(&prepared.ctx).plan_expired()?,
            report: None,
        };
        return output::print_json(&prepared, &[], &expiry);
    }
    let session = prepared.lock()?;
    output::validate_json_prepared(&prepared)?;
    let plan = session.plan_expired()?;
    output::validate_json_expiry(&plan)?;
    prepared.revalidate(&session)?;
    stop_if_stdout_closed()?;
    let recheck = boundary_recheck(&prepared, &session);
    let executed = session.execute_clean(&prepared.plan, prepared.settings.purge, &recheck);
    let clean_failed = executed.iter().any(CleanExecution::failed);
    let report = (!clean_failed).then(|| session.execute_expiry(&plan));
    let expiry = ExpiryExecution { plan, report };
    let output_result = output::print_json(&prepared, &executed, &expiry);
    ensure_clean_success(clean_failed)?;
    ensure_expiry_success(&expiry)?;
    output_result
}

fn run_human(prepared: PreparedClean) -> Result<()> {
    if prepared.settings.dry_run {
        return run_human_preview(&prepared);
    }
    if prepared.plan.items().is_empty() && Lifecycle::new(&prepared.ctx).plan_expired()?.is_empty()
    {
        return output::print_plan(&prepared);
    }
    let session = prepared.lock()?;
    let expiry_plan = session.plan_expired()?;
    output::print_plan(&prepared)?;
    output::print_mutation_scope(&prepared, &expiry_plan)?;
    if prepared.plan.items().is_empty() && expiry_plan.is_empty() {
        return Ok(());
    }
    let permanent = permanent_deletion_planned(&prepared, &expiry_plan);
    if !confirm_execution(&prepared, &expiry_plan)? {
        let output_result = output::print_cancelled(prepared.settings.ui);
        if permanent {
            anyhow::bail!("permanent deletion cancelled; no clean or purge changes were made");
        }
        return output_result;
    }
    prepared.revalidate(&session)?;
    execute_human_plan(prepared, session, expiry_plan)
}

fn run_human_preview(prepared: &PreparedClean) -> Result<()> {
    let expiry_plan = Lifecycle::new(&prepared.ctx).plan_expired()?;
    output::print_plan(prepared)?;
    output::print_expiry_plan(&expiry_plan, prepared, true)?;
    print_preview_next(prepared)
}

fn print_preview_next(prepared: &PreparedClean) -> Result<()> {
    next_action::print(Request {
        output: OutputMode::Human(prepared.settings.ui),
        workflow: Workflow::CleanPreview(CleanPreviewState {
            scope: &prepared.scope,
            planned: prepared.plan.items().len(),
            direct_purge_requested: prepared.settings.purge,
        }),
        home: Some(&prepared.ctx.home),
    })
}

fn confirm_execution(prepared: &PreparedClean, expiry: &ExpiryPlan) -> Result<bool> {
    if !prepared.settings.yes
        && !confirm_required("clean requires --yes or --dry-run when stdin is not a terminal")?
    {
        return Ok(false);
    }
    let permanent = permanent_deletion_planned(prepared, expiry);
    if permanent
        && !prepared.settings.yes
        && !confirm_permanent_delete(prepared.settings.ui.colors)?
    {
        return Ok(false);
    }
    Ok(true)
}

fn permanent_deletion_planned(prepared: &PreparedClean, expiry: &ExpiryPlan) -> bool {
    (prepared.settings.purge && !prepared.plan.items().is_empty()) || !expiry.is_empty()
}

fn execute_human_plan(
    prepared: PreparedClean,
    session: MutationSession,
    plan: ExpiryPlan,
) -> Result<()> {
    stop_if_stdout_closed()?;
    let started = std::time::Instant::now();
    let recheck = boundary_recheck(&prepared, &session);
    let executed = session.execute_clean(&prepared.plan, prepared.settings.purge, &recheck);
    let elapsed = started.elapsed();
    let failed = executed.iter().any(CleanExecution::failed);
    let expiry = ExpiryExecution {
        report: (!failed).then(|| session.execute_expiry(&plan)),
        plan,
    };
    let output_result = output::print_execution(&prepared, &executed, Some(elapsed))
        .and_then(|()| {
            if failed {
                Ok(())
            } else {
                output::print_expiry(&expiry, prepared.settings.ui.colors)
            }
        })
        .and_then(|()| print_result_next(&prepared, &executed));
    ensure_clean_success(failed)?;
    ensure_expiry_success(&expiry)?;
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

fn ensure_expiry_success(expiry: &ExpiryExecution) -> Result<()> {
    if expiry
        .report
        .as_ref()
        .is_some_and(|report| !report.failed.is_empty())
    {
        anyhow::bail!("one or more expired trash entries failed to purge");
    }
    Ok(())
}
