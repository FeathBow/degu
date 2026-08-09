use super::output;
use super::preparation::PreparedClean;
use crate::action_result::{ActionKind, ActionResultOwner, NotStartedReason, StartedActionOutcome};
use crate::commands::next_action::{
    self, CleanPreviewState, CleanResultState, OutputMode, Request, Workflow,
};
use crate::commands::prompt::{confirm_permanent_delete, confirm_required};
use crate::lifecycle::{CleanExecution, ExpiryPlan, Lifecycle, MutationSession, PurgeReport};
use crate::quota_observation::{
    QuotaActionReport, coordinate, not_attempted_action, planned_action,
};
use anyhow::Result;
use degu_core::finding::Finding;
use std::path::PathBuf;

pub(super) struct ExpiryExecution {
    pub(super) plan: ExpiryPlan,
    pub(super) report: Option<PurgeReport>,
    pub(super) observation: QuotaActionReport,
}

pub(super) struct CleanQuotaObservations {
    pub(super) direct_purge: QuotaActionReport,
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
        let plan = Lifecycle::new(&prepared.ctx).plan_expired()?;
        let expiry_observation = not_attempted_action(
            ActionResultOwner::CleanCommand,
            ActionKind::ExpiryPurge,
            "clean:expiry-purge",
            plan.trash_roots().map(PathBuf::from),
            NotStartedReason::DryRun,
        )
        .map_err(|error| anyhow::anyhow!("invalid expiry observation contract: {error:?}"))?;
        let expiry = ExpiryExecution {
            plan,
            report: None,
            observation: expiry_observation,
        };
        let direct_purge = not_attempted_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "clean:direct-purge",
            [],
            NotStartedReason::DryRun,
        )
        .map_err(|error| anyhow::anyhow!("invalid direct observation contract: {error:?}"))?;
        return output::print_json(
            &prepared,
            &[],
            &expiry,
            &CleanQuotaObservations { direct_purge },
        );
    }
    let session = prepared.lock()?;
    output::validate_json_prepared(&prepared)?;
    let plan = session.plan_expired()?;
    output::validate_json_expiry(&plan)?;
    prepared.revalidate(&session)?;
    stop_if_stdout_closed()?;
    let recheck = boundary_recheck(&prepared, &session);
    let (executed, direct_purge) = execute_clean(&prepared, &session, &recheck)?;
    let clean_failed = executed.iter().any(CleanExecution::failed);
    let expiry = execute_expiry(&session, plan, clean_failed)?;
    let direct_purge = match direct_purge {
        Some(observation) => observation,
        None => not_attempted_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "clean:direct-purge",
            [],
            NotStartedReason::Empty,
        )
        .map_err(|error| anyhow::anyhow!("invalid direct observation contract: {error:?}"))?,
    };
    let observations = CleanQuotaObservations { direct_purge };
    crate::quota_observation::print_warnings(
        &observations.direct_purge,
        prepared.settings.ui.colors,
    );
    crate::quota_observation::print_warnings(&expiry.observation, prepared.settings.ui.colors);
    let output_result = output::print_json(&prepared, &executed, &expiry, &observations);
    ensure_clean_success(clean_failed)?;
    ensure_expiry_success(&expiry)?;
    output_result
}

fn run_human(prepared: PreparedClean) -> Result<()> {
    if prepared.settings.dry_run {
        return run_human_preview(&prepared);
    }
    if prepared.plan.items().is_empty()
        && !Lifecycle::new(&prepared.ctx)
            .plan_expired()?
            .has_housekeeping_scope()
    {
        return output::print_plan(&prepared);
    }
    let session = prepared.lock()?;
    let expiry_plan = session.plan_expired()?;
    output::print_plan(&prepared)?;
    output::print_mutation_scope(&prepared, &expiry_plan)?;
    if prepared.plan.items().is_empty() && !expiry_plan.has_housekeeping_scope() {
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
    let (executed, direct_purge) = execute_clean(&prepared, &session, &recheck)?;
    let elapsed = started.elapsed();
    let failed = executed.iter().any(CleanExecution::failed);
    let expiry = execute_expiry(&session, plan, failed)?;
    let output_result = output::print_execution(&prepared, &executed, Some(elapsed))
        .and_then(|()| {
            if let Some(observation) = &direct_purge {
                crate::quota_observation::print_human(observation, prepared.settings.ui.colors)?;
            }
            if failed {
                Ok(())
            } else {
                output::print_expiry(&expiry, prepared.settings.ui.colors)?;
                crate::quota_observation::print_human(
                    &expiry.observation,
                    prepared.settings.ui.colors,
                )?;
                Ok(())
            }
        })
        .and_then(|()| print_result_next(&prepared, &executed));
    ensure_clean_success(failed)?;
    ensure_expiry_success(&expiry)?;
    output_result
}

/// The caller has completed final batch revalidation and the stdout boundary.
/// The per-finding recheck stays inside lifecycle execution immediately before
/// each mutation; moving it before the pre probe would only widen its race.
fn direct_observation_request(
    source: &std::path::Path,
    resolved: std::result::Result<PathBuf, String>,
) -> PathBuf {
    resolved
        .map(|root| root.parent().unwrap_or(&root).to_path_buf())
        .unwrap_or_else(|_| source.parent().unwrap_or(source).to_path_buf())
}

fn execute_clean(
    prepared: &PreparedClean,
    session: &MutationSession,
    recheck: &dyn Fn(&Finding) -> Result<(), String>,
) -> Result<(Vec<CleanExecution>, Option<QuotaActionReport>)> {
    if !prepared.settings.purge || prepared.plan.items().is_empty() {
        return Ok((
            session.execute_clean(&prepared.plan, prepared.settings.purge, recheck),
            None,
        ));
    }
    let lifecycle = Lifecycle::new(&prepared.ctx);
    let anchors = prepared
        .plan
        .items()
        .iter()
        .map(|finding| {
            // Observation discovery is reporting-only. A resolver failure must
            // not upgrade lifecycle's per-item failure into a batch setup
            // failure; retain a non-authoritative source-side request.
            direct_observation_request(finding.path(), lifecycle.resolve_trash_dir(finding.path()))
        })
        .collect::<Vec<_>>();
    let action = planned_action(
        ActionResultOwner::CleanCommand,
        ActionKind::DirectPurge,
        "clean:direct-purge",
        anchors,
    )
    .map_err(|error| anyhow::anyhow!("invalid direct-purge observation contract: {error:?}"))?;
    let mut probe = crate::quota::probe;
    let (executed, completed) = coordinate(action, &mut probe, || {
        let executed = session.execute_clean(&prepared.plan, true, recheck);
        let outcome = clean_outcome(&executed);
        (executed, outcome)
    });
    Ok((executed, Some(QuotaActionReport::Attempted(completed))))
}

fn execute_expiry(
    session: &MutationSession,
    plan: ExpiryPlan,
    clean_failed: bool,
) -> Result<ExpiryExecution> {
    if clean_failed {
        let observation = not_attempted_action(
            ActionResultOwner::CleanCommand,
            ActionKind::ExpiryPurge,
            "clean:expiry-purge",
            plan.trash_roots().map(PathBuf::from),
            NotStartedReason::PrerequisiteFailed,
        )
        .map_err(|error| anyhow::anyhow!("invalid expiry observation contract: {error:?}"))?;
        return Ok(ExpiryExecution {
            report: None,
            plan,
            observation,
        });
    }
    if !plan.has_housekeeping_scope() {
        let observation = not_attempted_action(
            ActionResultOwner::CleanCommand,
            ActionKind::ExpiryPurge,
            "clean:expiry-purge",
            [],
            NotStartedReason::Empty,
        )
        .map_err(|error| anyhow::anyhow!("invalid expiry observation contract: {error:?}"))?;
        return Ok(ExpiryExecution {
            report: Some(PurgeReport::default()),
            plan,
            observation,
        });
    }
    let action = planned_action(
        ActionResultOwner::CleanCommand,
        ActionKind::ExpiryPurge,
        "clean:expiry-purge",
        plan.trash_roots().map(PathBuf::from),
    )
    .map_err(|error| anyhow::anyhow!("invalid expiry observation contract: {error:?}"))?;
    let mut probe = crate::quota::probe;
    let (report, completed) = coordinate(action, &mut probe, || {
        let report = session.execute_expiry(&plan);
        let outcome = crate::commands::purge_outcome(&report);
        (report, outcome)
    });
    Ok(ExpiryExecution {
        plan,
        report: Some(report),
        observation: QuotaActionReport::Attempted(completed),
    })
}

fn clean_outcome(executed: &[CleanExecution]) -> StartedActionOutcome {
    let failures = executed.iter().filter(|item| item.failed()).count();
    match failures {
        0 => StartedActionOutcome::Success,
        count if count == executed.len() => StartedActionOutcome::Failure,
        _ => StartedActionOutcome::Partial,
    }
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

#[cfg(test)]
mod tests {
    use super::direct_observation_request;
    use std::path::{Path, PathBuf};

    #[test]
    fn direct_observation_discovery_keeps_failed_and_valid_items_in_the_batch() {
        let requests = [
            direct_observation_request(
                Path::new("/source/failed/cache"),
                Err("resolver failed".to_owned()),
            ),
            direct_observation_request(
                Path::new("/source/valid/cache"),
                Ok(PathBuf::from("/persistent/trash")),
            ),
        ];
        assert_eq!(
            requests,
            [
                PathBuf::from("/source/failed"),
                PathBuf::from("/persistent")
            ]
        );
    }
}
