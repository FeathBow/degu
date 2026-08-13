mod execution;
mod plan;
mod production;
mod purge;
#[cfg(test)]
mod tests;

use crate::lifecycle::trash::Trash;
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use std::path::{Path, PathBuf};

use super::EntryIdentity;
use super::claims::prepare_claims_dir;
use super::journal::OperationLog;
use super::storage::{
    ensure_managed_trash_root, register_trash_root, resolve_trash_dir, trash_dir_state,
};
use execution::{CleanFailure, StageRequest, record_clean_failure, stage_finding_with_log};

pub(crate) use execution::{CleanExecution, CleanExecutionFailure, cleaned_resources};
pub(crate) use plan::CapturedCleanPlan;

pub(crate) fn execute_clean(
    ctx: &DetectCtx,
    plan: &CapturedCleanPlan,
    purge: bool,
    recheck: &dyn Fn(&Finding) -> Result<(), String>,
    sealed_staging: Option<&mut degu_core::sealed_staging::ReadyStagingEngine>,
    retained_purge_authorities: &mut Vec<degu_core::sealed_staging::PurgeAuthority>,
) -> anyhow::Result<Vec<CleanExecution>> {
    let reclamation_id = reclamation_id();
    if let Some(engine) = sealed_staging {
        let mut run = production::ProductionRun {
            ctx,
            log: OperationLog::new(ctx),
            reclamation_id,
            recheck,
            engine,
            purge,
            retained_purge_authorities,
        };
        let mut executed = Vec::with_capacity(plan.items().len());
        let mut blocked = false;
        for (finding, identity) in plan.items_with_identities() {
            if blocked {
                // A prior item poisoned the WAL lease for the rest of this run;
                // report each remaining finding as not attempted rather than
                // silently dropping it from the results.
                executed.push(CleanExecution::plain_stage_failed(
                    finding,
                    "sealed-staging recovery was blocked earlier in this run; not attempted"
                        .to_string(),
                ));
                continue;
            }
            let outcome = production::execute(&mut run, finding, identity);
            blocked = outcome.recovery_blocked;
            executed.push(outcome.execution);
        }
        return Ok(executed);
    }

    let run = CleanRun {
        ctx,
        log: OperationLog::new(ctx),
        reclamation_id,
        purge,
        recheck,
    };
    Ok(plan
        .items_with_identities()
        .map(|(finding, identity)| execute_finding(&run, finding, identity))
        .collect())
}

struct CleanRun<'a> {
    ctx: &'a DetectCtx,
    log: OperationLog,
    reclamation_id: String,
    purge: bool,
    recheck: &'a dyn Fn(&Finding) -> Result<(), String>,
}

fn execute_finding(
    run: &CleanRun<'_>,
    finding: &Finding,
    identity: &EntryIdentity,
) -> CleanExecution {
    let span = tracing::info_span!(target: "degu", "clean", path = %finding.path().display());
    let _guard = span.enter();
    let trash_root = match prepare_trash_root(run.ctx, finding.path()) {
        Ok(root) => root,
        Err(reason) => return record_failure(run, finding, reason),
    };
    let trash = Trash::new(trash_root.clone());
    let entry = match trash.reserve(finding.path()) {
        Ok(entry) => entry,
        Err(err) => return record_failure(run, finding, err.to_string()),
    };
    let mut append = |record: &degu_core::oplog::OpRecord| run.log.append(record);
    let request = StageRequest {
        trash: &trash,
        finding,
        identity,
        entry,
        reclamation_id: &run.reclamation_id,
    };
    let staged = stage_finding_with_log(request, &mut append, run.recheck);
    let item = if run.purge {
        purge::execute(run.ctx, staged)
    } else {
        staged.finish()
    };
    trace_execution(&item);
    item
}

fn prepare_trash_root(ctx: &DetectCtx, path: &Path) -> Result<PathBuf, String> {
    let trash_root = resolve_trash_dir(ctx, path)?;
    let cross_device = trash_root != trash_dir_state(ctx);
    let expected_name = if cross_device { ".degu-trash" } else { "trash" };
    let trash_root =
        ensure_managed_trash_root(&trash_root, expected_name).map_err(|error| error.to_string())?;
    prepare_claims_dir(&trash_root).map_err(|error| error.to_string())?;
    if cross_device {
        register_trash_root(&ctx.xdg_state(), &trash_root).map_err(|err| {
            format!(
                "failed to register trash root {}: {err}",
                trash_root.display()
            )
        })?;
    }
    Ok(trash_root)
}

fn record_failure(run: &CleanRun<'_>, finding: &Finding, reason: String) -> CleanExecution {
    record_clean_failure(CleanFailure {
        log: &run.log,
        finding,
        reason,
        reclamation_id: Some(run.reclamation_id.clone()),
    })
}

fn trace_execution(item: &CleanExecution) {
    let outcome = if item.failed() { "failed" } else { "ok" };
    tracing::info!(
        target: "degu",
        path = %item.path().display(),
        bytes_allocated = item.bytes_allocated(),
        outcome,
        final_log_append_failed = item.final_log_append_failed(),
        "clean item executed"
    );
}

fn reclamation_id() -> String {
    format!(
        "{}-{}",
        jiff::Timestamp::now().as_millisecond(),
        std::process::id()
    )
}
