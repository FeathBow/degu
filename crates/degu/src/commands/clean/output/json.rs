use super::super::execution::{CleanQuotaObservations, ExpiryExecution};
use super::super::preparation::PreparedClean;
use crate::lifecycle::{CleanExecution, ExpiryPlan, Lifecycle, TRASH_RETENTION_DAYS};
use crate::output::stdoutln;
use anyhow::Result;
use std::path::PathBuf;

pub(crate) fn print(
    prepared: &PreparedClean,
    executed: &[CleanExecution],
    expiry: &ExpiryExecution,
    observations: &CleanQuotaObservations,
) -> Result<()> {
    let (planned, excluded, omitted) = prepared_findings_json(prepared)?;
    let executed = executed
        .iter()
        .map(execution_json)
        .collect::<Result<Vec<_>>>()?;
    let report = serde_json::json!({
        "completeness": completeness_label(prepared, omitted),
        "omitted": omitted,
        "planned": planned,
        "excluded": excluded,
        "executed": executed,
        "opt_in": prepared.scope.include_review(),
        "expiry": expiry_json(expiry)?,
        "quota_observations": {
            "direct_purge": crate::quota_observation::json(&observations.direct_purge),
            "expiry_purge": crate::quota_observation::json(&expiry.observation),
        },
    });
    stdoutln!("{}", serde_json::to_string_pretty(&report)?)
}

pub(crate) fn validate_prepared(prepared: &PreparedClean) -> Result<()> {
    let _ = prepared_findings_json(prepared)?;
    let lifecycle = Lifecycle::new(&prepared.ctx);
    for finding in prepared.plan.items() {
        let trash_dir = lifecycle
            .resolve_trash_dir(finding.path())
            .map_err(anyhow::Error::msg)?;
        let _ = serde_json::to_value(trash_dir)?;
    }
    Ok(())
}

pub(crate) fn validate_expiry(plan: &ExpiryPlan) -> Result<()> {
    let _ = expiry_plan_json(plan)?;
    let roots = plan.trash_roots().collect::<Vec<_>>();
    let _ = serde_json::to_value(roots)?;
    Ok(())
}

fn prepared_findings_json(
    prepared: &PreparedClean,
) -> Result<(serde_json::Value, serde_json::Value, usize)> {
    // Plan items are already representable (partitioned at prepare time); the
    // exclusions are not, so drop any non-UTF-8 path here too rather than fail
    // the whole document.
    let mut excluded = Vec::new();
    let mut excluded_omitted = 0usize;
    for finding in prepared.exclusions.iter() {
        if finding.path().to_str().is_some() {
            excluded.push(finding);
        } else {
            excluded_omitted += 1;
        }
    }
    Ok((
        serde_json::to_value(prepared.plan.items())?,
        serde_json::to_value(excluded)?,
        prepared.unrepresentable + excluded_omitted,
    ))
}

fn completeness_label(prepared: &PreparedClean, omitted: usize) -> &'static str {
    if omitted > 0 && !prepared.scan_status.is_truncated() && !prepared.scan_status.is_incomplete()
    {
        "incomplete"
    } else {
        prepared.scan_status.as_str()
    }
}

fn expiry_json(expiry: &ExpiryExecution) -> Result<serde_json::Value> {
    let planned = expiry_plan_json(&expiry.plan)?;
    let report = expiry.report.as_ref();
    let purged = report.map_or(&[][..], |report| report.purged.as_slice());
    let failed = match report {
        Some(report) => report
            .failed
            .iter()
            .map(expiry_failure_json)
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let purged = serde_json::to_value(purged)?;
    Ok(serde_json::json!({
        "retention_days": TRASH_RETENTION_DAYS,
        "attempted": report.is_some(),
        "planned": planned,
        "purged": purged,
        "failed": failed,
    }))
}

fn expiry_plan_json(plan: &ExpiryPlan) -> Result<serde_json::Value> {
    let entries = plan.entries().collect::<Vec<_>>();
    Ok(serde_json::to_value(entries)?)
}

fn expiry_failure_json(failure: &(PathBuf, String)) -> Result<serde_json::Value> {
    let path = serde_json::to_value(&failure.0)?;
    Ok(serde_json::json!({
        "path": path,
        "reason": &failure.1,
    }))
}

fn execution_json(item: &CleanExecution) -> Result<serde_json::Value> {
    let path = serde_json::to_value(item.path())?;
    let trash_entry = serde_json::to_value(item.trash_entry())?;
    Ok(serde_json::json!({
        "path": path,
        "trash_entry": trash_entry,
        "state": item.state_label(),
        "outcome": outcome_json(item),
        "purged": item.purged(),
    }))
}

fn outcome_json(item: &CleanExecution) -> serde_json::Value {
    match item.failure_reason() {
        None => serde_json::json!("ok"),
        Some(reason) => serde_json::json!({ "failed": { "reason": reason } }),
    }
}
