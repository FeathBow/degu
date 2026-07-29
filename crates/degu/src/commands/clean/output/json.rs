use super::super::preparation::PreparedClean;
use crate::lifecycle::{CleanExecution, Lifecycle};
use crate::output::stdoutln;
use anyhow::Result;

pub(crate) fn print(prepared: &PreparedClean, executed: &[CleanExecution]) -> Result<()> {
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

fn execution_json(item: &CleanExecution) -> Result<serde_json::Value> {
    let path = serde_json::to_value(item.path())?;
    let trash_entry = serde_json::to_value(item.trash_entry())?;
    Ok(serde_json::json!({
        "path": path,
        "trash_entry": trash_entry,
        "state": item.state_label(),
        "outcome": outcome_json(item),
    }))
}

fn outcome_json(item: &CleanExecution) -> serde_json::Value {
    match item.failure_reason() {
        None => serde_json::json!("ok"),
        Some(reason) => serde_json::json!({ "failed": { "reason": reason } }),
    }
}
