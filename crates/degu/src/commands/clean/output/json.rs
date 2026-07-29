use super::super::preparation::PreparedClean;
use crate::output::stdoutln;
use anyhow::Result;

pub(crate) fn print(prepared: &PreparedClean) -> Result<()> {
    let (planned, excluded, omitted) = prepared_findings_json(prepared)?;
    let report = serde_json::json!({
        "completeness": completeness_label(prepared, omitted),
        "omitted": omitted,
        "planned": planned,
        "excluded": excluded,
        "executed": [],
        "opt_in": prepared.scope.include_review(),
    });
    stdoutln!("{}", serde_json::to_string_pretty(&report)?)
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
