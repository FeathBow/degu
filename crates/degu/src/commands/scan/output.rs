use super::ScanReport;
use crate::output::stdoutln;
use anyhow::Result;
use degu_core::finding::Finding;

pub(super) fn print(report: &ScanReport) -> Result<()> {
    if report.json {
        print_json(report)?;
        return Ok(());
    }
    Ok(())
}

fn print_json(report: &ScanReport) -> Result<()> {
    stdoutln!("{}", serde_json::to_string_pretty(&json_document(report)?)?)
}

fn json_document(report: &ScanReport) -> Result<serde_json::Value> {
    let (findings, findings_dropped) = representable_findings(&report.findings);
    let (runtime, runtime_dropped) = representable_findings(&report.runtime_findings);
    if findings_dropped + runtime_dropped > 0 {
        tracing::warn!(
            findings_dropped,
            runtime_dropped,
            "omitted findings whose path is not valid UTF-8; report marked incomplete"
        );
    }
    Ok(serde_json::json!({
        "findings": serde_json::to_value(&findings)?,
        "runtime": serde_json::to_value(&runtime)?,
        "completeness": {
            "findings": section_completeness(report.completeness.findings, findings_dropped),
            "runtime": section_completeness(report.completeness.runtime, runtime_dropped),
        },
    }))
}

/// One finding with a non-UTF-8 path would fail the whole array's serialization,
/// losing every finding. Such paths are omitted (and counted) so the rest of the
/// report survives -- fail closed: an unrepresentable finding is never emitted.
fn representable_findings(findings: &[Finding]) -> (Vec<&Finding>, usize) {
    let mut representable = Vec::with_capacity(findings.len());
    let mut dropped = 0;
    for finding in findings {
        if finding.path().to_str().is_some() {
            representable.push(finding);
        } else {
            dropped += 1;
        }
    }
    (representable, dropped)
}

/// An omitted finding downgrades a `complete` section to `incomplete`; a section
/// already truncated or incomplete keeps its stronger signal.
fn section_completeness(status: crate::collection::ScanStatus, dropped: usize) -> &'static str {
    if dropped > 0 && !status.is_truncated() && !status.is_incomplete() {
        "incomplete"
    } else {
        status.as_str()
    }
}
