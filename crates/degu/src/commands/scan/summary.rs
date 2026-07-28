mod output;

use super::ScanReport;
use crate::collection::ScanStatus;
use crate::output::stdoutln;
use anyhow::Result;
use degu_core::finding::Finding;
use std::collections::HashMap;

#[derive(Debug)]
struct SourceRow {
    ecosystem: String,
    bytes_allocated: u64,
    bytes_hardlinked: u64,
    inodes: u64,
    share: f64,
    lower_bound: bool,
}

#[derive(Default)]
struct SourceAggregate {
    bytes_allocated: u64,
    bytes_hardlinked: u64,
    inodes: u64,
    lower_bound: bool,
}

impl SourceAggregate {
    fn new(lower_bound: bool) -> Self {
        Self {
            lower_bound,
            ..Self::default()
        }
    }

    fn add(&mut self, finding: &Finding) {
        self.bytes_allocated = self
            .bytes_allocated
            .saturating_add(finding.bytes_allocated());
        self.bytes_hardlinked = self
            .bytes_hardlinked
            .saturating_add(finding.bytes_hardlinked());
        self.inodes = self.inodes.saturating_add(finding.inodes());
        self.lower_bound |= finding.measurement_incomplete();
    }
}

#[derive(Debug)]
struct SourceSummary {
    total_bytes_allocated: u64,
    total_bytes_hardlinked: u64,
    total_inodes: u64,
    ecosystems: Vec<SourceRow>,
    incomplete: bool,
    lower_bound: bool,
    truncated: bool,
}

pub(super) fn print(scan: &ScanReport) -> Result<()> {
    let summary = source_summary(&scan.findings, scan.completeness.findings);
    let runtime = source_summary(&scan.runtime_findings, scan.completeness.runtime);
    if scan.json {
        stdoutln!(
            "{}",
            serde_json::to_string_pretty(&summary_json(&summary, &runtime))?
        )?;
        return Ok(());
    }
    if scan.completeness.findings.is_requested() {
        output::print_summary(&summary, scan.ui)?;
    }
    if scan.completeness.runtime.is_requested() {
        output::print_runtime_summary(&runtime, scan.ui)?;
    }
    output::print_completion_notes(output::CompletionNotes {
        truncated: scan.truncated(),
        incomplete: summary.incomplete || runtime.incomplete,
        unvisited_dirs: scan.completeness.unvisited_dirs(),
        ui: scan.ui,
    })
}

fn source_summary(findings: &[Finding], status: ScanStatus) -> SourceSummary {
    let lower_bound = status.is_lower_bound();
    let mut by_ecosystem = HashMap::<String, SourceAggregate>::new();
    let mut total = SourceAggregate::new(lower_bound);
    let incomplete = status.is_incomplete();
    let truncated = status.is_truncated();
    for finding in findings {
        let entry = by_ecosystem
            .entry(finding.ecosystem().to_owned())
            .or_insert_with(|| SourceAggregate::new(lower_bound));
        entry.add(finding);
        total.add(finding);
    }
    let mut ecosystems = by_ecosystem
        .into_iter()
        .map(|(ecosystem, aggregate)| SourceRow {
            ecosystem,
            bytes_allocated: aggregate.bytes_allocated,
            bytes_hardlinked: aggregate.bytes_hardlinked,
            inodes: aggregate.inodes,
            share: source_share(aggregate.bytes_allocated, total.bytes_allocated),
            lower_bound: aggregate.lower_bound,
        })
        .collect::<Vec<_>>();
    sort_rows(&mut ecosystems);
    SourceSummary {
        total_bytes_allocated: total.bytes_allocated,
        total_bytes_hardlinked: total.bytes_hardlinked,
        total_inodes: total.inodes,
        ecosystems,
        incomplete,
        lower_bound: total.lower_bound,
        truncated,
    }
}

fn source_share(bytes_allocated: u64, total_bytes_allocated: u64) -> f64 {
    if total_bytes_allocated == 0 {
        0.0
    } else {
        bytes_allocated as f64 / total_bytes_allocated as f64
    }
}

fn sort_rows(rows: &mut [SourceRow]) {
    rows.sort_by(|left, right| {
        right
            .bytes_allocated
            .cmp(&left.bytes_allocated)
            .then_with(|| left.ecosystem.cmp(&right.ecosystem))
    });
}

fn summary_json(report: &SourceSummary, runtime: &SourceSummary) -> serde_json::Value {
    serde_json::json!({
        "total": total_json(report),
        "ecosystems": ecosystems_json(report),
        "runtime": {
            "ecosystems": ecosystems_json(runtime),
            "total": total_json(runtime),
        },
        "truncated": report.truncated || runtime.truncated,
    })
}

fn total_json(report: &SourceSummary) -> serde_json::Value {
    serde_json::json!({
        "bytes_allocated": report.total_bytes_allocated,
        "bytes_hardlinked": report.total_bytes_hardlinked,
        "inodes": report.total_inodes,
        "lower_bound": report.lower_bound,
    })
}

fn ecosystems_json(report: &SourceSummary) -> Vec<serde_json::Value> {
    report
        .ecosystems
        .iter()
        .map(|row| {
            serde_json::json!({
                "ecosystem": row.ecosystem,
                "bytes_allocated": row.bytes_allocated,
                "bytes_hardlinked": row.bytes_hardlinked,
                "inodes": row.inodes,
                "lower_bound": row.lower_bound,
                "share": row.share,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
