use super::ScanReport;
use crate::commands::next_action::{self, OutputMode, Request, ScanState, Workflow};
use crate::finding_filter::FilteredFinding;
use crate::findings_table::{self, print as print_findings_table};
use crate::lifecycle::Lifecycle;
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    cleanup, lower_bound_bytes, print_scan_footer, print_scan_incomplete_warning, semantic,
};
use crate::runtime::{Headline, HeadlineLead, Ui};
use anyhow::Result;
use degu_core::finding::{DispositionMode, Finding};
use std::path::Path;

mod findings;

const PROJECT_SCOPE_LABEL: &str =
    "Scan build artifacts under this project, or any parent directory:";
const PROJECT_SCOPE_COMMAND: &str = "degu scan .";
const UNMANAGED_ARTIFACTS_HINT: &str =
    "Rerun with --details for each Not managed location's full reason.";
const FOLDED_LOCATIONS_HINT: &str = "Rerun with --details to list every location.";

pub(super) fn print(report: &ScanReport) -> Result<()> {
    if report.json {
        if report.summary {
            super::summary::print(report)?;
        } else {
            print_json(report)?;
        }
        return Ok(());
    }
    if report.summary {
        super::summary::print(report)?;
    } else {
        print_human(report)?;
    }
    let trash_entries = print_trash_summary(&report.ctx, report.ui)?;
    let guidance = next_action::resolve(Request {
        output: OutputMode::Human(report.ui),
        workflow: Workflow::Scan(ScanState {
            scope: &report.scope,
            trash_entries,
            completeness: report.completeness,
            needs_review: has_needs_review_findings(report),
            has_effective_project_roots: report.has_effective_project_roots,
        }),
        home: Some(&report.ctx.home),
    });
    if !report.summary {
        print_details_hint(report)?;
    }
    print_project_scope_note(report, &guidance)?;
    guidance.print()
}

fn print_scan_incomplete(report: &ScanReport) -> Result<()> {
    let marked_totals = (!report.findings.is_empty() && report.findings_lower_bound())
        || (!report.runtime_findings.is_empty() && report.runtime_lower_bound());
    print_scan_incomplete_warning(report.is_lower_bound(), marked_totals, report.ui)
}

/// The one end-of-report pointer at --details. A report with folded tiers
/// needs the complete listing, and an explicitly rooted scan whose
/// artifacts stay out of "Ready to clean" needs the full reasons; the
/// details view carries both, so when the two cases coincide only the
/// folded-locations wording prints.
fn print_details_hint(report: &ScanReport) -> Result<()> {
    let hint = if findings::any_tier_folds(report) {
        FOLDED_LOCATIONS_HINT
    } else if has_unmanaged_artifacts_to_explain(report) {
        UNMANAGED_ARTIFACTS_HINT
    } else {
        return Ok(());
    };
    stdoutln!(
        "\n{}",
        semantic::paint(
            report.ui.prose(hint),
            Tone::Secondary,
            report.ui.colors.stdout
        )
    )
}

fn has_unmanaged_artifacts_to_explain(report: &ScanReport) -> bool {
    !report.details
        && report.scope.has_explicit_roots()
        && report.findings.iter().any(|finding| {
            finding.ecosystem() == "artifacts"
                && finding.disposition().mode == DispositionMode::ReportOnly
        })
}

fn print_project_scope_note(report: &ScanReport, guidance: &next_action::Guidance) -> Result<()> {
    if report.truncated()
        || report.has_effective_project_roots
        || !report.scope.includes_project_sources()
        || guidance.project_scan_is_next()
    {
        return Ok(());
    }
    stdoutln!(
        "{}",
        report.ui.section(&report.ui.command_block(
            &semantic::paint(
                report.ui.prose(PROJECT_SCOPE_LABEL),
                Tone::Accent,
                report.ui.colors.stdout
            ),
            &semantic::paint(PROJECT_SCOPE_COMMAND, Tone::Accent, report.ui.colors.stdout),
        ))
    )
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

fn print_human(report: &ScanReport) -> Result<()> {
    let not_managed_explained = if report.completeness.findings.is_requested() {
        findings::print(report)?
    } else {
        print_scan_incomplete(report)?;
        false
    };
    if report.completeness.runtime.is_requested() {
        if report.completeness.findings.is_requested() {
            stdoutln!("")?;
        }
        print_runtime(RuntimeSection {
            findings: &report.runtime_findings,
            hidden: &report.runtime_hidden,
            details: report.details,
            lower_bound: report.runtime_lower_bound(),
            home: &report.ctx.home,
            ui: report.ui,
            explain_not_managed: !not_managed_explained,
        })?;
    }
    print_scan_footer(
        report.truncated(),
        report.completeness.unvisited_dirs(),
        report.ui,
    )
}

fn print_trash_summary(ctx: &degu_core::ecosystem::DetectCtx, ui: Ui) -> Result<usize> {
    if let Some(summary) = Lifecycle::new(ctx).trash_summary()? {
        stdoutln!(
            "{}",
            ui.section(&render_trash_summary(
                summary.bytes_allocated,
                summary.entries,
                summary.bytes_hardlinked,
                summary.entries_lower_bound,
                summary.bytes_lower_bound,
                ui
            ))
        )?;
        return Ok(summary.entries);
    }
    Ok(0)
}

fn render_trash_summary(
    bytes_allocated: u64,
    entries: usize,
    bytes_hardlinked: u64,
    entries_lower_bound: bool,
    bytes_lower_bound: bool,
    ui: Ui,
) -> String {
    // A budget that expires before any entry is enumerated leaves nothing to
    // lower-bound; reporting zero would read as a near-empty trash rather than
    // an unmeasured one.
    if entries_lower_bound && entries == 0 {
        return ui.prose("Trash size unknown (scan budget reached).");
    }
    let mut sentence = format!(
        "Trash holds {} across {}.",
        lower_bound_bytes(bytes_lower_bound, bytes_allocated, ui.glyphs),
        cleanup::lower_bound_count_label(
            entries_lower_bound,
            entries,
            "entry",
            "entries",
            ui.glyphs
        )
    );
    if bytes_hardlinked > 0 {
        sentence.push_str(&format!(
            " {} is hardlink-shared; reclaimed space may be lower.",
            lower_bound_bytes(bytes_lower_bound, bytes_hardlinked, ui.glyphs)
        ));
    }
    ui.prose(&sentence)
}

/// Artifacts are cleanable only under explicit roots: bare clean never
/// receives config-discovered project roots, so Eligible artifacts from a
/// bare scan must not be promised as cleanable anywhere in the output.
fn is_cleanable(finding: &Finding, report: &ScanReport) -> bool {
    finding.disposition().mode == DispositionMode::Eligible
        && (finding.ecosystem() != "artifacts" || report.scope.has_explicit_roots())
}

fn has_needs_review_findings(report: &ScanReport) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.disposition().mode == DispositionMode::OptIn)
}

struct RuntimeSection<'a> {
    findings: &'a [Finding],
    hidden: &'a [FilteredFinding],
    details: bool,
    lower_bound: bool,
    home: &'a Path,
    ui: Ui,
    explain_not_managed: bool,
}

fn print_runtime(section: RuntimeSection<'_>) -> Result<()> {
    if section.findings.is_empty() {
        stdoutln!(
            "{}",
            section.ui.toned_prose(
                0,
                crate::commands::scan::NO_RUNTIME_LOCATIONS_DETECTED,
                Tone::Secondary
            )
        )?;
        return print_hidden_summary(section.hidden, section.ui);
    }
    print_runtime_heading(&section)?;
    print_findings_table(
        section.findings,
        findings_table::FindingsTableOptions::new(section.ui, section.details, section.home)
            .for_disposition(DispositionMode::ReportOnly),
    )?;
    print_runtime_total(&section)?;
    print_hidden_summary(section.hidden, section.ui)
}

fn print_runtime_heading(section: &RuntimeSection<'_>) -> Result<()> {
    stdoutln!(
        "{}",
        section
            .ui
            .toned_prose(0, "node-runtime (Not managed):", Tone::Heading)
    )?;
    if section.explain_not_managed
        && let Some(explanation) = cleanup::explanation(DispositionMode::ReportOnly)
    {
        stdoutln!(
            "{}",
            section.ui.toned_prose(0, explanation, Tone::Secondary)
        )?;
    }
    Ok(())
}

fn print_runtime_total(section: &RuntimeSection<'_>) -> Result<()> {
    let stats = cleanup::FindingStats::from_findings(section.findings);
    stdoutln!(
        "{}",
        section.ui.toned_prose(
            0,
            &format!(
                "Total node-runtime: {}",
                stats.bytes_label(section.lower_bound, section.ui.glyphs)
            ),
            Tone::Heading
        )
    )
}

fn print_hidden_summary(hidden: &[FilteredFinding], ui: Ui) -> Result<()> {
    if hidden.is_empty() {
        return Ok(());
    }
    let bytes = hidden.iter().fold(0u64, |total, filtered| {
        total.saturating_add(filtered.finding.bytes_allocated())
    });
    let lower_bound = hidden
        .iter()
        .any(|filtered| filtered.finding.measurement_incomplete());
    stdoutln!(
        "{}",
        ui.headline(
            Headline::new("Hidden by filters", HeadlineLead::Colon)
                .stat(cleanup::count_label(hidden.len(), "location", "locations"))
                .stat(lower_bound_bytes(lower_bound, bytes, ui.glyphs))
        )
    )
}

#[cfg(test)]
mod tests;
