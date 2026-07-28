use super::{ScanReport, print_hidden_summary};
use crate::findings_table::{FindingsTableOptions, print as print_findings_table};
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    WIDE_TABLE_MIN_WIDTH, any_hardlinked, cleanup, print_hardlink_summary, semantic,
};
use crate::runtime::{Headline, HeadlineLead, Ui};
use anyhow::Result;
use degu_core::finding::{DispositionMode, Finding};

const SECTION_ORDER: [DispositionMode; 3] = [
    DispositionMode::Eligible,
    DispositionMode::OptIn,
    DispositionMode::ReportOnly,
];

/// Longest tier tail rendered row by row before folding is considered.
const ROW_BUDGET: usize = 10;
/// A tier folds only when the fold line replaces at least this many rows; a
/// shorter tail reads faster as rows than behind a fold line.
const FOLD_MIN_SAVINGS: usize = 2;

pub(super) fn print(report: &ScanReport) -> Result<bool> {
    if report.findings.is_empty() {
        print_empty(report)?;
        return Ok(false);
    }
    print_populated(report)?;
    Ok(has_mode(&report.findings, DispositionMode::ReportOnly))
}

fn print_empty(report: &ScanReport) -> Result<()> {
    if report.scope.only_ids().is_empty() {
        stdoutln!(
            "{}",
            report.ui.prose(crate::commands::scan::NO_STORAGE_DETECTED)
        )?;
    } else {
        stdoutln!(
            "{}",
            report.ui.headline(
                Headline::new("No matching locations", HeadlineLead::Separator)
                    .stat(format!("Sources: {}", report.scope.only_ids().join(", ")))
            )
        )?;
    }
    super::print_scan_incomplete(report)?;
    print_hidden_summary(&report.hidden, report.ui)
}

fn print_populated(report: &ScanReport) -> Result<()> {
    print_headline(report)?;
    super::print_scan_incomplete(report)?;
    for mode in SECTION_ORDER {
        print_section(report, mode)?;
    }
    if has_trailing_notes(report) {
        stdoutln!("")?;
    }
    print_hidden_summary(&report.hidden, report.ui)?;
    print_hardlink_summary(&report.findings, report.findings_lower_bound(), report.ui)
}

/// Whether anything follows the findings tables inside the human report; a
/// blank line then separates the tables from that trailing notes block.
fn has_trailing_notes(report: &ScanReport) -> bool {
    !report.hidden.is_empty() || any_hardlinked(&report.findings) || report.truncated()
}

fn print_headline(report: &ScanReport) -> Result<()> {
    let total = cleanup::FindingStats::from_findings(&report.findings);
    let label = headline_label(
        format!(
            "{} detected across {}",
            total.bytes_label(report.findings_lower_bound(), report.ui.glyphs),
            total.locations_label()
        ),
        report.elapsed,
        report.ui,
    );
    let mut headline = Headline::new(label, HeadlineLead::Separator).label_tone(Tone::Heading);
    let ready = cleanup::FindingStats::collect(
        report
            .findings
            .iter()
            .filter(|finding| super::is_cleanable(finding, report)),
    );
    if ready.has_bytes() {
        headline = headline.stat_toned(
            format!(
                "{} ready to clean",
                ready.bytes_label(report.findings_lower_bound(), report.ui.glyphs)
            ),
            Tone::Ready,
        );
    }
    stdoutln!("{}", report.ui.headline(headline))
}

/// The headline with its " in <elapsed>" suffix while it fits the terminal
/// width; the duration is the most disposable field, so it is dropped
/// before the label would wrap mid-phrase (the field-dropping strategy of
/// the scan progress line). Piped output never carries the duration.
fn headline_label(
    base: String,
    elapsed: Option<std::time::Duration>,
    ui: crate::runtime::Ui,
) -> String {
    if !ui.stdout_is_terminal {
        return base;
    }
    let Some(elapsed) = elapsed else {
        return base;
    };
    let with_duration = format!("{base} in {}", crate::presentation::human_duration(elapsed));
    if unicode_width::UnicodeWidthStr::width(with_duration.as_str()) <= usize::from(ui.width) {
        with_duration
    } else {
        base
    }
}

fn print_section(report: &ScanReport, mode: DispositionMode) -> Result<()> {
    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.disposition().mode == mode)
        .cloned()
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return Ok(());
    }
    stdoutln!(
        "\n{}",
        cleanup::group_header(
            report.ui,
            cleanup::Group {
                label: cleanup::label(mode),
                mode,
                stats: cleanup::FindingStats::from_findings(&findings),
                scan_lower_bound: report.findings_lower_bound(),
                indent: 0,
            },
        )
    )?;
    if let Some(explanation) = cleanup::explanation(mode) {
        stdoutln!(
            "{}",
            semantic::paint(
                report.ui.prose(explanation),
                Tone::Secondary,
                report.ui.colors.stdout
            )
        )?;
    }
    // --details bypasses folding: the details view is the complete listing
    // the fold line points at.
    let (visible, folded) = if report.details {
        (findings.as_slice(), None)
    } else {
        fold_tail(&findings, ROW_BUDGET)
    };
    print_findings_table(
        visible,
        FindingsTableOptions::new(report.ui, report.details, &report.ctx.home)
            .for_disposition(mode),
    )?;
    print_fold_line(report, folded)
}

/// The tail a tier folds behind one line: the hidden rows plus their
/// aggregated stats, both cut from the same slice so the fold line can
/// never disagree with the rows it replaces.
struct FoldedTail<'a> {
    findings: &'a [Finding],
    stats: cleanup::FindingStats,
}

/// Pure fold split for one already-ranked tier: the visible head plus, when
/// folding pays for itself, the folded tail with its aggregated stats.
/// `rank_findings` orders findings bytes-descending, so the head always
/// holds the largest rows; the split never re-sorts. The runtime section
/// can adopt folding later by routing through this call.
fn fold_tail(findings: &[Finding], budget: usize) -> (&[Finding], Option<FoldedTail<'_>>) {
    if !folds(findings.len(), budget) {
        return (findings, None);
    }
    let (visible, tail) = findings.split_at(budget);
    (
        visible,
        Some(FoldedTail {
            findings: tail,
            stats: cleanup::FindingStats::from_findings(tail),
        }),
    )
}

fn folds(rows: usize, budget: usize) -> bool {
    rows.saturating_sub(budget) >= FOLD_MIN_SAVINGS
}

/// Whether any findings tier folds its tail, so the end-of-report hint can
/// point at --details exactly once.
pub(super) fn any_tier_folds(report: &ScanReport) -> bool {
    !report.details
        && SECTION_ORDER.into_iter().any(|mode| {
            folds(
                report
                    .findings
                    .iter()
                    .filter(|finding| finding.disposition().mode == mode)
                    .count(),
                ROW_BUDGET,
            )
        })
}

fn print_fold_line(report: &ScanReport, folded: Option<FoldedTail<'_>>) -> Result<()> {
    let Some(folded) = folded else {
        return Ok(());
    };
    // The narrow compact layout renders one block per finding with a blank
    // line between blocks; the fold line keeps a block of its own there.
    if report.ui.stdout_is_terminal && report.ui.width < WIDE_TABLE_MIN_WIDTH {
        stdoutln!("")?;
    }
    stdoutln!(
        "{}",
        fold_line(report.ui, &folded, report.findings_lower_bound())
    )
}

/// One dimmed line aggregating a folded tail. Byte and inode totals go
/// through the shared [`cleanup::FindingStats`] labels under the same
/// scan-level lower bound as the tier header above, so the two always agree
/// on their `>=` marks.
fn fold_line(ui: Ui, folded: &FoldedTail<'_>, scan_lower_bound: bool) -> String {
    let count = folded.findings.len();
    let noun = if count == 1 { "location" } else { "locations" };
    let label = format!("{} and {count} more {noun}", ui.glyphs.ellipsis);
    ui.headline(
        Headline::new(label, HeadlineLead::Separator)
            .label_tone(Tone::Secondary)
            .stat(folded.stats.bytes_label(scan_lower_bound, ui.glyphs))
            .stat(folded.stats.inodes_label(scan_lower_bound, ui.glyphs)),
    )
}

fn has_mode(findings: &[Finding], mode: DispositionMode) -> bool {
    findings
        .iter()
        .any(|finding| finding.disposition().mode == mode)
}

#[cfg(test)]
mod tests {
    use super::{ROW_BUDGET, fold_line, fold_tail, headline_label};
    use crate::runtime::Ui;
    use degu_core::finding::{
        Finding, FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
        finalize_findings,
    };
    use std::path::PathBuf;

    const ROW_BYTES: u64 = 4096;

    #[test]
    fn headline_drops_the_duration_before_it_would_wrap() {
        let base = || "112.0 KiB detected across 2 locations".to_owned();
        let elapsed = Some(std::time::Duration::from_millis(5));

        assert_eq!(
            headline_label(base(), elapsed, Ui::test_terminal(80)),
            "112.0 KiB detected across 2 locations in 5ms"
        );
        assert_eq!(
            headline_label(base(), elapsed, Ui::test_terminal(40)),
            base()
        );
        assert_eq!(headline_label(base(), None, Ui::test_terminal(80)), base());
        assert_eq!(headline_label(base(), elapsed, Ui::test_pipe(80)), base());
    }

    fn tier_finding(index: usize, bytes: u64, inodes: u64, skipped: u64) -> Finding {
        let candidate = FindingCandidate {
            ecosystem: "pip".to_string(),
            path: PathBuf::from(format!("/home/researcher/.cache/tier/{index:02}")),
            kind: FindingKind::PackageCache,
            bytes_apparent: bytes,
            bytes_allocated: bytes,
            age_days: Some(1),
            bytes_hardlinked: 0,
            inodes,
            skipped,
            truncated: false,
            unvisited_dirs: 0,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery: Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            ownership: Ownership::Standalone,
            hazard: None,
            rationale: "fold fixture".to_string(),
        };
        finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
            .pop()
            .unwrap()
    }

    /// A ranked tier of `rows` one-inode findings, bytes-descending like
    /// `rank_findings` output: row `index` holds `ROW_BYTES * (rows -
    /// index)`, so a 12-row tier folds `2 * ROW_BYTES + ROW_BYTES` =
    /// 12.0 KiB across its two tail rows.
    fn ranked_tier(rows: usize) -> Vec<Finding> {
        (0..rows)
            .map(|index| tier_finding(index, ROW_BYTES * (rows - index) as u64, 1, 0))
            .collect()
    }

    #[test]
    fn tiers_fold_only_past_ten_rows_when_two_are_saved() {
        for (rows, visible_rows, folded_rows) in [(10, 10, None), (11, 11, None), (12, 10, Some(2))]
        {
            let tier = ranked_tier(rows);
            let (visible, folded) = fold_tail(&tier, ROW_BUDGET);
            assert_eq!(visible.len(), visible_rows, "rows {rows}");
            assert_eq!(
                folded.as_ref().map(|tail| tail.findings.len()),
                folded_rows,
                "rows {rows}"
            );
            // The split preserves the ranked order: the head keeps the
            // largest rows exactly as given, never re-sorted.
            for (index, finding) in visible.iter().enumerate() {
                assert_eq!(finding.path(), tier[index].path(), "rows {rows}");
            }
        }
    }

    #[test]
    fn fold_split_conserves_tier_totals_exactly() {
        let tier: Vec<Finding> = (0..13)
            .map(|index| tier_finding(index, (1u64 << 40) >> index, 1000 - index as u64, 0))
            .collect();
        let sums = |findings: &[Finding]| {
            findings.iter().fold((0u64, 0u64), |(bytes, inodes), f| {
                (bytes + f.bytes_allocated(), inodes + f.inodes())
            })
        };

        let (visible, folded) = fold_tail(&tier, ROW_BUDGET);
        let folded = folded.expect("13 rows must fold");

        let (visible_bytes, visible_inodes) = sums(visible);
        let (folded_bytes, folded_inodes) = sums(folded.findings);
        let (total_bytes, total_inodes) = sums(&tier);
        assert_eq!(visible_bytes + folded_bytes, total_bytes);
        assert_eq!(visible_inodes + folded_inodes, total_inodes);
        assert_eq!(visible.len() + folded.findings.len(), tier.len());
    }

    /// A ranked 12-row tier whose finding at `index` has an incomplete
    /// measurement (skipped entries), everything else complete.
    fn tier_incomplete_at(index: usize) -> Vec<Finding> {
        let mut tier = ranked_tier(12);
        tier[index] = tier_finding(index, tier[index].bytes_allocated(), 1, 1);
        tier
    }

    #[test]
    fn fold_line_lower_bound_follows_the_finding_stats_convention() {
        let rendered = |tier: &[Finding], scan_lower_bound: bool| {
            let (_, folded) = fold_tail(tier, ROW_BUDGET);
            fold_line(Ui::test_pipe(200), &folded.unwrap(), scan_lower_bound)
        };

        // A measurement-incomplete folded row marks the folded totals.
        assert_eq!(
            rendered(&tier_incomplete_at(11), false),
            "... and 2 more locations - >= 12.0 KiB - >= 2 inodes"
        );
        // Incompleteness confined to visible rows never leaks into the fold.
        assert_eq!(
            rendered(&tier_incomplete_at(0), false),
            "... and 2 more locations - 12.0 KiB - 2 inodes"
        );
        // A scan-level lower bound marks the fold line with the tier header.
        assert_eq!(
            rendered(&ranked_tier(12), true),
            "... and 2 more locations - >= 12.0 KiB - >= 2 inodes"
        );
    }

    #[test]
    fn fold_line_switches_glyphs_and_stays_single_line_when_piped() {
        let tier = ranked_tier(12);
        let (_, folded) = fold_tail(&tier, ROW_BUDGET);
        let folded = folded.unwrap();

        assert_eq!(
            fold_line(Ui::test_terminal(80), &folded, false),
            "\u{2026} and 2 more locations \u{b7} 12.0 KiB \u{b7} 2 inodes"
        );
        assert_eq!(
            fold_line(Ui::test_pipe(80), &folded, false),
            "... and 2 more locations - 12.0 KiB - 2 inodes"
        );
        // Narrow terminals move the stats to one indented line; piped
        // output never leaves the single-line form.
        assert_eq!(
            fold_line(Ui::test_terminal(40), &folded, false),
            "\u{2026} and 2 more locations\n  12.0 KiB \u{b7} 2 inodes"
        );
        assert_eq!(
            fold_line(Ui::test_pipe(40), &folded, false),
            "... and 2 more locations - 12.0 KiB - 2 inodes"
        );
    }
}
