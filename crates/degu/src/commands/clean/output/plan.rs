use super::super::preparation::PreparedClean;
use crate::findings::{FindingsTableOptions, print as print_findings_table};
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    any_hardlinked, cleanup, lower_bound_bytes, print_hardlink_summary,
    print_scan_incomplete_warning, semantic,
};
use crate::runtime::{Headline, HeadlineLead};
use anyhow::Result;
use degu_core::finding::DispositionMode;

mod exclusions;

pub(in crate::commands::clean) fn print(prepared: &PreparedClean) -> Result<()> {
    print_dry_run_header(prepared)?;
    let marked_totals = prepared.scan_status.is_lower_bound()
        && (!prepared.plan.items().is_empty() || !prepared.exclusions.policy_visible().is_empty());
    print_scan_incomplete_warning(
        prepared.scan_status.is_lower_bound(),
        marked_totals,
        prepared.settings.ui,
    )?;
    print_protected_gate_note(prepared)?;
    print_omitted_note(prepared)?;
    if prepared.plan.items().is_empty() {
        stdoutln!(
            "{}",
            prepared
                .settings
                .ui
                .prose("No locations are selected for this clean.")
        )?;
    } else {
        print_selected(prepared)?;
    }
    exclusions::print_policy(prepared)?;
    exclusions::print_filtered(prepared)
}

/// Discloses that the completeness gate skipped deliberately protected
/// regions. Human output only; the frozen JSON report never carries region
/// provenance.
fn print_protected_gate_note(prepared: &PreparedClean) -> Result<()> {
    let excluded = prepared.protected_regions_excluded;
    if excluded == 0 {
        return Ok(());
    }
    let note = format!(
        "{excluded} reported-only location(s) behind protected boundaries were excluded from completeness gating; plan unaffected."
    );
    stdoutln!(
        "{}",
        prepared.settings.ui.toned_prose(0, &note, Tone::Secondary)
    )
}

fn print_omitted_note(prepared: &PreparedClean) -> Result<()> {
    let omitted = prepared.unrepresentable;
    if omitted == 0 {
        return Ok(());
    }
    let note = format!(
        "{omitted} location(s) omitted: path is not valid UTF-8 and cannot be shown for verification, so it was excluded from the plan."
    );
    stdoutln!(
        "{}",
        prepared.settings.ui.toned_prose(0, &note, Tone::Secondary)
    )
}

fn print_dry_run_header(prepared: &PreparedClean) -> Result<()> {
    if !prepared.settings.dry_run {
        return Ok(());
    }
    stdoutln!(
        "{}\n",
        prepared.settings.ui.headline(
            Headline::new("Dry run", HeadlineLead::Separator)
                .label_tone(Tone::AccentHeading)
                .stat("no changes will be made.")
        )
    )
}

fn print_selected(prepared: &PreparedClean) -> Result<()> {
    let stats = cleanup::FindingStats::from_findings(prepared.plan.items());
    print_selection_summary(prepared, stats)?;
    print_selected_group(prepared, DispositionMode::Eligible)?;
    print_selected_group(prepared, DispositionMode::OptIn)?;
    if any_hardlinked(prepared.plan.items()) {
        stdoutln!("")?;
    }
    print_hardlink_summary(
        prepared.plan.items(),
        prepared.plan_lower_bound(),
        prepared.settings.ui,
    )
}

fn print_selection_summary(prepared: &PreparedClean, stats: cleanup::FindingStats) -> Result<()> {
    if !prepared.settings.dry_run {
        return print_selected_summary(prepared, stats);
    }
    if prepared.settings.purge {
        print_permanent_preview(prepared, stats)
    } else {
        print_staging_preview(prepared, stats)
    }
}

fn print_selected_summary(prepared: &PreparedClean, stats: cleanup::FindingStats) -> Result<()> {
    stdoutln!(
        "{}",
        prepared.settings.ui.headline(
            Headline::new(
                format!("Selected {}", planned_bytes(prepared)),
                HeadlineLead::Phrase("from")
            )
            .stat(stats.locations_label())
            .stat(stats.inodes_label(prepared.plan_lower_bound(), prepared.settings.ui.glyphs))
        )
    )
}

fn print_permanent_preview(prepared: &PreparedClean, stats: cleanup::FindingStats) -> Result<()> {
    stdoutln!(
        "{}",
        semantic::paint(
            prepared.settings.ui.prose(&format!(
                "Would permanently delete {}",
                planned_bytes(prepared)
            )),
            Tone::Destructive,
            prepared.settings.ui.colors.stdout
        )
    )?;
    print_scope_summary(prepared, stats)?;
    stdoutln!(
        "{}",
        semantic::paint(
            "Not restorable.",
            Tone::Destructive,
            prepared.settings.ui.colors.stdout
        )
    )
}

fn print_staging_preview(prepared: &PreparedClean, stats: cleanup::FindingStats) -> Result<()> {
    stdoutln!(
        "{}",
        prepared.settings.ui.headline(
            Headline::new(
                format!("Would move {}", planned_bytes(prepared)),
                HeadlineLead::Phrase("to")
            )
            .stat("Degu trash")
            .stat_tone(Tone::AccentHeading)
        )
    )?;
    print_scope_summary(prepared, stats)?;
    stdoutln!(
        "{}",
        prepared
            .settings
            .ui
            .prose("Undoable; quota is unchanged until Degu trash is purged.")
    )?;
    stdoutln!(
        "{}",
        semantic::paint(
            prepared.settings.ui.prose(
                "Quota can change only after permanent deletion: inspect degu trash list; degu trash purge deletes all listed entries."
            ),
            Tone::Secondary,
            prepared.settings.ui.colors.stdout
        )
    )
}

fn print_scope_summary(prepared: &PreparedClean, stats: cleanup::FindingStats) -> Result<()> {
    let label = format!("From {}", stats.locations_label());
    stdoutln!(
        "{}",
        prepared.settings.ui.headline(
            Headline::new(label, HeadlineLead::Separator)
                .label_tone(Tone::Secondary)
                .stat(stats.inodes_label(prepared.plan_lower_bound(), prepared.settings.ui.glyphs))
        )
    )
}

fn print_selected_group(prepared: &PreparedClean, mode: DispositionMode) -> Result<()> {
    let findings = prepared
        .plan
        .items()
        .iter()
        .filter(|finding| finding.disposition().mode == mode)
        .cloned()
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return Ok(());
    }
    let stats = cleanup::FindingStats::from_findings(&findings);
    let label = match mode {
        DispositionMode::Eligible => cleanup::label(mode),
        DispositionMode::OptIn => "Needs review (included by --include-review)",
        DispositionMode::ReportOnly => return Ok(()),
    };
    stdoutln!(
        "\n{}",
        cleanup::group_header(
            prepared.settings.ui,
            cleanup::Group {
                label,
                mode,
                stats,
                scan_lower_bound: prepared.plan_lower_bound(),
                indent: 0,
            },
        )
    )?;
    let options = table_options(prepared);
    let options = match mode {
        DispositionMode::Eligible => options.for_plan(),
        DispositionMode::OptIn => options.for_disposition(mode),
        DispositionMode::ReportOnly => return Ok(()),
    };
    print_findings_table(&findings, options)
}

fn table_options(prepared: &PreparedClean) -> FindingsTableOptions<'_> {
    FindingsTableOptions::new(
        prepared.settings.ui,
        prepared.settings.details,
        &prepared.ctx.home,
    )
}

pub(super) fn planned_bytes(prepared: &PreparedClean) -> String {
    lower_bound_bytes(
        prepared.plan_lower_bound(),
        prepared.plan.total_bytes_allocated(),
        prepared.settings.ui.glyphs,
    )
}
