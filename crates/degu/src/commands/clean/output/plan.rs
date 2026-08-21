use super::super::preparation::PreparedClean;
use crate::findings::{FindingsTableOptions, print as print_findings_table};
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    any_hardlinked, cleanup, display_path, escape_terminal_text, lower_bound_bytes,
    print_hardlink_summary, print_scan_incomplete_warning, semantic,
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
    let assessed = prepared.preview_tree_policy_assessed();
    let assessed_owned = assessed
        .iter()
        .map(|finding| (*finding).clone())
        .collect::<Vec<_>>();
    if !assessed_owned.is_empty() {
        let stats = cleanup::FindingStats::from_findings(&assessed_owned);
        print_selection_summary(prepared, stats, &assessed_owned)?;
        print_selected_group(prepared, DispositionMode::Eligible)?;
        print_selected_group(prepared, DispositionMode::OptIn)?;
        if prepared.settings.dry_run {
            stdoutln!(
                "{}",
                prepared.settings.ui.toned_prose(
                    0,
                    "Tree policy metadata assessed; source-parent seal, regular-file content reads, and runtime checks remain for execution.",
                    Tone::Secondary,
                )
            )?;
        }
        let internal_hard_link_items = assessed
            .iter()
            .filter(|finding| {
                prepared
                    .preview_assessment(finding)
                    .is_some_and(|assessment| assessment.has_internal_hard_links())
            })
            .count();
        if internal_hard_link_items != 0 {
            let note = if prepared.settings.purge {
                format!(
                    "{internal_hard_link_items} location(s) contain complete internal regular-file hardlink groups: execution may stage them, but permanent purge is unsupported and they will remain undoable in Degu trash."
                )
            } else {
                format!(
                    "{internal_hard_link_items} location(s) contain complete internal regular-file hardlink groups: staging and undo are supported, but later permanent purge is unsupported."
                )
            };
            stdoutln!(
                "{}",
                prepared.settings.ui.toned_prose(0, &note, Tone::Secondary)
            )?;
        }
        if any_hardlinked(&assessed_owned) {
            stdoutln!("")?;
        }
        print_hardlink_summary(
            &assessed_owned,
            assessed_owned
                .iter()
                .any(|finding| finding.measurement_incomplete()),
            prepared.settings.ui,
        )?;
    }
    print_preflight_group(prepared, true)?;
    print_preflight_group(prepared, false)
}

fn print_selection_summary(
    prepared: &PreparedClean,
    stats: cleanup::FindingStats,
    findings: &[degu_core::finding::Finding],
) -> Result<()> {
    if !prepared.settings.dry_run {
        return print_selected_summary(prepared, stats);
    }
    if prepared.settings.purge {
        print_permanent_preview(prepared, stats, findings)
    } else {
        print_staging_preview(prepared, stats, findings)
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

fn print_permanent_preview(
    prepared: &PreparedClean,
    stats: cleanup::FindingStats,
    findings: &[degu_core::finding::Finding],
) -> Result<()> {
    let purge_supported = findings
        .iter()
        .filter(|finding| {
            prepared
                .preview_assessment(finding)
                .is_none_or(|assessment| assessment.purge_supported())
        })
        .cloned()
        .collect::<Vec<_>>();
    let staged_only = findings
        .iter()
        .filter(|finding| {
            prepared
                .preview_assessment(finding)
                .is_some_and(|assessment| !assessment.purge_supported())
        })
        .cloned()
        .collect::<Vec<_>>();
    if !purge_supported.is_empty() {
        stdoutln!(
            "{}",
            semantic::paint(
                prepared.settings.ui.prose(&format!(
                    "Would permanently delete {} after exact authority verification",
                    preview_bytes(prepared, &purge_supported)
                )),
                Tone::Destructive,
                prepared.settings.ui.colors.stdout
            )
        )?;
    }
    if !staged_only.is_empty() {
        stdoutln!(
            "{}",
            prepared.settings.ui.prose(&format!(
                "Would stage {} in Degu trash, but not permanently delete it because sealed purge does not support multi-link regular-file groups",
                preview_bytes(prepared, &staged_only)
            ))
        )?;
    }
    print_scope_summary(prepared, stats)?;
    if !purge_supported.is_empty() {
        stdoutln!(
            "{}",
            semantic::paint(
                "Preview is mutation-free; confirmed execution must seal and stage before authority-bound deletion. Not restorable.",
                Tone::Destructive,
                prepared.settings.ui.colors.stdout
            )
        )?;
    }
    if !staged_only.is_empty() {
        stdoutln!(
            "{}",
            prepared.settings.ui.prose(
                "Unsupported purge locations remain fully staged and can be restored with `degu undo`."
            )
        )?;
    }
    Ok(())
}

fn print_staging_preview(
    prepared: &PreparedClean,
    stats: cleanup::FindingStats,
    findings: &[degu_core::finding::Finding],
) -> Result<()> {
    stdoutln!(
        "{}",
        prepared.settings.ui.headline(
            Headline::new(
                format!("Would move {}", preview_bytes(prepared, findings)),
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
                "Quota can change only after permanent deletion: inspect degu trash list; trash purge deletes purge-supported entries but retains sealed internal-hardlink entries."
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
        .filter(|finding| {
            prepared
                .preview_assessment(finding)
                .is_none_or(|assessment| assessment.is_tree_policy_assessed())
        })
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

fn print_preflight_group(prepared: &PreparedClean, blocked: bool) -> Result<()> {
    let rows = prepared
        .plan
        .items()
        .iter()
        .zip(prepared.preview_assessments())
        .filter(|(_, assessment)| {
            if blocked {
                assessment.is_blocked()
            } else {
                assessment.needs_execution_validation()
            }
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok(());
    }
    let findings = rows
        .iter()
        .map(|(finding, _)| (*finding).clone())
        .collect::<Vec<_>>();
    let stats = cleanup::FindingStats::from_findings(&findings);
    let label = if blocked {
        "Blocked by sealed staging preflight"
    } else {
        "Needs execution validation"
    };
    let mode = if blocked {
        DispositionMode::ReportOnly
    } else {
        DispositionMode::OptIn
    };
    stdoutln!(
        "\n{}",
        cleanup::group_header(
            prepared.settings.ui,
            cleanup::Group {
                label,
                mode,
                stats,
                scan_lower_bound: findings
                    .iter()
                    .any(|finding| finding.measurement_incomplete()),
                indent: 0,
            },
        )
    )?;
    for (finding, assessment) in rows {
        let path = escape_terminal_text(&display_path(finding.path(), &prepared.ctx.home));
        let reason = assessment
            .reason()
            .unwrap_or("execution validation required");
        stdoutln!("  {path}")?;
        stdoutln!("    {reason}")?;
    }
    Ok(())
}

fn preview_bytes(prepared: &PreparedClean, findings: &[degu_core::finding::Finding]) -> String {
    lower_bound_bytes(
        findings
            .iter()
            .any(|finding| finding.measurement_incomplete()),
        findings
            .iter()
            .map(|finding| finding.bytes_allocated())
            .sum(),
        prepared.settings.ui.glyphs,
    )
}

pub(super) fn planned_bytes(prepared: &PreparedClean) -> String {
    lower_bound_bytes(
        prepared.plan_lower_bound(),
        prepared.plan.total_bytes_allocated(),
        prepared.settings.ui.glyphs,
    )
}
