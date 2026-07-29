use super::{PreparedClean, table_options};
use crate::commands::next_action;
use crate::finding_filter::rank_findings;
use crate::findings_table::print as print_findings_table;
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{cleanup, escape_terminal_text, semantic};
use crate::runtime::{Headline, HeadlineLead};
use anyhow::Result;
use degu_core::finding::{DispositionMode, Finding};

const POLICY_MODES: [DispositionMode; 2] = [DispositionMode::OptIn, DispositionMode::ReportOnly];

pub(super) fn print_policy(prepared: &PreparedClean) -> Result<()> {
    if prepared.exclusions.policy_visible().is_empty() {
        return Ok(());
    }
    stdoutln!(
        "\n{}",
        semantic::paint(
            "Excluded:",
            Tone::Heading,
            prepared.settings.ui.colors.stdout
        )
    )?;
    for mode in POLICY_MODES {
        print_policy_summary(prepared, mode)?;
    }
    if has_policy_mode(prepared, DispositionMode::ReportOnly)
        && let Some(explanation) = cleanup::explanation(DispositionMode::ReportOnly)
    {
        stdoutln!(
            "{}",
            prepared
                .settings
                .ui
                .toned_prose(2, explanation, Tone::Secondary)
        )?;
    }
    print_review_focus(prepared)?;
    if prepared.settings.details {
        print_policy_details(prepared)
    } else {
        print_details_hint(prepared)
    }
}

pub(super) fn print_filtered(prepared: &PreparedClean) -> Result<()> {
    let path_selection = prepared.scope.has_paths();
    let findings = if path_selection {
        prepared.exclusions.filter_hidden().cloned().collect()
    } else {
        filtered_findings(prepared)
    };
    if findings.is_empty() {
        return Ok(());
    }
    let findings = rank_findings(findings);
    let stats = cleanup::FindingStats::from_findings(&findings);
    let label = if path_selection {
        "Outside this selection"
    } else {
        "Hidden by filters"
    };
    stdoutln!(
        "\n{}",
        prepared.settings.ui.headline(
            Headline::new(label, HeadlineLead::Colon)
                .label_tone(Tone::Heading)
                .stat(stats.locations_label())
                .stat(stats.bytes_label(prepared.scan_lower_bound(), prepared.settings.ui.glyphs))
        )
    )?;
    if prepared.settings.details && !path_selection {
        print_findings_table(&findings, table_options(prepared))?;
    }
    Ok(())
}

fn print_details_hint(prepared: &PreparedClean) -> Result<()> {
    let label = if has_policy_mode(prepared, DispositionMode::OptIn) {
        "Review details"
    } else {
        "Excluded details"
    };
    match next_action::details_preview_from_clean(&prepared.scope, &prepared.ctx.home) {
        Some(line) => stdoutln!(
            "{}",
            prepared.settings.ui.command_block(
                &semantic::paint(
                    format!("{label}:"),
                    Tone::AccentHeading,
                    prepared.settings.ui.colors.stdout
                ),
                &semantic::paint(
                    line.as_str(),
                    Tone::Accent,
                    prepared.settings.ui.colors.stdout
                ),
            )
        ),
        None => stdoutln!(
            "{}",
            prepared
                .settings
                .ui
                .prose(&format!("{label} {}", next_action::UNSAFE_SCOPE_REASON))
        ),
    }
}

fn print_policy_summary(prepared: &PreparedClean, mode: DispositionMode) -> Result<()> {
    let stats = cleanup::FindingStats::for_mode(prepared.exclusions.policy_visible(), mode);
    if stats.is_empty() {
        return Ok(());
    }
    stdoutln!(
        "{}",
        cleanup::group_header(
            prepared.settings.ui,
            cleanup::Group {
                label: cleanup::label(mode),
                mode,
                stats,
                scan_lower_bound: prepared.scan_lower_bound(),
                indent: 2,
            },
        )
    )
}

fn print_policy_details(prepared: &PreparedClean) -> Result<()> {
    for mode in POLICY_MODES {
        let findings = policy_findings(prepared, mode);
        if findings.is_empty() {
            continue;
        }
        stdoutln!(
            "\n{}:",
            semantic::disposition(
                cleanup::label(mode),
                mode,
                prepared.settings.ui.colors.stdout
            )
        )?;
        print_findings_table(&findings, table_options(prepared).for_disposition(mode))?;
    }
    Ok(())
}

fn print_review_focus(prepared: &PreparedClean) -> Result<()> {
    let findings = policy_findings(prepared, DispositionMode::OptIn);
    let Some(finding) = findings.first() else {
        return Ok(());
    };
    stdoutln!(
        "\n{}",
        semantic::paint(
            prepared
                .settings
                .ui
                .prose("Review this location before including it:"),
            Tone::Review,
            prepared.settings.ui.colors.stdout
        )
    )?;
    stdoutln!(
        "  Path: {}",
        super::super::escaped_path(finding.path(), &prepared.ctx.home)
    )?;
    stdoutln!(
        "{}",
        prepared
            .settings
            .ui
            .indented_prose(2, &format!("Reason: {}", review_reason(finding)))
    )?;
    print_review_preview(prepared, finding)
}

fn print_review_preview(prepared: &PreparedClean, finding: &Finding) -> Result<()> {
    let Some(line) =
        next_action::review_preview_from_clean(&prepared.scope, finding.path(), &prepared.ctx.home)
    else {
        stdoutln!(
            "{}",
            prepared
                .settings
                .ui
                .indented_prose(2, next_action::UNSAFE_PATH_REASON)
        )?;
        return Ok(());
    };
    stdoutln!(
        "  {}",
        semantic::paint(
            "Preview (no changes):",
            Tone::AccentHeading,
            prepared.settings.ui.colors.stdout
        )
    )?;
    stdoutln!(
        "    {}",
        semantic::paint(
            line.as_str(),
            Tone::Accent,
            prepared.settings.ui.colors.stdout
        )
    )?;
    stdoutln!(
        "{}",
        semantic::paint(
            prepared.settings.ui.prose(next_action::review_followup(
                prepared.settings.ui.stdout_is_terminal
            )),
            Tone::Secondary,
            prepared.settings.ui.colors.stdout
        )
    )
}

fn review_reason(finding: &Finding) -> String {
    escape_terminal_text(
        finding
            .disposition()
            .reason
            .as_deref()
            .unwrap_or("not specified"),
    )
}

fn policy_findings(prepared: &PreparedClean, mode: DispositionMode) -> Vec<Finding> {
    prepared
        .exclusions
        .policy_visible()
        .iter()
        .filter(|finding| finding.disposition().mode == mode)
        .cloned()
        .collect()
}

fn has_policy_mode(prepared: &PreparedClean, mode: DispositionMode) -> bool {
    prepared
        .exclusions
        .policy_visible()
        .iter()
        .any(|finding| finding.disposition().mode == mode)
}

fn filtered_findings(prepared: &PreparedClean) -> Vec<Finding> {
    prepared
        .exclusions
        .filter_hidden()
        .filter(|finding| !excluded_by_policy(finding, prepared.scope.include_review()))
        .cloned()
        .collect()
}

fn excluded_by_policy(finding: &Finding, include_review: bool) -> bool {
    match finding.disposition().mode {
        DispositionMode::ReportOnly => true,
        DispositionMode::OptIn => !include_review,
        DispositionMode::Eligible => false,
    }
}
