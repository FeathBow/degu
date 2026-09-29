use super::execution::ExpiryExecution;
use super::preparation::PreparedClean;
use crate::lifecycle::{
    CleanExecution, ExpiryPlan, Lifecycle, TRASH_RETENTION_DAYS, cleaned_resources,
};
use crate::output::{flush_stdout, stdoutln};
use crate::presentation::semantic::Tone;
use crate::presentation::{cleanup, display_path, escape_terminal_text, human_bytes, semantic};
use crate::runtime::{Headline, HeadlineLead};
use anyhow::Result;
use std::path::PathBuf;

mod failure;
mod json;
mod plan;
#[cfg(test)]
mod tests;

pub(super) use json::{
    print as print_json, validate_expiry as validate_json_expiry,
    validate_prepared as validate_json_prepared,
};
pub(super) use plan::print as print_plan;

pub(super) fn print_mutation_scope(
    prepared: &PreparedClean,
    expiry: &ExpiryPlan,
    sealed_staging: bool,
) -> Result<()> {
    if !prepared.plan.items().is_empty() {
        print_mechanism(prepared, sealed_staging)?;
    }
    print_expiry_plan(expiry, prepared, false)?;
    flush_stdout()
}

/// What a staging clean closes with, or nothing when nothing truthful is left
/// to say.
///
/// Undo is offered only when every executed entry can actually use it. A run
/// reports `Do not run undo for this entry` for the ones that cannot, and a
/// closing line that invited undo anyway would leave the reader holding two
/// instructions with no way to tell which one applies.
fn staged_note(
    staged_under_seal: bool,
    manual_recovery: bool,
    purge_unsupported: bool,
) -> Option<String> {
    let quota = if manual_recovery {
        "Still counts against quota while staged. Entries that need manual recovery cannot be restored with 'degu undo'; each one's reason is reported as an error."
    } else {
        "Still counts against quota while staged; restore with 'degu undo'."
    };
    if staged_under_seal {
        let expiry = if purge_unsupported {
            " Internal-hardlink entries are retained because permanent purge is unsupported; unrelated purge-supported entries may be purged after seven days."
        } else {
            " A later clean may purge it after seven days; legacy path-based cleanup cannot delete it."
        };
        Some(format!("{quota}{expiry}"))
    } else if manual_recovery {
        None
    } else {
        Some(quota.to_owned())
    }
}

fn plan_has_purge_unsupported(prepared: &PreparedClean) -> bool {
    prepared
        .preview_tree_policy_assessed()
        .iter()
        .any(|finding| {
            prepared
                .preview_assessment(finding)
                .is_some_and(|assessment| !assessment.purge_supported())
        })
}

fn print_mechanism(prepared: &PreparedClean, sealed_staging: bool) -> Result<()> {
    let ui = prepared.settings.ui;
    let trash_dirs = clean_plan_trash_dirs(prepared)?;
    if !ui.stdout_is_terminal {
        return print_mechanism_sentence(prepared, &trash_dirs, sealed_staging);
    }
    stdoutln!(
        "{}",
        ui.headline(
            Headline::new("Plan", HeadlineLead::Colon)
                .stat(format!(
                    "move {}",
                    cleanup::count_label(prepared.plan.items().len(), "location", "locations")
                ))
                .stat(plan::planned_bytes(prepared))
        )
    )?;
    stdoutln!("To:")?;
    for trash_dir in &trash_dirs {
        stdoutln!("  {trash_dir}")?;
    }
    let mechanism = if prepared.settings.purge && plan_has_purge_unsupported(prepared) {
        ui.toned_prose(
            0,
            "Purge-supported items are sealed, staged, and permanently deleted through exact object-bound authority. Internal-hardlink items remain staged and undoable because permanent purge is unsupported.",
            Tone::Destructive,
        )
    } else if prepared.settings.purge {
        ui.toned_prose(
            0,
            "Sealed, staged, and permanently deleted through exact object-bound authority; not restorable.",
            Tone::Destructive,
        )
    } else if sealed_staging && plan_has_purge_unsupported(prepared) {
        ui.prose(
            "Restorable with degu undo. Internal-hardlink entries remain staged because permanent purge is unsupported; unrelated purge-supported entries may be purged after seven days. Legacy path-based cleanup cannot delete sealed entries."
        )
    } else if sealed_staging {
        ui.prose(&format!(
            "Restorable with degu undo; a later clean may purge it after {TRASH_RETENTION_DAYS} days. Legacy path-based cleanup cannot delete it."
        ))
    } else {
        ui.prose(&format!(
            "Restorable with degu undo; a later clean may purge it after {TRASH_RETENTION_DAYS} days."
        ))
    };
    stdoutln!("{mechanism}")
}

fn print_mechanism_sentence(
    prepared: &PreparedClean,
    trash_dirs: &[String],
    sealed_staging: bool,
) -> Result<()> {
    let mechanism = if prepared.settings.purge && plan_has_purge_unsupported(prepared) {
        semantic::paint(
            "purge-supported items are sealed, staged, and permanently deleted through exact object-bound authority; internal-hardlink items remain staged and undoable because permanent purge is unsupported.",
            Tone::Destructive,
            prepared.settings.ui.colors.stdout,
        )
    } else if prepared.settings.purge {
        semantic::paint(
            "sealed, staged, and permanently deleted through exact object-bound authority; not restorable.",
            Tone::Destructive,
            prepared.settings.ui.colors.stdout,
        )
    } else if sealed_staging && plan_has_purge_unsupported(prepared) {
        "restorable with degu undo; internal-hardlink entries remain staged because permanent purge is unsupported, while unrelated purge-supported entries may be purged after seven days. Legacy path-based cleanup cannot delete sealed entries.".to_string()
    } else if sealed_staging {
        format!(
            "restorable with degu undo; a later clean may purge it after {TRASH_RETENTION_DAYS} days. Legacy path-based cleanup cannot delete it."
        )
    } else {
        format!(
            "restorable with degu undo; a later clean may purge it after {TRASH_RETENTION_DAYS} days."
        )
    };
    stdoutln!(
        "Plan: move {} ({}) to {} — {mechanism}",
        cleanup::count_label(prepared.plan.items().len(), "location", "locations"),
        plan::planned_bytes(prepared),
        trash_dirs.join(", ")
    )
}

pub(super) fn print_expiry_plan(
    plan: &ExpiryPlan,
    prepared: &PreparedClean,
    dry_run: bool,
) -> Result<()> {
    if plan.is_empty() {
        return Ok(());
    }
    let action = if dry_run {
        "would be permanently deleted"
    } else {
        "will be permanently deleted"
    };
    let action = semantic::paint(
        action,
        Tone::Destructive,
        prepared.settings.ui.colors.stdout,
    );
    let noun = if plan.len() == 1 { "entry" } else { "entries" };
    stdoutln!(
        "Expired trash: {} {noun} will be considered (at least {} days old); purge-supported entries {action}, while sealed entries with unsupported purge topology are retained and remain undoable.",
        plan.len(),
        TRASH_RETENTION_DAYS
    )?;
    for entry in plan.entries() {
        stdoutln!("  {}", escaped_path(entry, &prepared.ctx.home))?;
    }
    Ok(())
}

fn clean_plan_trash_dirs(prepared: &PreparedClean) -> Result<Vec<String>> {
    let mut roots = Vec::<PathBuf>::new();
    let lifecycle = Lifecycle::new(&prepared.ctx);
    for finding in prepared.plan.items() {
        let root = lifecycle
            .resolve_trash_dir(finding.path())
            .map_err(|reason| trash_resolution_error(finding.path(), &reason))?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.is_empty() {
        roots.push(lifecycle.trash_dir());
    }
    Ok(roots
        .iter()
        .map(|root| escaped_path(root, &prepared.ctx.home))
        .collect())
}

fn trash_resolution_error(path: &std::path::Path, reason: &str) -> anyhow::Error {
    anyhow::Error::msg(escape_terminal_text(reason)).context(format!(
        "failed to resolve trash root for {}",
        escape_terminal_text(&path.display().to_string())
    ))
}

pub(super) fn print_execution(
    prepared: &PreparedClean,
    executed: &[CleanExecution],
    elapsed: Option<std::time::Duration>,
) -> Result<()> {
    print_failures(executed, prepared.settings.ui.colors);
    let ui = prepared.settings.ui;
    let (cleaned_bytes, cleaned_inodes) = cleaned_resources(executed, prepared.settings.purge);
    let cleaned = executed
        .iter()
        .filter(|item| item.reported_as_cleaned(prepared.settings.purge))
        .count();
    let separator = ui.glyphs.separator;
    if prepared.settings.purge {
        let mut summary = format!(
            "Purged {} {separator} {} {separator} {}",
            cleanup::count_label(cleaned, "location", "locations"),
            human_bytes(cleaned_bytes),
            cleanup::inode_total_label(false, cleaned_inodes, ui.glyphs)
        );
        append_elapsed(&mut summary, elapsed, ui);
        stdoutln!("{}", ui.prose(&summary))
    } else if cleaned == 0 {
        stdoutln!("{}", ui.prose("No locations completed staging."))
    } else {
        let mut summary = format!(
            "Staged {} {separator} {} {separator} {} into the trash",
            cleanup::count_label(cleaned, "location", "locations"),
            human_bytes(cleaned_bytes),
            cleanup::inode_total_label(false, cleaned_inodes, ui.glyphs)
        );
        append_elapsed(&mut summary, elapsed, ui);
        stdoutln!("{}", ui.prose(&summary))?;
        if let Some(note) = staged_note(
            executed
                .iter()
                .any(CleanExecution::staged_under_seal_authority),
            executed
                .iter()
                .any(CleanExecution::requires_manual_recovery),
            plan_has_purge_unsupported(prepared),
        ) {
            stdoutln!("{}", ui.prose(&note))?;
        }
        Ok(())
    }
}

fn append_elapsed(
    summary: &mut String,
    elapsed: Option<std::time::Duration>,
    ui: crate::runtime::Ui,
) {
    if !ui.stdout_is_terminal {
        return;
    }
    if let Some(elapsed) = elapsed {
        summary.push_str(&format!(
            " in {}",
            crate::presentation::human_duration(elapsed)
        ));
    }
}

fn print_failures(executed: &[CleanExecution], colors: crate::runtime::OutputColors) {
    for item in executed {
        if let Some((severity, note)) = failure::note(item) {
            crate::presentation::print_stderr_note(severity, &note, colors);
        }
    }
}

pub(super) fn print_expiry(
    expiry: &ExpiryExecution,
    colors: crate::runtime::OutputColors,
) -> Result<()> {
    let Some(report) = &expiry.report else {
        return Ok(());
    };
    if !report.purged.is_empty() {
        let noun = if report.purged.len() == 1 {
            "entry"
        } else {
            "entries"
        };
        stdoutln!("Purged {} expired trash {noun}", report.purged.len())?;
    }
    for (entry, reason) in report.unpurged() {
        let entry = escape_terminal_text(&entry.display().to_string());
        let reason = escape_terminal_text(reason);
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Error,
            &format!("failed to purge expired entry {entry}: {reason}"),
            colors,
        );
    }
    for (entry, reason) in report.gaps() {
        let entry = escape_terminal_text(&entry.display().to_string());
        let reason = escape_terminal_text(reason);
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            &format!(
                "purged expired entry {entry}, but the outcome was not fully recorded: {reason}"
            ),
            colors,
        );
    }
    Ok(())
}

fn escaped_path(path: &std::path::Path, home: &std::path::Path) -> String {
    escape_terminal_text(&display_path(path, home))
}

pub(super) fn print_cancelled(ui: crate::runtime::Ui) -> Result<()> {
    stdoutln!("{}", ui.prose("Canceled; no clean or purge changes made."))
}
