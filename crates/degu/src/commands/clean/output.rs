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

pub(super) fn print_mutation_scope(prepared: &PreparedClean, expiry: &ExpiryPlan) -> Result<()> {
    if !prepared.plan.items().is_empty() {
        print_mechanism(prepared)?;
    }
    print_expiry_plan(expiry, prepared, false)?;
    flush_stdout()
}

fn print_mechanism(prepared: &PreparedClean) -> Result<()> {
    let ui = prepared.settings.ui;
    let trash_dirs = clean_plan_trash_dirs(prepared)?;
    if !ui.stdout_is_terminal {
        return print_mechanism_sentence(prepared, &trash_dirs);
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
    if prepared.settings.purge {
        let mechanism = ui.toned_prose(
            0,
            "Staged then purged immediately; not restorable.",
            Tone::Destructive,
        );
        stdoutln!("{mechanism}")?;
    }
    Ok(())
}

fn print_mechanism_sentence(prepared: &PreparedClean, trash_dirs: &[String]) -> Result<()> {
    if prepared.settings.purge {
        let mechanism = semantic::paint(
            "staged then purged immediately; not restorable.",
            Tone::Destructive,
            prepared.settings.ui.colors.stdout,
        );
        return stdoutln!(
            "Plan: move {} ({}) to {} — {mechanism}",
            cleanup::count_label(prepared.plan.items().len(), "location", "locations"),
            plan::planned_bytes(prepared),
            trash_dirs.join(", ")
        );
    }
    stdoutln!(
        "Plan: move {} ({}) to {}",
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
        "Expired trash: {} {noun} {action} (at least {} days old).",
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
        stdoutln!("{}", ui.prose(&summary))
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
    for (entry, reason) in &report.failed {
        let entry = escape_terminal_text(&entry.display().to_string());
        let reason = escape_terminal_text(reason);
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Error,
            &format!("failed to purge expired entry {entry}: {reason}"),
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
