use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use std::path::Path;

use crate::cli::TrashPurgeArgs;
use crate::commands::prompt::confirm_permanent_delete;
use crate::lifecycle::{Lifecycle, TrashPurgePlan};
use crate::native::{
    ActionKind, ActionResultOwner, NotStartedReason, QuotaActionReport, coordinate,
    not_attempted_action, planned_action,
};
use crate::output::{flush_stdout, stdoutln};
use crate::presentation::semantic::Tone;
use crate::presentation::{display_path, escape_terminal_text, semantic};
use crate::runtime::Ui;
use serde::Serialize;

pub(super) fn run(args: TrashPurgeArgs, ui: Ui) -> Result<()> {
    let json = args.output.json;
    let yes = args.yes;
    let ctx = DetectCtx::from_process()?;
    if json && !yes {
        anyhow::bail!("--json requires --yes");
    }
    // Said before the plan, because a plan that reaches nothing reads like an
    // empty trash rather than a trash this environment cannot see.
    if let Some(note) =
        super::output::coverage_note(crate::lifecycle::activated_store_coverage(&ctx))
    {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            note,
            ui.colors,
        );
    }
    let mut session = Lifecycle::new(&ctx).lock()?;
    let plan = if !args.entry.is_empty() {
        session.plan_purge_entries(&args.entry)?
    } else if !args.path.is_empty() {
        let selected = session.plan_purge_selected(&args.path)?;
        // Nothing staged from a named origin is a legitimate outcome, but it
        // reads exactly like a mistyped path unless the selector is named.
        report_unmatched(&selected.unmatched, ui);
        report_uncertain(&selected.uncertain, ui);
        selected.plan
    } else {
        session.plan_purge_all()?
    };
    if json {
        validate_json_plan(&plan)?;
    } else {
        if !plan.has_housekeeping_scope() {
            return stdoutln!("{}", super::output::TRASH_IS_EMPTY);
        }
        print_plan(&plan, &ctx.home, ui.colors.stdout)?;
        flush_stdout()?;
    }
    if !yes && !confirm_permanent_delete(ui.colors)? {
        anyhow::bail!("Purge cancelled; no trash entries were deleted.");
    }
    if crate::output::stdout_consumer_gone() {
        return Err(crate::output::stdout_closed_error());
    }

    let (report, observation) = if !plan.has_housekeeping_scope() {
        let observation = not_attempted_action(
            ActionResultOwner::TrashPurgeCommand,
            ActionKind::TrashPurge,
            "trash:purge-all",
            [],
            NotStartedReason::Empty,
        )
        .map_err(|error| anyhow::anyhow!("invalid trash observation contract: {error:?}"))?;
        (session.execute_purge_all(plan), observation)
    } else {
        let action = planned_action(
            ActionResultOwner::TrashPurgeCommand,
            ActionKind::TrashPurge,
            "trash:purge-all",
            plan.trash_roots().map(std::path::PathBuf::from),
        )
        .map_err(|error| anyhow::anyhow!("invalid trash-purge observation contract: {error:?}"))?;
        let mut probe = crate::quota::probe;
        let (report, completed) = coordinate(action, &mut probe, || {
            // Admission is itself a durable post-confirmation mutation, so it
            // belongs inside the same quota observation boundary as execution.
            let report = session.execute_explicit_purge_all(plan);
            let outcome = crate::commands::purge_outcome(&report);
            (report, outcome)
        });
        (report, QuotaActionReport::Attempted(completed))
    };
    let output_result = if json {
        crate::native::print_warnings(&observation, ui.colors);
        print_json_report(&report, &observation)
    } else {
        print_human_report(&report, ui.colors)
            .and_then(|()| crate::native::print_human(&observation, ui.colors))
    };
    if report.unpurged().next().is_some() {
        anyhow::bail!("one or more trash entries failed to purge")
    }
    output_result
}

fn report_unmatched(unmatched: &[std::path::PathBuf], ui: Ui) {
    for path in unmatched {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            &ui.prose(&format!(
                "no staged entry came from {}; this selector removed nothing.",
                escape_terminal_text(&path.display().to_string())
            )),
            ui.colors,
        );
    }
}

/// Named rather than left out silently: the listing shows this entry, so a selector
/// that reached it and removed nothing otherwise reads as a mistyped path.
fn report_uncertain(uncertain: &[std::path::PathBuf], ui: Ui) {
    for entry in uncertain {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            &ui.prose(&format!(
                "the origin of {} could not be confirmed, so an origin selector does not reach it; purge it by entry, or resolve the ambiguity 'degu trash list' reports.",
                escape_terminal_text(&entry.display().to_string())
            )),
            ui.colors,
        );
    }
}

fn print_json_report(
    report: &crate::lifecycle::PurgeReport,
    observation: &QuotaActionReport,
) -> Result<()> {
    stdoutln!(
        "{}",
        serde_json::to_string_pretty(&json_report(report, observation))?
    )
}

fn validate_json_plan(plan: &TrashPurgePlan) -> Result<()> {
    let entries = plan.entries().collect::<Vec<_>>();
    let _ = serde_json::to_value(entries)?;
    let claims = plan
        .trash_roots()
        .map(|root| root.join(".claims"))
        .collect::<Vec<_>>();
    let _ = serde_json::to_value(claims)?;
    Ok(())
}

#[derive(Serialize)]
struct PurgeJsonReport<'a> {
    purged: &'a [std::path::PathBuf],
    failed: Vec<PurgeFailureJson<'a>>,
    unrecorded: Vec<PurgeFailureJson<'a>>,
    quota_observations: serde_json::Value,
}

#[derive(Serialize)]
struct PurgeFailureJson<'a> {
    path: &'a Path,
    reason: &'a str,
}

fn json_report<'a>(
    report: &'a crate::lifecycle::PurgeReport,
    observation: &QuotaActionReport,
) -> PurgeJsonReport<'a> {
    PurgeJsonReport {
        purged: &report.purged,
        failed: failure_rows(report.unpurged()),
        unrecorded: failure_rows(report.gaps()),
        quota_observations: crate::native::json(observation),
    }
}

fn failure_rows<'a>(
    reasons: impl Iterator<Item = &'a (std::path::PathBuf, String)>,
) -> Vec<PurgeFailureJson<'a>> {
    reasons
        .map(|(path, reason)| PurgeFailureJson { path, reason })
        .collect()
}

fn print_plan(plan: &TrashPurgePlan, home: &Path, color_enabled: bool) -> Result<()> {
    let action = semantic::paint(
        "will be permanently deleted",
        Tone::Destructive,
        color_enabled,
    );
    if plan.is_empty() {
        return stdoutln!("Purge plan: expired trash claim markers, if present, {action}.");
    }
    let noun = if plan.len() == 1 { "entry" } else { "entries" };
    stdoutln!(
        "Purge plan: {} reviewed trash {noun} will be considered; purge-supported entries {action}, while sealed entries with unsupported purge topology are retained and remain undoable.",
        plan.len(),
    )?;
    for entry in plan.entries() {
        stdoutln!("  {}", escape_terminal_text(&display_path(entry, home)))?;
    }
    Ok(())
}

fn print_human_report(
    report: &crate::lifecycle::PurgeReport,
    colors: crate::runtime::OutputColors,
) -> Result<()> {
    let noun = if report.purged.len() == 1 {
        "entry"
    } else {
        "entries"
    };
    stdoutln!("Purged {} trash {noun}", report.purged.len())?;
    for (entry, reason) in report.unpurged() {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Error,
            &render_failure(entry, reason),
            colors,
        );
    }
    for (entry, reason) in report.gaps() {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            &render_gap(entry, reason),
            colors,
        );
    }
    Ok(())
}

fn render_failure(entry: &Path, reason: &str) -> String {
    let entry = escape_terminal_text(&entry.display().to_string());
    let reason = escape_terminal_text(reason);
    format!("failed to purge {entry}: {reason}")
}

fn render_gap(entry: &Path, reason: &str) -> String {
    let entry = escape_terminal_text(&entry.display().to_string());
    let reason = escape_terminal_text(reason);
    format!("purged {entry}, but the outcome was not fully recorded: {reason}")
}

#[cfg(test)]
mod tests {
    use super::{json_report, render_failure};
    use crate::lifecycle::PurgeReport;
    use std::path::Path;

    fn keys(value: &serde_json::Value) -> Vec<&str> {
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    fn not_attempted() -> crate::native::QuotaActionReport {
        crate::native::not_attempted_action(
            crate::native::ActionResultOwner::TrashPurgeCommand,
            crate::native::ActionKind::TrashPurge,
            "trash:test",
            [],
            crate::native::NotStartedReason::Empty,
        )
        .unwrap()
    }

    #[test]
    fn an_entry_that_was_deleted_is_never_also_reported_as_failed() {
        let purged = Path::new("/trash/gone").to_path_buf();
        let kept = Path::new("/trash/kept").to_path_buf();
        let report = PurgeReport {
            purged: vec![purged.clone()],
            failed: vec![
                (
                    purged.clone(),
                    "operation log append failed: log full".to_owned(),
                ),
                (kept.clone(), "claim remains after failure".to_owned()),
            ],
        };

        let json = serde_json::to_value(json_report(&report, &not_attempted())).unwrap();

        assert_eq!(json["failed"].as_array().unwrap().len(), 1);
        assert_eq!(json["failed"][0]["path"], kept.display().to_string());
        assert_eq!(json["unrecorded"].as_array().unwrap().len(), 1);
        assert_eq!(json["unrecorded"][0]["path"], purged.display().to_string());
    }

    #[test]
    fn purge_failure_escapes_terminal_controls() {
        let rendered = render_failure(Path::new("/home/me/trash\u{1b}[31m"), "changed\nagain");
        assert_eq!(
            rendered,
            "failed to purge /home/me/trash\\u{1b}[31m: changed\\nagain"
        );

        let report = PurgeReport {
            purged: Vec::new(),
            failed: vec![(
                Path::new("/trash/entry").to_path_buf(),
                "changed".to_owned(),
            )],
        };
        let json = serde_json::to_value(json_report(&report, &not_attempted())).unwrap();
        assert_eq!(
            keys(&json),
            ["failed", "purged", "quota_observations", "unrecorded"]
        );
        assert_eq!(
            json["quota_observations"]["observation_state"],
            "not_attempted"
        );
        assert_eq!(keys(&json["failed"][0]), ["path", "reason"]);
    }
}
