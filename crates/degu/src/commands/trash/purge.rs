use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use std::path::Path;

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

pub(super) fn run(json: bool, yes: bool, ui: Ui) -> Result<()> {
    let ctx = DetectCtx::from_process()?;
    if json && !yes {
        anyhow::bail!("--json requires --yes");
    }
    let mut session = Lifecycle::new(&ctx).lock()?;
    let plan = session.plan_purge_all()?;
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
        print_human_report(&report.purged, &report.failed, ui.colors)
            .and_then(|()| crate::native::print_human(&observation, ui.colors))
    };
    if !report.failed.is_empty() {
        anyhow::bail!("one or more trash entries failed to purge")
    }
    output_result
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
    let failed = report
        .failed
        .iter()
        .map(|(path, reason)| PurgeFailureJson { path, reason })
        .collect();
    PurgeJsonReport {
        purged: &report.purged,
        failed,
        quota_observations: crate::native::json(observation),
    }
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
    stdoutln!("Purge plan: all {} trash {noun} {action}.", plan.len(),)?;
    for entry in plan.entries() {
        stdoutln!("  {}", escape_terminal_text(&display_path(entry, home)))?;
    }
    Ok(())
}

fn print_human_report(
    purged: &[std::path::PathBuf],
    failed: &[(std::path::PathBuf, String)],
    colors: crate::runtime::OutputColors,
) -> Result<()> {
    let noun = if purged.len() == 1 {
        "entry"
    } else {
        "entries"
    };
    stdoutln!("Purged {} trash {noun}", purged.len())?;
    for (entry, reason) in failed {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Error,
            &render_failure(entry, reason),
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
        let observation = crate::native::not_attempted_action(
            crate::native::ActionResultOwner::TrashPurgeCommand,
            crate::native::ActionKind::TrashPurge,
            "trash:test",
            [],
            crate::native::NotStartedReason::Empty,
        )
        .unwrap();
        let json = serde_json::to_value(json_report(&report, &observation)).unwrap();
        assert_eq!(keys(&json), ["failed", "purged", "quota_observations"]);
        assert_eq!(
            json["quota_observations"]["observation_state"],
            "not_attempted"
        );
        assert_eq!(keys(&json["failed"][0]), ["path", "reason"]);
    }
}
