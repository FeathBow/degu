use crate::commands::guidance::{self, OutputMode, Request, UndoState, Workflow};
use crate::lifecycle::{
    Lifecycle, UndoAmbiguousEntry, UndoEntry, UndoFailedEntry, UndoLogFailure, UndoReport,
};
use crate::output::stdoutln;
use crate::presentation::escape_terminal_text as escaped;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

pub(crate) const NOTHING_TO_UNDO: &str = "Nothing to undo.";

#[derive(Serialize)]
struct UndoJson<'a> {
    reclamation_id: Option<&'a str>,
    restored: Vec<EntryJson<'a>>,
    failed: Vec<FailedJson<'a>>,
    log_failures: Vec<LogFailureJson<'a>>,
    gone: Vec<EntryJson<'a>>,
    ambiguous: Vec<AmbiguousJson<'a>>,
}

#[derive(Serialize)]
struct EntryJson<'a> {
    path: &'a Path,
    trash_entry: &'a Path,
}

#[derive(Serialize)]
struct AmbiguousJson<'a> {
    path: &'a Path,
    trash_entry: &'a Path,
    reclamation_id: Option<&'a str>,
}

#[derive(Serialize)]
struct FailedJson<'a> {
    path: &'a Path,
    trash_entry: &'a Path,
    reason: &'a str,
}

#[derive(Serialize)]
struct LogFailureJson<'a> {
    path: &'a Path,
    trash_entry: &'a Path,
    reason: &'a str,
    restored: bool,
}

pub(crate) fn run(json: bool, ui: crate::runtime::Ui) -> Result<()> {
    let ctx = degu_core::ecosystem::DetectCtx::from_process()?;
    let session = Lifecycle::new(&ctx).lock()?;
    let Some(report) = session.undo_latest()? else {
        print_none(json)?;
        return Ok(());
    };
    let output_result = print_report(json, &report).and_then(|()| {
        guidance::print(Request {
            output: if json {
                OutputMode::Json
            } else {
                OutputMode::Human(ui)
            },
            workflow: Workflow::Undo(UndoState {
                restored: report.restored.len(),
                failed: report.failure_count(),
                ambiguous: report.ambiguous_entries().count(),
            }),
            home: None,
        })
    });
    if report.has_failures() {
        anyhow::bail!("one or more undo operations did not complete cleanly")
    }
    if report.has_ambiguity() {
        anyhow::bail!("one or more entries have ambiguous staging state")
    }
    output_result
}

fn print_none(json: bool) -> Result<()> {
    if json {
        return print_json(&UndoReport::new(None));
    }
    stdoutln!("{NOTHING_TO_UNDO}")
}

fn print_report(json: bool, report: &UndoReport) -> Result<()> {
    if json {
        print_json(report)?;
    } else {
        print_human(report)?;
    }
    Ok(())
}

fn print_json(report: &UndoReport) -> Result<()> {
    stdoutln!("{}", serde_json::to_string_pretty(&json_report(report))?)
}

fn json_report(report: &UndoReport) -> UndoJson<'_> {
    UndoJson {
        reclamation_id: report.reclamation_id.as_deref(),
        restored: report
            .restored
            .iter()
            .map(|entry| EntryJson {
                path: &entry.path,
                trash_entry: &entry.trash_entry,
            })
            .collect(),
        failed: report
            .failed
            .iter()
            .map(|entry| FailedJson {
                path: &entry.path,
                trash_entry: &entry.trash_entry,
                reason: &entry.reason,
            })
            .collect(),
        log_failures: report
            .log_failures
            .iter()
            .map(|entry| LogFailureJson {
                path: &entry.path,
                trash_entry: &entry.trash_entry,
                reason: &entry.reason,
                restored: entry.restored,
            })
            .collect(),
        gone: report
            .gone
            .iter()
            .map(|entry| EntryJson {
                path: &entry.path,
                trash_entry: &entry.trash_entry,
            })
            .collect(),
        ambiguous: report
            .ambiguous_entries()
            .map(|entry| AmbiguousJson {
                path: &entry.path,
                trash_entry: &entry.trash_entry,
                reclamation_id: entry.reclamation_id.as_deref(),
            })
            .collect(),
    }
}

fn print_human(report: &UndoReport) -> Result<()> {
    for line in human_lines(report) {
        stdoutln!("{line}")?;
    }
    Ok(())
}

fn human_lines(report: &UndoReport) -> Vec<String> {
    let mut lines = report
        .ambiguous_entries()
        .map(render_ambiguous)
        .collect::<Vec<_>>();
    lines.extend(
        report
            .restored
            .iter()
            .filter(|entry| !has_log_failure(report, &entry.path, &entry.trash_entry))
            .map(render_restored),
    );
    lines.extend(
        report
            .failed
            .iter()
            .filter(|entry| !has_log_failure(report, &entry.path, &entry.trash_entry))
            .map(render_failed),
    );
    lines.extend(report.log_failures.iter().map(render_log_failure));
    lines.extend(report.gone.iter().map(render_gone));
    lines.push(render_summary(report));
    lines
}

fn render_ambiguous(entry: &UndoAmbiguousEntry) -> String {
    let path = escaped_path(&entry.path);
    let reclamation = escaped(entry.reclamation_id.as_deref().unwrap_or("-"));
    let trash_entry = escaped_path(&entry.trash_entry);
    format!(
        "ambiguous {path} from reclamation {reclamation} (cannot verify original and trash entry state at {trash_entry}; no changes made)"
    )
}

fn render_restored(entry: &UndoEntry) -> String {
    format!("restored {}", escaped_path(&entry.path))
}

fn render_failed(entry: &UndoFailedEntry) -> String {
    format!(
        "failed {}: {}",
        escaped_path(&entry.path),
        escaped(&entry.reason)
    )
}

fn render_log_failure(entry: &UndoLogFailure) -> String {
    let path = escaped_path(&entry.path);
    let reason = escaped(&entry.reason);
    if entry.restored {
        format!("restored {path}, but {reason}")
    } else {
        format!("failed {path}: {reason}")
    }
}

fn has_log_failure(report: &UndoReport, path: &Path, trash_entry: &Path) -> bool {
    report
        .log_failures
        .iter()
        .any(|failure| failure.path == path && failure.trash_entry == trash_entry)
}

fn render_gone(entry: &UndoEntry) -> String {
    format!("gone {} (trash entry missing)", escaped_path(&entry.path))
}

fn render_summary(report: &UndoReport) -> String {
    let total = [
        report.restored.len(),
        report.failed.len(),
        report.gone.len(),
        report.ambiguous.len(),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add);
    format!(
        "Restored {} of {} from reclamation {}.",
        report.restored.len(),
        total,
        escaped(report.reclamation_id.as_deref().unwrap_or("-"))
    )
}

fn escaped_path(path: &Path) -> String {
    escaped(&path.display().to_string())
}

#[cfg(test)]
#[path = "undo/tests.rs"]
mod tests;
