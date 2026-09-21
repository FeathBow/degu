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

/// Move staged entries back by hand when the store no longer authenticates.
///
/// `undo` refuses in this state for a good reason: an unauthenticated store is
/// not vouched for, so degu will not write its contents back on its own
/// authority. But the entries are ordinary files, their origins are recorded
/// outside the store, and `degu trash list` reads them without activating
/// anything — so refusing left people with data they could see, could not
/// recover through degu, and no next step.
///
/// This does not activate the store, open the WAL, or pretend the contents are
/// verified. It moves files and says so. The broken store is then renamed
/// aside, not deleted, so `degu init` can set the account up again and the
/// evidence survives for whoever wants to look at it.
/// Rename an authority whose store is gone, so setup can run again.
fn archive_lost_authority(anchor: &std::path::Path, ui: crate::runtime::Ui) -> Result<()> {
    stdoutln!(
        "The recorded authority at {} no longer has the store it authenticated. Nothing staged \
         under it can be recovered: the store is gone, not unreadable.",
        escaped(&anchor.display().to_string())
    )?;
    if !crate::commands::prompt::confirm_restore_unverified(ui.colors)? {
        stdoutln!("Canceled; nothing was moved.")?;
        return Ok(());
    }
    let archived = archived_name(anchor);
    std::fs::rename(anchor, &archived)?;
    stdoutln!(
        "The stale authority was archived to\n  {}\nNothing was deleted. Run 'degu init' to set \
         this account up again.",
        escaped(&archived.display().to_string())
    )
}

fn archived_name(path: &std::path::Path) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    path.with_file_name(format!(
        "{}.broken-{stamp}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn rescue_unauthenticated(ui: crate::runtime::Ui) -> Result<()> {
    use degu_core::activation::StoreActivationKind;

    let ctx = degu_core::ecosystem::DetectCtx::from_process()?;
    // Recovery shows up two ways: readiness succeeds and reports an activation
    // that no longer matches its store, or it fails outright. Anything else
    // means the normal path works and this one has no business running.
    let anchor = match degu_core::activation::check_current_euid_authority_readiness() {
        Ok(readiness) => match readiness.activation() {
            StoreActivationKind::Lost | StoreActivationKind::CorruptOrReplaced => {
                readiness.path().to_path_buf()
            }
            _ => anyhow::bail!(
                "this account's store authenticates; run 'degu undo' without \
                 --accept-unauthenticated-store"
            ),
        },
        Err(degu_core::activation::StoreActivationError::SelectedAuthorityLost {
            selected,
            ..
        }) => selected,
        Err(other) => return Err(anyhow::Error::new(other)),
    };

    let store = crate::lifecycle::sealed_staging_store_path(&ctx);
    // The authority can outlive the store it authenticated. There is nothing
    // to move back then — the entries went with it — but the stale anchor
    // still blocks setup, and clearing it is the way out this command exists
    // to give.
    if !store.exists() {
        return archive_lost_authority(&anchor, ui);
    }

    let entries = Lifecycle::new(&ctx).trash_entries()?;

    let restorable: Vec<_> = entries
        .iter()
        .filter_map(|entry| entry.original.as_ref().map(|origin| (entry, origin)))
        .collect();
    stdoutln!(
        "The store at {} no longer authenticates. These entries are readable, but degu cannot \
         verify their contents are what it staged.",
        escaped(&store.display().to_string())
    )?;
    for (entry, origin) in &restorable {
        stdoutln!(
            "  {} -> {}",
            escaped(&entry.entry.display().to_string()),
            escaped(&origin.display().to_string())
        )?;
    }
    let unknown = entries.len() - restorable.len();
    if unknown > 0 {
        stdoutln!("  {unknown} entries record no origin and are left where they are.")?;
    }

    if !crate::commands::prompt::confirm_restore_unverified(ui.colors)? {
        stdoutln!("Canceled; nothing was moved.")?;
        return Ok(());
    }

    let mut restored = 0usize;
    for (entry, origin) in &restorable {
        if origin.exists() {
            stdoutln!(
                "  skipped {}: something already occupies it",
                escaped(&origin.display().to_string())
            )?;
            continue;
        }
        if let Some(parent) = origin.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::rename(&entry.entry, origin) {
            Ok(()) => {
                restored += 1;
                stdoutln!(
                    "  restored {} (contents not verified)",
                    escaped(&origin.display().to_string())
                )?;
            }
            Err(error) => stdoutln!(
                "  failed {}: {error}",
                escaped(&origin.display().to_string())
            )?,
        }
    }

    if store.exists() {
        let archived = archived_name(&store);
        std::fs::rename(&store, &archived)?;
        stdoutln!(
            "\nThe unauthenticated store was archived to\n  {}\nNothing was deleted. Run 'degu \
             init' to set this account up again, or keep the archive for investigation.",
            escaped(&archived.display().to_string())
        )?;
    }
    stdoutln!("\nMoved {restored} of {} entries.", restorable.len())
}

pub(crate) fn run(
    accept_unauthenticated_store: bool,
    json: bool,
    ui: crate::runtime::Ui,
) -> Result<()> {
    if accept_unauthenticated_store {
        return rescue_unauthenticated(ui);
    }
    let ctx = degu_core::ecosystem::DetectCtx::from_process()?;
    let mut session = Lifecycle::new(&ctx).lock()?;
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
