use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use degu_core::oplog::{ObjectIdentity, OpOutcome, OpRecord};

use super::super::EntryIdentity;
use super::super::journal::{OperationLog, RestoreRecord, restore_record};
use super::report::{UndoAmbiguousEntry, UndoEntry, UndoFailedEntry, UndoLogFailure, UndoReport};
use super::selection::UndoSelection;
use failure::RestoreFailure;

mod failure;
#[cfg(test)]
mod tests;

pub(super) fn restore_selection(
    log: &OperationLog,
    selection: UndoSelection,
    blocker: &dyn Fn(&Path) -> Option<String>,
) -> Result<UndoReport> {
    let mut append = |record: &OpRecord| log.append(record);
    restore_selection_with_blocker(selection, &mut append, blocker)
}

#[cfg(test)]
fn restore_selection_with_append(
    selection: UndoSelection,
    append: &mut dyn FnMut(&OpRecord) -> std::io::Result<()>,
) -> Result<UndoReport> {
    restore_selection_with_blocker(selection, append, &|_| None)
}

fn restore_selection_with_blocker(
    selection: UndoSelection,
    append: &mut dyn FnMut(&OpRecord) -> std::io::Result<()>,
    blocker: &dyn Fn(&Path) -> Option<String>,
) -> Result<UndoReport> {
    let mut run = RestoreRun {
        append,
        blocker,
        reclamation_id: selection.reclamation_id.clone(),
        report: UndoReport::new(selection.reclamation_id),
    };
    for target in selection.targets {
        run.restore(target)?;
    }
    let selected_ambiguous = selection
        .ambiguous
        .into_iter()
        .map(ambiguous_undo_entry)
        .collect::<Result<Vec<_>>>()?;
    run.report.ambiguous.extend(selected_ambiguous);
    Ok(run.report)
}

struct RestoreRun<'a> {
    append: &'a mut dyn FnMut(&OpRecord) -> std::io::Result<()>,
    blocker: &'a dyn Fn(&Path) -> Option<String>,
    reclamation_id: Option<String>,
    report: UndoReport,
}

impl RestoreRun<'_> {
    fn restore(&mut self, target: OpRecord) -> Result<()> {
        let trash_entry = target
            .trash_entry
            .clone()
            .context("undo target missing trash entry")?;
        let Some(identity) = self.capture_identity(&target, &trash_entry)? else {
            return Ok(());
        };
        if let Some(reason) = (self.blocker)(&trash_entry) {
            self.report.failed.push(UndoFailedEntry {
                path: target.path,
                trash_entry,
                reason,
            });
            return Ok(());
        }
        if let Err(error) = self.append_record(RestoreAppend {
            target: &target,
            trash_entry: &trash_entry,
            expected_identity: Some(identity.oplog_identity()),
            outcome: OpOutcome::Pending,
        }) {
            self.record_pending_failure(PendingFailure {
                path: target.path,
                trash_entry,
                error,
            });
            return Ok(());
        }
        let restore = restore_entry(RestoreEntry {
            identity: &identity,
            trash_entry: &trash_entry,
            original: &target.path,
            destination_parent: target.destination_parent,
        });
        let outcome = restore_outcome(&restore);
        let final_append = self.append_record(RestoreAppend {
            target: &target,
            trash_entry: &trash_entry,
            expected_identity: None,
            outcome: outcome.clone(),
        });
        trace_restore(&target.path, &outcome);
        self.record_attempt(RestoreAttempt {
            path: target.path,
            trash_entry,
            restore,
            final_append,
        });
        Ok(())
    }

    fn capture_identity(
        &mut self,
        target: &OpRecord,
        trash_entry: &Path,
    ) -> Result<Option<EntryIdentity>> {
        match EntryIdentity::capture(trash_entry) {
            Ok(identity) => {
                if !recorded_authorizes(target, &identity) {
                    self.report
                        .ambiguous
                        .push(ambiguous_undo_entry(target.clone())?);
                    return Ok(None);
                }
                Ok(Some(identity))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.report.gone.push(UndoEntry {
                    path: target.path.clone(),
                    trash_entry: trash_entry.to_path_buf(),
                });
                tracing::info!(
                    target: "degu",
                    path = %target.path.display(),
                    outcome = "gone",
                    "undo item executed"
                );
                Ok(None)
            }
            Err(err) => Err(err).with_context(|| {
                format!("failed to inspect trash entry {}", trash_entry.display())
            }),
        }
    }

    fn append_record(&mut self, request: RestoreAppend<'_>) -> std::io::Result<()> {
        let record = restore_record(RestoreRecord {
            target: request.target,
            trash_entry: request.trash_entry,
            reclamation_id: self.reclamation_id.clone(),
            expected_identity: request.expected_identity,
            outcome: request.outcome,
        });
        (self.append)(&record)
    }

    fn record_pending_failure(&mut self, failure: PendingFailure) {
        let reason = format!(
            "operation log append failed before restore: {}; no changes were made",
            failure.error
        );
        self.report.failed.push(UndoFailedEntry {
            path: failure.path.clone(),
            trash_entry: failure.trash_entry.clone(),
            reason: reason.clone(),
        });
        self.report.log_failures.push(UndoLogFailure {
            path: failure.path,
            trash_entry: failure.trash_entry,
            reason,
            restored: false,
        });
    }

    fn record_attempt(&mut self, attempt: RestoreAttempt) {
        let (restored, restore_error) = match attempt.restore {
            Ok(()) => {
                self.report.restored.push(UndoEntry {
                    path: attempt.path.clone(),
                    trash_entry: attempt.trash_entry.clone(),
                });
                (true, None)
            }
            Err(error) => {
                let reason = error.reason();
                self.report.failed.push(UndoFailedEntry {
                    path: attempt.path.clone(),
                    trash_entry: attempt.trash_entry.clone(),
                    reason: reason.clone(),
                });
                (false, Some(reason))
            }
        };
        if let Err(error) = attempt.final_append {
            let reason = match restore_error {
                Some(restore_error) => format!(
                    "restore failed: {restore_error}; final operation log append also failed: {error}"
                ),
                None => format!("final operation log append failed: {error}"),
            };
            self.report.log_failures.push(UndoLogFailure {
                path: attempt.path.clone(),
                trash_entry: attempt.trash_entry,
                reason,
                restored,
            });
        }
    }
}

struct RestoreAppend<'a> {
    target: &'a OpRecord,
    trash_entry: &'a Path,
    expected_identity: Option<ObjectIdentity>,
    outcome: OpOutcome,
}

struct PendingFailure {
    path: PathBuf,
    trash_entry: PathBuf,
    error: std::io::Error,
}

struct RestoreAttempt {
    path: PathBuf,
    trash_entry: PathBuf,
    restore: std::result::Result<(), RestoreFailure>,
    final_append: std::io::Result<()>,
}

/// Restore authority flows from the staging record, not from whatever object
/// now sits at the trash path: a replacement planted after selection would
/// otherwise be captured here and restored under the record's name. `Ok`
/// records demand the exact recorded identity; an interrupted `Pending` stage
/// accepts the same object whose ctime the stage rename bumped; a record with
/// no identity cannot authorize anything.
fn recorded_authorizes(target: &OpRecord, current: &EntryIdentity) -> bool {
    let Some(recorded) = target.expected_identity else {
        return false;
    };
    match target.outcome {
        OpOutcome::Ok => current.oplog_identity() == recorded,
        OpOutcome::Pending => current.oplog_identity().same_object(&recorded),
        OpOutcome::Failed { .. } => false,
    }
}

fn ambiguous_undo_entry(record: OpRecord) -> Result<UndoAmbiguousEntry> {
    let trash_entry = record
        .trash_entry
        .context("ambiguous undo record missing trash entry")?;
    let reclamation_id = record.reclamation_id;
    tracing::info!(
        target: "degu",
        path = %record.path.display(),
        trash_entry = %trash_entry.display(),
        source_reclamation_id = reclamation_id.as_deref().unwrap_or("-"),
        outcome = "ambiguous",
        "undo item skipped"
    );
    Ok(UndoAmbiguousEntry {
        path: record.path,
        trash_entry,
        reclamation_id,
    })
}

fn restore_outcome(restore: &std::result::Result<(), RestoreFailure>) -> OpOutcome {
    match restore {
        Ok(()) => OpOutcome::Ok,
        Err(err) => OpOutcome::Failed {
            reason: err.reason(),
        },
    }
}

struct RestoreEntry<'a> {
    identity: &'a EntryIdentity,
    trash_entry: &'a Path,
    original: &'a Path,
    destination_parent: Option<ObjectIdentity>,
}

fn restore_entry(request: RestoreEntry<'_>) -> std::result::Result<(), RestoreFailure> {
    // Legacy records predate destination-parent capture; without it the restore
    // destination cannot be authenticated against an ancestor-symlink swap, so
    // refuse before touching the filesystem and leave the trash entry in place.
    let Some(destination_parent) = request.destination_parent else {
        return Err(RestoreFailure::unauthenticated_parent(
            request.original,
            request.trash_entry,
        ));
    };
    degu_walk::validate_single_mount_tree(request.trash_entry)
        .map_err(|error| RestoreFailure::at_trash_source(request.trash_entry, error))?;
    request
        .identity
        .rename_verified_into_parent(request.trash_entry, request.original, destination_parent)
        .map(|_| ())
        .map_err(|error| RestoreFailure::from_rename(request.trash_entry, error))
}

fn trace_restore(path: &Path, outcome: &OpOutcome) {
    let outcome = match outcome {
        OpOutcome::Pending => "pending",
        OpOutcome::Ok => "ok",
        OpOutcome::Failed { .. } => "failed",
    };
    tracing::info!(target: "degu", path = %path.display(), outcome, "undo item executed");
}
