mod report;
mod restore;
mod selection;

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use degu_core::authority::TransactionState;
use degu_core::ecosystem::DetectCtx;
use degu_core::oplog::OpOutcome;
use degu_core::seal_wal::TransactionId;
use degu_core::sealed_staging::{
    ProductionStagingEntry, ReadyStagingEngine, VerifiedUndoFailureDisposition, VerifiedUndoRequest,
};

use super::journal::{OperationLog, VerifiedRestoreRecord, verified_restore_record};
use restore::restore_selection;
use selection::select_actionable_undo_group;

pub(crate) use report::{
    UndoAmbiguousEntry, UndoEntry, UndoFailedEntry, UndoLogFailure, UndoReport,
};

pub(crate) fn undo_latest(
    ctx: &DetectCtx,
    engine: Option<&mut ReadyStagingEngine>,
    blocker: &dyn Fn(&Path) -> Option<String>,
) -> Result<Option<UndoReport>> {
    let log = OperationLog::new(ctx);
    let records = log.read()?;
    let legacy_selection = select_actionable_undo_group(&records);

    if let Some(engine) = engine
        && let Some(report) = undo_latest_verified(ctx, &log, &records, engine)?
    {
        return Ok(Some(report));
    }

    let Some(selection) = legacy_selection else {
        return Ok(None);
    };
    let reclamation_label = selection
        .reclamation_id
        .clone()
        .unwrap_or_else(|| "-".to_string());
    let span = tracing::info_span!(target: "degu", "undo", reclamation_id = %reclamation_label);
    let _guard = span.enter();
    let report = restore_selection(&log, selection, blocker)?;
    trace_summary(&report, &reclamation_label);
    Ok(Some(report))
}

fn undo_latest_verified(
    ctx: &DetectCtx,
    log: &OperationLog,
    records: &[degu_core::oplog::OpRecord],
    engine: &mut ReadyStagingEngine,
) -> Result<Option<UndoReport>> {
    let entries = engine.production_entries();
    let Some(latest) = entries
        .iter()
        .rev()
        .find(|entry| sealed_undo_active(entry.state()))
    else {
        return Ok(None);
    };
    let reclamation_id = latest.reclamation_id().to_owned();
    let canonical_home = std::fs::canonicalize(&ctx.home)
        .context("failed to authenticate canonical HOME for verified undo")?;
    let group = entries
        .iter()
        .filter(|entry| entry.reclamation_id() == reclamation_id)
        .collect::<Vec<_>>();

    let same_group_selection =
        selection::select_actionable_undo_group_named(records, &reclamation_id);
    if let Some(blocked) = block_mixed_group(
        &canonical_home,
        &reclamation_id,
        &group,
        same_group_selection.as_ref(),
    ) {
        trace_summary(&blocked, &reclamation_id);
        return Ok(Some(blocked));
    }

    let mut report = UndoReport::new(Some(reclamation_id.clone()));
    let mut recovery_blocked = false;
    for entry in group
        .into_iter()
        .filter(|entry| sealed_undo_active(entry.state()))
    {
        let (original, trash_entry) = projected_paths(&canonical_home, entry);
        if entry.state() == TransactionState::UndoConflict {
            report.ambiguous.push(UndoAmbiguousEntry {
                path: original,
                trash_entry,
                reclamation_id: Some(reclamation_id.clone()),
            });
            continue;
        }
        if recovery_blocked {
            report.failed.push(UndoFailedEntry {
                path: original,
                trash_entry,
                reason: "an earlier verified undo in this group requires startup recovery; no later item was attempted".into(),
            });
            continue;
        }
        let Some(token) = engine.verified_undo_token(entry.transaction(), &reclamation_id) else {
            report.failed.push(UndoFailedEntry {
                path: original,
                trash_entry,
                reason:
                    "the exact leased WAL could not mint this mapping's one-use verified undo token"
                        .into(),
            });
            continue;
        };
        let request = match (
            open_directory(&canonical_home),
            open_directory(&canonical_home),
        ) {
            (Ok(source), Ok(destination)) => VerifiedUndoRequest::new(source, destination),
            (Err(error), _) | (_, Err(error)) => {
                report.failed.push(UndoFailedEntry {
                    path: original,
                    trash_entry,
                    reason: format!("failed to open verified undo HOME anchors: {error}"),
                });
                continue;
            }
        };

        match engine.undo_verified(token, request) {
            Ok(commit) => {
                debug_assert_eq!(commit.transaction(), entry.transaction());
                report.restored.push(UndoEntry {
                    path: original.clone(),
                    trash_entry: trash_entry.clone(),
                });
                let projection = verified_restore_record(VerifiedRestoreRecord {
                    path: &original,
                    trash_entry: &trash_entry,
                    reclamation_id: &reclamation_id,
                    outcome: OpOutcome::Ok,
                });
                if let Err(error) = log.append(&projection) {
                    report.log_failures.push(UndoLogFailure {
                        path: original,
                        trash_entry,
                        reason: format!(
                            "verified undo completed durably, but the non-authoritative operation log append failed: {error}"
                        ),
                        restored: true,
                    });
                }
            }
            Err(error) => {
                recovery_blocked = matches!(
                    error.disposition(),
                    VerifiedUndoFailureDisposition::RecoveryBlocked
                );
                if matches!(
                    error.disposition(),
                    VerifiedUndoFailureDisposition::Terminal(TransactionState::UndoConflict)
                ) {
                    report.ambiguous.push(UndoAmbiguousEntry {
                        path: original,
                        trash_entry,
                        reclamation_id: Some(reclamation_id.clone()),
                    });
                } else {
                    report.failed.push(UndoFailedEntry {
                        path: original,
                        trash_entry,
                        reason: format!(
                            "verified undo transaction {} failed during {}: {error}",
                            transaction_hex(error.transaction()),
                            error.stage()
                        ),
                    });
                }
            }
        }
    }
    trace_summary(&report, &reclamation_id);
    Ok(Some(report))
}

fn block_mixed_group(
    canonical_home: &Path,
    reclamation_id: &str,
    sealed_group: &[&ProductionStagingEntry],
    legacy_selection: Option<&selection::UndoSelection>,
) -> Option<UndoReport> {
    let selection = legacy_selection?;
    if selection.reclamation_id.as_deref() != Some(reclamation_id) {
        return None;
    }
    let sealed_paths = sealed_group
        .iter()
        .map(|entry| projected_paths(canonical_home, entry))
        .collect::<HashSet<_>>();
    let selected = selection.targets.iter().chain(&selection.ambiguous);
    if selected.clone().all(|record| {
        record
            .trash_entry
            .as_ref()
            .is_some_and(|trash| sealed_paths.contains(&(record.path.clone(), trash.clone())))
    }) {
        return None;
    }

    let reason = "reclamation group mixes legacy/unmapped and WAL-sealed entries; whole-group authority is ambiguous, so no entry was moved";
    let mut report = UndoReport::new(Some(reclamation_id.to_owned()));
    for record in selection.targets.iter().chain(&selection.ambiguous) {
        if let Some(trash_entry) = &record.trash_entry {
            report.failed.push(UndoFailedEntry {
                path: record.path.clone(),
                trash_entry: trash_entry.clone(),
                reason: reason.into(),
            });
        }
    }
    for (path, trash_entry) in sealed_paths {
        if !selection
            .targets
            .iter()
            .chain(&selection.ambiguous)
            .any(|record| record.path == path && record.trash_entry.as_ref() == Some(&trash_entry))
        {
            report.failed.push(UndoFailedEntry {
                path,
                trash_entry,
                reason: reason.into(),
            });
        }
    }
    Some(report)
}

fn projected_paths(home: &Path, entry: &ProductionStagingEntry) -> (PathBuf, PathBuf) {
    (
        home.join(entry.source_parent().relative_path())
            .join(entry.source_basename()),
        home.join(entry.destination_parent().relative_path())
            .join(entry.destination_basename()),
    )
}

fn sealed_undo_active(state: TransactionState) -> bool {
    matches!(
        state,
        TransactionState::VerifiedCommitted | TransactionState::UndoConflict
    )
}

fn open_directory(path: &Path) -> std::io::Result<rustix::fd::OwnedFd> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
}

fn transaction_hex(transaction: TransactionId) -> String {
    let mut output = String::with_capacity(32);
    for byte in transaction.0 {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn trace_summary(report: &UndoReport, reclamation_label: &str) {
    tracing::info!(
        target: "degu",
        restored = report.restored.len(),
        failed = report.failure_count(),
        log_failures = report.log_failures.len(),
        gone = report.gone.len(),
        ambiguous = report.ambiguous.len(),
        reclamation_id = %reclamation_label,
        "undo summary"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_hex_is_fixed_width_and_adapter_local() {
        assert_eq!(
            transaction_hex(TransactionId([
                0x00, 0x01, 0x0f, 0x10, 0x2a, 0x7f, 0x80, 0xff, 0x55, 0xaa, 0x03, 0x30, 0x99, 0x09,
                0xd0, 0x0d,
            ])),
            "00010f102a7f80ff55aa03309909d00d"
        );
    }
}
