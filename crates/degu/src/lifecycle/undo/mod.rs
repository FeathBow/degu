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
use super::mount;
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
    let sealed_paths = entries
        .iter()
        .filter(|entry| entry.reclamation_id() == reclamation_id)
        .map(|entry| {
            mount::entry_anchor(&ctx.home, entry)
                .map(|anchor| projected_paths(&anchor, entry))
                .with_context(|| {
                    format!(
                        "failed to project mount-domain mapping for transaction {:?}",
                        entry.transaction()
                    )
                })
        })
        .collect::<Result<HashSet<_>>>()?;
    let group = entries
        .iter()
        .filter(|entry| {
            entry.reclamation_id() == reclamation_id && sealed_undo_active(entry.state())
        })
        .map(|entry| {
            mount::entry_anchor(&ctx.home, entry)
                .map(|anchor| (entry, anchor))
                .with_context(|| {
                    format!(
                        "failed to reopen mount-domain anchor for verified undo transaction {:?}",
                        entry.transaction()
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let same_group_selection =
        selection::select_actionable_undo_group_named(records, &reclamation_id);
    if let Some(blocked) = block_mixed_group(
        &reclamation_id,
        &sealed_paths,
        same_group_selection.as_ref(),
    ) {
        trace_summary(&blocked, &reclamation_id);
        return Ok(Some(blocked));
    }

    let mut report = UndoReport::new(Some(reclamation_id.clone()));
    let mut recovery_blocked = false;
    for (entry, anchor) in group {
        let (original, trash_entry) = projected_paths(&anchor, entry);
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
        let request = match mount::open_pair_fds(&anchor) {
            Ok((source, destination)) => VerifiedUndoRequest::new(source, destination),
            Err(error) => {
                report.failed.push(UndoFailedEntry {
                    path: original,
                    trash_entry,
                    reason: format!("failed to open verified undo mount-domain anchors: {error}"),
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
    reclamation_id: &str,
    sealed_paths: &HashSet<(PathBuf, PathBuf)>,
    legacy_selection: Option<&selection::UndoSelection>,
) -> Option<UndoReport> {
    let selection = legacy_selection?;
    if selection.reclamation_id.as_deref() != Some(reclamation_id) {
        return None;
    }
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
            .any(|record| record.path == *path && record.trash_entry.as_ref() == Some(trash_entry))
        {
            report.failed.push(UndoFailedEntry {
                path: path.clone(),
                trash_entry: trash_entry.clone(),
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
    use degu_core::oplog::{OpAction, OpRecord};

    fn record(path: &str, trash: &str) -> OpRecord {
        OpRecord {
            ts: "2026-01-01T00:00:00Z".into(),
            tool_version: "test".into(),
            command: "clean".into(),
            action: OpAction::Trash,
            path: PathBuf::from(path),
            bytes_allocated: 1,
            inodes: 1,
            trash_entry: Some(PathBuf::from(trash)),
            reclamation_id: Some("group".into()),
            expected_identity: None,
            destination_parent: None,
            outcome: OpOutcome::Ok,
        }
    }

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

    #[test]
    fn terminal_wal_mapping_does_not_make_active_same_group_look_legacy() {
        let terminal = record("/source/old", "/trash/old");
        let active = record("/source/current", "/trash/current");
        let selection = selection::UndoSelection {
            targets: vec![terminal.clone(), active.clone()],
            ambiguous: Vec::new(),
            reclamation_id: Some("group".into()),
        };
        let sealed_paths = [
            (terminal.path.clone(), terminal.trash_entry.clone().unwrap()),
            (active.path.clone(), active.trash_entry.clone().unwrap()),
        ]
        .into_iter()
        .collect();
        assert!(block_mixed_group("group", &sealed_paths, Some(&selection)).is_none());
    }
}
