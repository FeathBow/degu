use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use degu_core::oplog::{
    ObjectIdentity, OpAction, OpOutcome, OpRecord, PendingProbe, PendingState,
    reconcile_pending_move,
};

pub(crate) struct TrashOplogInfo {
    pub(crate) staged_at: Option<jiff::Timestamp>,
    pub(crate) original: PathBuf,
    /// The recorded operation state or object identity cannot be confirmed.
    pub(crate) ambiguous: bool,
}

pub(crate) fn reconciled_trash_info(records: &[OpRecord]) -> HashMap<PathBuf, TrashOplogInfo> {
    let ActiveTrashState {
        indices,
        ambiguous_restores,
    } = active_trash_state(records);
    indices
        .into_iter()
        .filter_map(|index| reconciled_record_info(&records[index]))
        .map(|(entry, mut info)| {
            info.ambiguous |= ambiguous_restores.contains(&entry);
            (entry, info)
        })
        .collect()
}

pub(crate) fn reconciled_record_info(record: &OpRecord) -> Option<(PathBuf, TrashOplogInfo)> {
    let entry = record.trash_entry.clone()?;
    let ambiguous = match record.outcome {
        OpOutcome::Ok => match recorded_entry_state(record, &entry) {
            RecordedEntryState::Match => false,
            RecordedEntryState::Missing => return None,
            RecordedEntryState::Ambiguous => true,
        },
        OpOutcome::Pending => pending_ambiguity(record, &entry)?,
        OpOutcome::Failed { .. } if probe_exists_no_follow(&entry) => true,
        OpOutcome::Failed { .. } => return None,
    };
    let info = TrashOplogInfo {
        staged_at: record.ts.parse::<jiff::Timestamp>().ok(),
        original: record.path.clone(),
        ambiguous,
    };
    Some((entry, info))
}

fn pending_ambiguity(record: &OpRecord, entry: &Path) -> Option<bool> {
    match reconcile_pending_record(record, entry) {
        PendingState::Moved => Some(false),
        PendingState::AmbiguousBothExist | PendingState::AmbiguousIdentity => Some(true),
        PendingState::NotMoved | PendingState::AmbiguousBothMissing => None,
    }
}

#[cfg(test)]
pub(crate) fn active_trash_indices(records: &[OpRecord]) -> Vec<usize> {
    active_trash_state(records).indices
}

pub(crate) struct ActiveTrashState {
    pub(crate) indices: Vec<usize>,
    pub(crate) ambiguous_restores: HashSet<PathBuf>,
}

pub(crate) fn active_trash_state(records: &[OpRecord]) -> ActiveTrashState {
    let mut scan = ActiveTrashScan::default();
    for (index, record) in records.iter().enumerate().rev() {
        scan.visit(index, record);
    }
    ActiveTrashState {
        indices: scan.active,
        ambiguous_restores: scan.ambiguous_restores,
    }
}

#[derive(Default)]
struct ActiveTrashScan {
    named_later: HashSet<PathBuf>,
    restored: HashSet<PathBuf>,
    purged: HashSet<PathBuf>,
    named_restore_later: HashSet<PathBuf>,
    ambiguous_restores: HashSet<PathBuf>,
    active: Vec<usize>,
}

impl ActiveTrashScan {
    fn visit(&mut self, index: usize, record: &OpRecord) {
        match (&record.action, &record.outcome, &record.trash_entry) {
            (OpAction::Restore, outcome, Some(entry)) => self.visit_restore(RestoreVisit {
                record,
                entry,
                outcome,
            }),
            (OpAction::Purge, OpOutcome::Ok, None) => {
                self.purged.insert(record.path.clone());
            }
            (OpAction::Trash, outcome, Some(entry)) => self.visit_trash(TrashVisit {
                index,
                entry,
                outcome,
            }),
            _ => {}
        }
    }

    fn visit_restore(&mut self, visit: RestoreVisit<'_>) {
        if self.named_later.contains(visit.entry) {
            return;
        }
        if !self.named_restore_later.insert(visit.entry.to_path_buf()) {
            return;
        }
        match visit.outcome {
            OpOutcome::Ok => {
                self.restored.insert(visit.entry.to_path_buf());
            }
            OpOutcome::Pending => match reconcile_pending_restore(visit.record, visit.entry) {
                PendingState::Moved => {
                    self.restored.insert(visit.entry.to_path_buf());
                }
                PendingState::AmbiguousBothExist
                | PendingState::AmbiguousBothMissing
                | PendingState::AmbiguousIdentity => {
                    self.ambiguous_restores.insert(visit.entry.to_path_buf());
                }
                PendingState::NotMoved => {}
            },
            OpOutcome::Failed { .. } => {}
        }
    }

    fn visit_trash(&mut self, visit: TrashVisit<'_>) {
        let active = matches!(visit.outcome, OpOutcome::Pending | OpOutcome::Ok)
            || matches!(visit.outcome, OpOutcome::Failed { .. })
                && probe_exists_no_follow(visit.entry);
        if active
            && !self.named_later.contains(visit.entry)
            && !self.restored.contains(visit.entry)
            && !self.purged.contains(visit.entry)
        {
            self.active.push(visit.index);
        }
        self.named_later.insert(visit.entry.to_path_buf());
    }
}

struct RestoreVisit<'a> {
    record: &'a OpRecord,
    entry: &'a Path,
    outcome: &'a OpOutcome,
}

struct TrashVisit<'a> {
    index: usize,
    entry: &'a Path,
    outcome: &'a OpOutcome,
}

pub(crate) fn reconcile_pending_record(record: &OpRecord, entry: &Path) -> PendingState {
    reconcile_pending_move(
        identity_probe(&record.path),
        identity_probe(entry),
        record.expected_identity,
    )
}

fn identity_probe(path: &Path) -> PendingProbe {
    match ObjectIdentity::capture(path) {
        Ok(identity) => PendingProbe::Present(identity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PendingProbe::Missing,
        Err(_) => PendingProbe::Failed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordedEntryState {
    Match,
    Missing,
    Ambiguous,
}

pub(crate) fn recorded_entry_state(record: &OpRecord, entry: &Path) -> RecordedEntryState {
    match ObjectIdentity::capture(entry) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RecordedEntryState::Missing,
        Err(_) => RecordedEntryState::Ambiguous,
        Ok(actual) if record.expected_identity == Some(actual) => RecordedEntryState::Match,
        Ok(_) => RecordedEntryState::Ambiguous,
    }
}

fn reconcile_pending_restore(record: &OpRecord, entry: &Path) -> PendingState {
    reconcile_pending_move(
        identity_probe(entry),
        identity_probe(&record.path),
        record.expected_identity,
    )
}

pub(crate) fn probe_exists_no_follow(path: &Path) -> bool {
    // Probe errors must remain ambiguous rather than authorize restore or expiry.
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(err) => err.kind() != std::io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests;
