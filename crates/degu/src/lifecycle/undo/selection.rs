use std::collections::HashSet;

use degu_core::oplog::{OpAction, OpOutcome, OpRecord, PendingState};

#[cfg(test)]
use super::super::reconcile::active_trash_indices;
use super::super::reconcile::{
    RecordedEntryState, active_trash_state, reconcile_pending_record, recorded_entry_state,
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
enum UndoGroup {
    Run(String),
    Single(usize),
}

pub(super) struct UndoSelection {
    pub(super) targets: Vec<OpRecord>,
    pub(super) ambiguous: Vec<OpRecord>,
    pub(super) reclamation_id: Option<String>,
}

enum UndoRecordClass {
    Restorable(OpRecord),
    Gone(OpRecord),
    Ambiguous(OpRecord),
    Ignore,
}

fn classify_undo_record(
    record: &OpRecord,
    ambiguous_restores: &HashSet<std::path::PathBuf>,
) -> UndoRecordClass {
    let Some(entry) = &record.trash_entry else {
        return UndoRecordClass::Ignore;
    };
    if ambiguous_restores.contains(entry) {
        return UndoRecordClass::Ambiguous(record.clone());
    }
    match &record.outcome {
        OpOutcome::Failed { .. } => UndoRecordClass::Ambiguous(record.clone()),
        OpOutcome::Ok => classify_recorded_entry(record, entry),
        OpOutcome::Pending => classify_pending_entry(record, entry),
    }
}

fn classify_recorded_entry(record: &OpRecord, entry: &std::path::Path) -> UndoRecordClass {
    match recorded_entry_state(record, entry) {
        RecordedEntryState::Match => UndoRecordClass::Restorable(record.clone()),
        RecordedEntryState::Missing => UndoRecordClass::Gone(record.clone()),
        RecordedEntryState::Ambiguous => UndoRecordClass::Ambiguous(record.clone()),
    }
}

fn classify_pending_entry(record: &OpRecord, entry: &std::path::Path) -> UndoRecordClass {
    match reconcile_pending_record(record, entry) {
        PendingState::Moved => UndoRecordClass::Restorable(record.clone()),
        PendingState::NotMoved => UndoRecordClass::Ignore,
        PendingState::AmbiguousBothExist
        | PendingState::AmbiguousBothMissing
        | PendingState::AmbiguousIdentity => UndoRecordClass::Ambiguous(record.clone()),
    }
}

fn classify_undo_group(
    group: &[OpRecord],
    ambiguous_restores: &HashSet<std::path::PathBuf>,
) -> (UndoSelection, bool) {
    let mut selection = UndoSelection {
        targets: Vec::new(),
        ambiguous: Vec::new(),
        reclamation_id: None,
    };
    let mut has_restorable = false;
    for record in group {
        match classify_undo_record(record, ambiguous_restores) {
            UndoRecordClass::Restorable(record) => {
                has_restorable = true;
                selection.targets.push(record);
            }
            UndoRecordClass::Gone(record) => selection.targets.push(record),
            UndoRecordClass::Ambiguous(record) => selection.ambiguous.push(record),
            UndoRecordClass::Ignore => {}
        }
    }
    selection.reclamation_id = undo_group_reclamation_id(group);
    (selection, has_restorable)
}

pub(super) fn select_actionable_undo_group(records: &[OpRecord]) -> Option<UndoSelection> {
    let state = active_trash_state(records);
    let active = state.indices.into_iter().collect();
    let mut end = records.len();
    while let Some(group) = select_undo_group_with_active(&records[..end], &active) {
        let (selection, has_restorable) = classify_undo_group(&group, &state.ambiguous_restores);
        if has_restorable || !selection.ambiguous.is_empty() {
            return Some(selection);
        }
        let Some(cutoff) = selected_group_cutoff(&records[..end], &group) else {
            break;
        };
        end = cutoff;
    }
    None
}

/// Selects one exact active reclamation group independently of whichever JSONL
/// group is globally newest. Sealed WAL group classification must use this so a
/// newer unrelated legacy group cannot hide an unmapped same-group member.
pub(super) fn select_actionable_undo_group_named(
    records: &[OpRecord],
    reclamation_id: &str,
) -> Option<UndoSelection> {
    let state = active_trash_state(records);
    let active = state.indices.into_iter().collect::<HashSet<_>>();
    let group = records
        .iter()
        .enumerate()
        .filter(|(index, record)| {
            active.contains(index)
                && record.reclamation_id.as_deref() == Some(reclamation_id)
                && matches!(
                    (&record.action, &record.outcome, &record.trash_entry),
                    (
                        OpAction::Trash,
                        OpOutcome::Ok | OpOutcome::Pending | OpOutcome::Failed { .. },
                        Some(_)
                    )
                )
        })
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    if group.is_empty() {
        return None;
    }
    let (selection, _) = classify_undo_group(&group, &state.ambiguous_restores);
    Some(selection)
}

fn selected_group_cutoff(records: &[OpRecord], group: &[OpRecord]) -> Option<usize> {
    group
        .iter()
        .filter_map(|selected| records.iter().rposition(|record| record == selected))
        .min()
}

#[cfg(test)]
pub(crate) fn select_undo_group(records: &[OpRecord]) -> Option<Vec<OpRecord>> {
    let active = active_trash_indices(records).into_iter().collect();
    select_undo_group_with_active(records, &active)
}

fn select_undo_group_with_active(
    records: &[OpRecord],
    active: &HashSet<usize>,
) -> Option<Vec<OpRecord>> {
    let mut selected = None;
    let mut targets = Vec::new();
    for (index, record) in records.iter().enumerate().rev() {
        if !is_undo_candidate(record, index, active) {
            continue;
        }
        let group = undo_group_for_record(record, index);
        if selected.is_none() {
            selected = Some(group.clone());
        }
        if selected.as_ref() == Some(&group) {
            targets.push(record.clone());
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn is_undo_candidate(record: &OpRecord, index: usize, active: &HashSet<usize>) -> bool {
    matches!(
        (&record.action, &record.outcome, &record.trash_entry),
        (
            OpAction::Trash,
            OpOutcome::Ok | OpOutcome::Pending | OpOutcome::Failed { .. },
            Some(_)
        )
    ) && active.contains(&index)
}

fn undo_group_for_record(record: &OpRecord, index: usize) -> UndoGroup {
    match &record.reclamation_id {
        Some(id) => UndoGroup::Run(id.clone()),
        None => UndoGroup::Single(index),
    }
}

fn undo_group_reclamation_id(records: &[OpRecord]) -> Option<String> {
    records
        .iter()
        .find_map(|record| record.reclamation_id.clone())
}
