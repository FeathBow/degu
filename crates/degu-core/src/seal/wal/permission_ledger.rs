use super::{ApplicationStatus, DurablePermission, PermissionResolution, TransactionState};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct PhaseTally {
    pub(super) recorded: u64,
    completed: u64,
}

impl PhaseTally {
    pub(super) fn is_complete(self) -> bool {
        self.completed == self.recorded
    }
}

fn phase_accepts_resolution(phase: TransactionState, resolution: PermissionResolution) -> bool {
    match resolution {
        PermissionResolution::Applied => true,
        PermissionResolution::ConfirmedNotApplied => matches!(
            phase,
            TransactionState::SourceParentRestoreIntent | TransactionState::UndoIntent
        ),
    }
}

/// Coverage requires every applied seal and inverse to be counted exactly once.
/// Append and replay admit at most one live inverse per applied seal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct SealCoverage {
    applied_parent_seals: u64,
    applied_tree_seals: u64,
    reversed_parent_seals: u64,
    restored_parent_seals: u64,
    reversed_tree_seals: u64,
    undone_tree_seals: u64,
}

impl SealCoverage {
    fn record_applied_seal(&mut self, phase: TransactionState) {
        match phase {
            TransactionState::ParentSealIntent => self.applied_parent_seals += 1,
            TransactionState::TreeSealIntent => self.applied_tree_seals += 1,
            _ => {}
        }
    }

    // Restore and rollback reverse seals without satisfying phase-specific undo.
    fn record_applied_inverse(
        &mut self,
        sealed_phase: TransactionState,
        inverse_phase: TransactionState,
    ) {
        match sealed_phase {
            TransactionState::ParentSealIntent => {
                self.reversed_parent_seals += 1;
                if inverse_phase == TransactionState::SourceParentRestoreIntent {
                    self.restored_parent_seals += 1;
                }
            }
            TransactionState::TreeSealIntent => {
                self.reversed_tree_seals += 1;
                if inverse_phase == TransactionState::UndoIntent {
                    self.undone_tree_seals += 1;
                }
            }
            _ => {}
        }
    }

    pub(super) fn every_applied_seal_is_reversed(self) -> bool {
        self.reversed_parent_seals == self.applied_parent_seals
            && self.reversed_tree_seals == self.applied_tree_seals
    }

    pub(super) fn every_applied_parent_seal_is_restored(self) -> bool {
        self.restored_parent_seals == self.applied_parent_seals
    }

    pub(super) fn every_applied_tree_seal_is_undone(self) -> bool {
        self.undone_tree_seals == self.applied_tree_seals
    }
}

/// Transaction-local records and counts shared by append, replay and resume.
/// Callers validate intents and resolutions before advancing the ledger.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct PermissionLedger {
    pub(super) permissions: BTreeMap<u64, DurablePermission>,
    pub(super) highest_mutation_id: Option<u64>,
    // Intent order differs from mutation-ID order when callers choose sparse IDs.
    record_order: Vec<u64>,
    recorded: u64,
    resolved: u64,
    pub(super) active_inverses: HashMap<u64, u64>,
    phases: HashMap<TransactionState, PhaseTally>,
    pub(super) coverage: SealCoverage,
}

impl PermissionLedger {
    pub(super) fn record_intent(&mut self, permission: DurablePermission) {
        let permission = DurablePermission {
            application: ApplicationStatus::IntentDurableApplicationUnknown,
            ..permission
        };
        let mutation_id = permission.mutation_id;
        self.highest_mutation_id = Some(
            self.highest_mutation_id
                .map_or(mutation_id, |held| held.max(mutation_id)),
        );
        self.phases.entry(permission.phase).or_default().recorded += 1;
        self.recorded += 1;
        if let Some(original) = permission.reverses_mutation_id {
            self.active_inverses.insert(original, mutation_id);
        }
        self.record_order.push(mutation_id);
        self.permissions.insert(mutation_id, permission);
    }

    pub(super) fn into_record_order(self) -> Vec<DurablePermission> {
        let Self {
            record_order,
            mut permissions,
            ..
        } = self;
        record_order
            .into_iter()
            .map(|id| permissions.remove(&id).expect("recorded permission"))
            .collect()
    }

    pub(super) fn record_resolution(&mut self, mutation_id: u64, resolution: PermissionResolution) {
        let permission = self
            .permissions
            .get_mut(&mutation_id)
            .expect("validated permission intent");
        permission.application = match resolution {
            PermissionResolution::Applied => ApplicationStatus::Applied,
            PermissionResolution::ConfirmedNotApplied => ApplicationStatus::ConfirmedNotApplied,
        };
        let phase = permission.phase;
        let reverses = permission.reverses_mutation_id;
        self.resolved += 1;
        if phase_accepts_resolution(phase, resolution) {
            self.phases.entry(phase).or_default().completed += 1;
        }
        match resolution {
            PermissionResolution::Applied => {
                self.coverage.record_applied_seal(phase);
                if let Some(original) = reverses {
                    let sealed_phase = self
                        .permissions
                        .get(&original)
                        .expect("validated applied seal")
                        .phase;
                    self.coverage.record_applied_inverse(sealed_phase, phase);
                }
            }
            PermissionResolution::ConfirmedNotApplied => {
                if let Some(original) = reverses {
                    self.active_inverses.remove(&original);
                }
            }
        }
    }

    pub(super) fn has_unresolved(&self) -> bool {
        self.resolved != self.recorded
    }

    pub(super) fn phase(&self, phase: TransactionState) -> PhaseTally {
        self.phases.get(&phase).copied().unwrap_or_default()
    }

    pub(super) fn retains_active_seals(&self) -> bool {
        !self.coverage.every_applied_seal_is_reversed()
    }
}
