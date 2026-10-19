use super::{
    ApplicationStatus, DurablePermission, FrameExtent, PermissionResolution, TransactionState,
};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::ffi::OsStrExt;

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

    /// Applied seals no applied inverse has reversed, counted per seal kind.
    ///
    /// An inverse is counted only once its own resolution is applied, and only
    /// against an original the ledger already counted as an applied seal, so
    /// neither difference can go negative. Append and replay admit at most one
    /// live inverse per applied seal and refuse a second resolution, so no seal
    /// is reversed twice and the differences are exact rather than an upper
    /// bound.
    pub(super) fn active_seals(self) -> u64 {
        self.applied_parent_seals
            .saturating_sub(self.reversed_parent_seals)
            + self
                .applied_tree_seals
                .saturating_sub(self.reversed_tree_seals)
    }
}

/// What recovery validation asks about a transaction's permissions, measured
/// while frames are admitted rather than by re-reading the records.
///
/// These are facts about the transaction, not limits: the ledger reports the
/// extremes it has seen and recovery decides what is too much. Append and
/// replay feed the same ledger, so a resumed WAL and a fresh replay produce
/// these from one implementation rather than two.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PermissionWorkload {
    /// Durable permission intents this transaction admitted.
    pub recorded: u64,
    /// Intents whose application the WAL has resolved neither way.
    pub unresolved: u64,
    /// Applied seals no applied inverse has reversed: what startup recovery
    /// would still have to undo.
    pub active_seals: u64,
    /// Components in the longest evidence path any of these intents carries.
    pub deepest_path_components: u32,
    /// Bytes in the longest evidence path any of these intents carries. A path
    /// can be long without being deep, so neither bound implies the other.
    pub longest_path_bytes: u32,
}

/// What the ledger keeps of one admitted permission intent.
///
/// Not the record. The record is the frame the intent was written as, and the
/// extent is how a decision reads it back. What stays resident is what no
/// intent frame carries -- the phase the intent was admitted under, and the
/// resolution a later frame gave it -- plus the original an inverse reverses,
/// which every resolution consults and which would otherwise cost a frame read
/// per resolved record.
///
/// The extent is `None` for an intent a fixture replayed from records it never
/// framed. Reading one of those fails closed rather than decoding whatever sits
/// at offset zero, so such a fixture cannot reach a record at all.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct PermissionEntry {
    pub(super) frame: Option<FrameExtent>,
    pub(super) reverses_mutation_id: Option<u64>,
    pub(super) phase: TransactionState,
    pub(super) application: ApplicationStatus,
}

/// Transaction-local records and counts shared by append, replay and resume.
/// Callers validate intents and resolutions before advancing the ledger.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct PermissionLedger {
    pub(super) permissions: BTreeMap<u64, PermissionEntry>,
    pub(super) highest_mutation_id: Option<u64>,
    recorded: u64,
    resolved: u64,
    pub(super) active_inverses: HashMap<u64, u64>,
    phases: HashMap<TransactionState, PhaseTally>,
    pub(super) coverage: SealCoverage,
    deepest_path_components: u32,
    longest_path_bytes: u32,
}

impl PermissionLedger {
    /// One admitted intent, for the decisions that read a single mutation
    /// rather than the whole transaction.
    pub(super) fn entry(&self, mutation_id: u64) -> Option<&PermissionEntry> {
        self.permissions.get(&mutation_id)
    }

    /// Every admitted intent, in mutation-id order.
    ///
    /// Not necessarily the order the frames were written in: append refuses a
    /// mutation id it has already admitted, but not one lower than the last.
    pub(super) fn entries(&self) -> impl Iterator<Item = (u64, &PermissionEntry)> {
        self.permissions.iter().map(|(id, entry)| (*id, entry))
    }

    /// Admits an intent, keeping the extent of its frame in place of the record.
    ///
    /// The record is still handed in because the tallies are measured off it
    /// while it is here; what the entry keeps is the projection of it that no
    /// frame holds.
    pub(super) fn record_intent(
        &mut self,
        permission: DurablePermission,
        frame: Option<FrameExtent>,
    ) {
        let mutation_id = permission.mutation_id;
        self.highest_mutation_id = Some(
            self.highest_mutation_id
                .map_or(mutation_id, |held| held.max(mutation_id)),
        );
        self.phases.entry(permission.phase).or_default().recorded += 1;
        self.recorded += 1;
        let path = permission.evidence.relative_path();
        self.deepest_path_components = self
            .deepest_path_components
            .max(path.components().count().try_into().unwrap_or(u32::MAX));
        self.longest_path_bytes = self.longest_path_bytes.max(
            path.as_os_str()
                .as_bytes()
                .len()
                .try_into()
                .unwrap_or(u32::MAX),
        );
        if let Some(original) = permission.reverses_mutation_id {
            self.active_inverses.insert(original, mutation_id);
        }
        self.permissions.insert(
            mutation_id,
            PermissionEntry {
                frame,
                reverses_mutation_id: permission.reverses_mutation_id,
                phase: permission.phase,
                application: ApplicationStatus::IntentDurableApplicationUnknown,
            },
        );
    }

    pub(super) fn record_resolution(&mut self, mutation_id: u64, resolution: PermissionResolution) {
        let entry = self
            .permissions
            .get_mut(&mutation_id)
            .expect("validated permission intent");
        entry.application = match resolution {
            PermissionResolution::Applied => ApplicationStatus::Applied,
            PermissionResolution::ConfirmedNotApplied => ApplicationStatus::ConfirmedNotApplied,
        };
        let phase = entry.phase;
        let reverses = entry.reverses_mutation_id;
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

    pub(super) fn workload(&self) -> PermissionWorkload {
        PermissionWorkload {
            recorded: self.recorded,
            unresolved: self.recorded.saturating_sub(self.resolved),
            active_seals: self.coverage.active_seals(),
            deepest_path_components: self.deepest_path_components,
            longest_path_bytes: self.longest_path_bytes,
        }
    }
}
