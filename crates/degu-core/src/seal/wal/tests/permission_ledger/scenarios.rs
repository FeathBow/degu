use super::*;
use PermissionResolution::{Applied, ConfirmedNotApplied};
use TransactionState as S;

#[test]
fn sealing_resolutions_match_the_scans() {
    Admitted::default().assert_matches_scans();
    for phase in [S::ParentSealIntent, S::TreeSealIntent] {
        for resolution in [None, Some(Applied), Some(ConfirmedNotApplied)] {
            Admitted::default().record(seal(0, phase), resolution);
        }
    }
}

#[test]
fn inverse_resolutions_match_the_scans() {
    for (seal_phase, inverse_phase) in [
        (S::ParentSealIntent, S::RestoreIntent),
        (S::ParentSealIntent, S::SourceParentRestoreIntent),
        (S::ParentSealIntent, S::RollbackIntent),
        (S::ParentSealIntent, S::Quarantined),
        (S::TreeSealIntent, S::RestoreIntent),
        (S::TreeSealIntent, S::RollbackIntent),
        (S::TreeSealIntent, S::UndoIntent),
        (S::TreeSealIntent, S::Quarantined),
    ] {
        for resolution in [None, Some(Applied), Some(ConfirmedNotApplied)] {
            let mut ledger = Admitted::default();
            let original = seal(0, seal_phase);
            ledger.record(original.clone(), Some(Applied));
            ledger.record(inverse(1, &original, inverse_phase), resolution);
        }
    }
}

#[test]
fn a_confirmed_unapplied_inverse_can_be_retried() {
    let mut ledger = Admitted::default();
    let original = seal(0, S::TreeSealIntent);
    ledger.record(original.clone(), Some(Applied));
    ledger.record(
        inverse(1, &original, S::UndoIntent),
        Some(ConfirmedNotApplied),
    );
    ledger.record(inverse(2, &original, S::UndoIntent), Some(Applied));
}

#[test]
fn one_inverse_does_not_cover_two_seals() {
    let mut ledger = Admitted::default();
    let original = seal(0, S::TreeSealIntent);
    ledger.record(original.clone(), Some(Applied));
    ledger.record(seal(1, S::TreeSealIntent), Some(Applied));
    ledger.record(inverse(2, &original, S::UndoIntent), Some(Applied));
}

#[test]
fn parent_restoration_and_tree_undo_cover_both_seal_families() {
    let mut ledger = Admitted::default();
    let parent = seal(0, S::ParentSealIntent);
    let tree = seal(1, S::TreeSealIntent);
    ledger.record(parent.clone(), Some(Applied));
    ledger.record(tree.clone(), Some(Applied));
    ledger.record(
        inverse(2, &parent, S::SourceParentRestoreIntent),
        Some(Applied),
    );
    ledger.record(inverse(3, &tree, S::UndoIntent), Some(Applied));
}

#[test]
fn sparse_mutation_ids_preserve_unresolved_and_unapplied_work() {
    let mut ledger = Admitted::default();
    let original = seal(7, S::TreeSealIntent);
    ledger.record(original.clone(), Some(Applied));
    ledger.record(seal(3, S::TreeSealIntent), Some(ConfirmedNotApplied));
    ledger.record(inverse(11, &original, S::RestoreIntent), None);
}
