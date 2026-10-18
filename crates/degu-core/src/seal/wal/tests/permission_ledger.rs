use super::*;

mod boundaries;
mod scenarios;

/// A ledger and the records the fixture admitted into it, in mutation-id order.
///
/// The ledger holds no record of its own, so the scans these tests check its
/// counters against read this list. That is the right way round: an oracle that
/// read the subject's own copy of the records would agree with it by
/// construction. These fixtures frame nothing, which is why they keep the
/// records rather than reading them back.
#[derive(Default)]
struct Admitted {
    ledger: PermissionLedger,
    records: BTreeMap<u64, DurablePermission>,
}

impl Admitted {
    /// Admits an intent and, if given, its resolution, checking after each step
    /// that every counter still agrees with a scan.
    fn record(&mut self, permission: DurablePermission, resolution: Option<PermissionResolution>) {
        let mutation_id = permission.mutation_id;
        self.ledger.record_intent(permission.clone(), None);
        self.records.insert(
            mutation_id,
            DurablePermission {
                application: ApplicationStatus::IntentDurableApplicationUnknown,
                ..permission
            },
        );
        self.assert_matches_scans();
        if let Some(resolution) = resolution {
            self.ledger.record_resolution(mutation_id, resolution);
            self.records.get_mut(&mutation_id).unwrap().application = match resolution {
                PermissionResolution::Applied => ApplicationStatus::Applied,
                PermissionResolution::ConfirmedNotApplied => ApplicationStatus::ConfirmedNotApplied,
            };
            self.assert_matches_scans();
        }
    }

    fn assert_matches_scans(&self) {
        let records = self.records.values().cloned().collect::<Vec<_>>();
        assert_matches_scans(&self.ledger, &records);
    }
}

fn assert_matches_scans(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    assert_eq!(
        ledger.has_unresolved(),
        admitted.iter().any(|permission| {
            permission.application == ApplicationStatus::IntentDurableApplicationUnknown
        })
    );
    assert_eq!(
        ledger.highest_mutation_id,
        ledger.entries().map(|(id, _)| id).max()
    );
    assert_phase_completion(ledger, admitted);
    assert_parent_strategy(ledger, admitted);
    assert_coverage(ledger, admitted);
    assert_active_inverses(ledger, admitted);
    assert_quarantine_retention(ledger, admitted);
    assert_workload(ledger, admitted);
}

/// The counts recovery validation reads, against the scans they replaced. Every
/// scenario below asserts this after each intent and each resolution, so the
/// agreement is checked over the histories the ledger can actually reach rather
/// than over a record list assembled by hand.
fn assert_workload(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    assert_eq!(
        ledger.workload(),
        permission_workload_by_scan(admitted.iter())
    );
}

fn assert_phase_completion(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    use TransactionState as S;
    for (from, to) in [
        (S::ParentSealIntent, S::ParentSealed),
        (S::TreeSealIntent, S::TreeSealed),
        (S::SourceParentRestoreIntent, S::SourceParentRestored),
        (S::UndoIntent, S::UndoModesRestored),
        (S::Prepared, S::ParentSealIntent),
    ] {
        assert_eq!(
            phase_completion_is_recorded(Some(ledger), from, to),
            phase_completion_is_valid(admitted.iter(), from, to),
            "phase completion {from:?} -> {to:?}"
        );
    }
}

fn assert_parent_strategy(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    for metadata in [
        None,
        Some(permission_seal_staging_metadata()),
        Some(staging_metadata()),
    ] {
        assert_eq!(
            staging_parent_strategy_is_recorded(metadata.as_ref(), Some(ledger)),
            staging_parent_strategy_is_complete(metadata.as_ref(), admitted.iter())
        );
    }
}

fn assert_coverage(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    assert_eq!(
        ledger.coverage.every_applied_seal_is_reversed(),
        all_applied_seals_have_applied_inverse(admitted.iter())
    );
    assert_eq!(
        ledger.coverage.every_applied_parent_seal_is_restored(),
        all_applied_parent_seals_have_applied_inverse(admitted.iter())
    );
    assert_eq!(
        ledger.coverage.every_applied_tree_seal_is_undone(),
        all_applied_tree_seals_have_applied_inverse(admitted.iter())
    );
    assert_eq!(
        ledger.retains_active_seals(),
        retains_active_permission_seals(admitted.iter())
    );
}

fn assert_active_inverses(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    for id in 0..=ledger.highest_mutation_id.unwrap_or(0) + 1 {
        assert_eq!(
            ledger.active_inverses.contains_key(&id),
            admitted.iter().any(|permission| {
                permission.reverses_mutation_id == Some(id)
                    && matches!(
                        permission.application,
                        ApplicationStatus::Applied
                            | ApplicationStatus::IntentDurableApplicationUnknown
                    )
            }),
            "active inverse of {id}"
        );
    }
}

fn assert_quarantine_retention(ledger: &PermissionLedger, admitted: &[DurablePermission]) {
    let quarantined = ReplayedTransaction {
        id: TRANSACTION,
        state: TransactionState::Quarantined,
        staging_schema_version: None,
        permission_workload: ledger.workload(),
        staging: None,
        tree_manifest: None,
        tree_sidecar: None,
        rename_outcome: None,
        undo_rename_outcome: None,
        purge_removed_entries: 0,
        purge_last_path: None,
    };
    assert_eq!(
        quarantined_transaction_retains_active_permission_seals(&quarantined),
        retains_active_permission_seals(admitted.iter())
    );
}

const TRANSACTION: TransactionId = TransactionId([0xb2; 16]);
const ORIGINAL_MODE: u32 = 0o700;
const SEALED_MODE: u32 = 0o500;
const DEVICE: u64 = 11;
const FIRST_INODE: u64 = 100;
const INCARNATION: u64 = 33;

fn seal(id: u64, phase: TransactionState) -> DurablePermission {
    DurablePermission {
        mutation_id: id,
        phase,
        evidence: PersistentRecoveryEvidence::new(
            PathBuf::from(format!("dir{id}")),
            Some("local-fs".to_owned()),
            DEVICE,
            FIRST_INODE + id,
            Some(INCARNATION),
            SEALED_MODE,
        )
        .unwrap(),
        pre_mode: ORIGINAL_MODE,
        expected_mode: SEALED_MODE,
        reverses_mutation_id: None,
        application: ApplicationStatus::IntentDurableApplicationUnknown,
    }
}

fn inverse(id: u64, original: &DurablePermission, phase: TransactionState) -> DurablePermission {
    let evidence = &original.evidence;
    DurablePermission {
        mutation_id: id,
        phase,
        evidence: PersistentRecoveryEvidence::new(
            evidence.relative_path().to_owned(),
            evidence.filesystem_id().map(str::to_owned),
            evidence.device(),
            evidence.inode(),
            evidence.generation_or_btime(),
            original.pre_mode,
        )
        .unwrap(),
        pre_mode: original.expected_mode,
        expected_mode: original.pre_mode,
        reverses_mutation_id: Some(original.mutation_id),
        application: ApplicationStatus::IntentDurableApplicationUnknown,
    }
}

fn intent(permission: DurablePermission) -> PermissionIntent {
    PermissionIntent {
        transaction: TRANSACTION,
        mutation_id: permission.mutation_id,
        evidence: permission.evidence,
        pre_mode: permission.pre_mode,
        expected_mode: permission.expected_mode,
        reverses_mutation_id: permission.reverses_mutation_id,
    }
}

fn tree_wal() -> SealWal<FaultWriter> {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(TRANSACTION).unwrap();
    for next in [
        TransactionState::ParentSealIntent,
        TransactionState::ParentSealed,
        TransactionState::TreeSealIntent,
    ] {
        wal.transition(TRANSACTION, next).unwrap();
    }
    wal
}

fn restored_wal(ids: &[(u64, u64)]) -> SealWal<FaultWriter> {
    let mut wal = tree_wal();
    for &(original, _) in ids {
        wal.apply_permission_mutation(
            intent(seal(original, TransactionState::TreeSealIntent)),
            || Ok(()),
        )
        .unwrap();
    }
    wal.transition(TRANSACTION, TransactionState::RestoreIntent)
        .unwrap();
    for &(original, reverse) in ids {
        let original = seal(original, TransactionState::TreeSealIntent);
        wal.apply_permission_mutation(
            intent(inverse(reverse, &original, TransactionState::RestoreIntent)),
            || Ok(()),
        )
        .unwrap();
    }
    wal
}

fn replay_with_record(
    wal: SealWal<FaultWriter>,
    record: SealRecord,
) -> Result<Replay, ReplayError> {
    let mut bytes = wal.into_inner().bytes;
    bytes.extend_from_slice(&encode_frame(&record).unwrap());
    replay_records(parse_frames(&bytes).unwrap().records, &bytes)
}
