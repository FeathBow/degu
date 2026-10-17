use super::*;
use TransactionState as S;

#[test]
fn an_inverse_before_its_seal_is_refused_by_append_and_replay() {
    let mut wal = tree_wal();
    wal.transition(TRANSACTION, S::RestoreIntent).unwrap();
    let inverse = intent(inverse(1, &seal(0, S::TreeSealIntent), S::RestoreIntent));
    let appended =
        wal.apply_permission_mutation(inverse.clone(), || panic!("invalid inverse applied"));
    assert!(matches!(
        appended,
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "permission inverse references no durable mutation"
        )))
    ));
    let replayed = replay_with_record(wal, inverse.into_record());
    assert!(matches!(
        replayed,
        Err(ReplayError::InvalidHistory(
            "permission inverse references no mutation in its transaction"
        ))
    ));
}

#[test]
fn two_live_inverses_are_refused_by_append_and_replay() {
    let mut wal = restored_wal(&[(0, 1)]);
    let second = intent(inverse(2, &seal(0, S::TreeSealIntent), S::RestoreIntent));
    let appended =
        wal.apply_permission_mutation(second.clone(), || panic!("duplicate inverse applied"));
    assert!(matches!(
        appended,
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "permission inverse does not match its applied seal mutation"
        )))
    ));
    let replayed = replay_with_record(wal, second.into_record());
    assert!(matches!(
        replayed,
        Err(ReplayError::InvalidHistory(
            "permission inverse does not match its applied seal mutation"
        ))
    ));
}

#[test]
fn a_duplicate_mutation_id_is_refused_by_append_and_replay() {
    let mut wal = tree_wal();
    wal.apply_permission_mutation(intent(seal(4, S::TreeSealIntent)), || Ok(()))
        .unwrap();
    let duplicate = PermissionIntent {
        mutation_id: 4,
        ..intent(seal(5, S::TreeSealIntent))
    };
    let appended =
        wal.apply_permission_mutation(duplicate.clone(), || panic!("duplicate mutation applied"));
    assert!(matches!(
        appended,
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "duplicate permission mutation id"
        )))
    ));
    let replayed = replay_with_record(wal, duplicate.into_record());
    assert!(matches!(
        replayed,
        Err(ReplayError::InvalidHistory("duplicate permission intent"))
    ));
}

#[test]
fn repeated_resolutions_are_refused_by_append_and_replay() {
    for resolution in [
        PermissionResolution::Applied,
        PermissionResolution::ConfirmedNotApplied,
    ] {
        let mut wal = tree_wal();
        wal.apply_permission_mutation(intent(seal(0, S::TreeSealIntent)), || Ok(()))
            .unwrap();
        assert!(matches!(
            wal.resolve_unresolved_permission(TRANSACTION, 0, |_| panic!("resolved twice")),
            Err(ResolveError::NotUnresolved)
        ));
        let record = match resolution {
            PermissionResolution::Applied => SealRecord::PermissionApplied {
                transaction: TRANSACTION,
                mutation_id: 0,
            },
            PermissionResolution::ConfirmedNotApplied => SealRecord::PermissionNotApplied {
                transaction: TRANSACTION,
                mutation_id: 0,
            },
        };
        let replayed = replay_with_record(wal, record);
        assert!(matches!(
            replayed,
            Err(ReplayError::InvalidHistory(
                "duplicate permission resolution"
            ))
        ));
    }
}

#[test]
fn a_manifest_over_an_unapplied_tree_seal_is_refused() {
    let manifest = DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count: 1,
        sha256: [0xe6; 32],
    };
    let commitment = sidecar_commitment(TRANSACTION, 1, 1, 48);
    let mut wal = wal_with_unapplied_tree_seal();
    let appended = wal.complete_tree_manifest_with_sidecar(TRANSACTION, manifest, commitment);
    assert!(matches!(
        appended,
        Err(AppendError::InvalidState(
            "tree completion is duplicate or permission work is unresolved"
        ))
    ));
    let replayed = replay_with_record(
        wal,
        SealRecord::TreeManifestSidecarComplete {
            transaction: TRANSACTION,
            manifest,
            commitment,
        },
    );
    assert!(matches!(
        replayed,
        Err(ReplayError::InvalidHistory(
            "tree completion is duplicate, unordered, or has unresolved permissions"
        ))
    ));
}

fn wal_with_unapplied_tree_seal() -> SealWal<FaultWriter> {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(TRANSACTION, staging_metadata()).unwrap();
    advance_to_tree_intent(&mut wal, TRANSACTION);
    let failed = wal.apply_staging_permission_mutation(
        PermissionIntent {
            transaction: TRANSACTION,
            mutation_id: 1,
            evidence: staging_tree_evidence("tree", 20),
            pre_mode: 0o770,
            expected_mode: SEALED_MODE,
            reverses_mutation_id: None,
        },
        || Err(io::Error::from_raw_os_error(libc::EPERM)),
    );
    assert!(matches!(failed, Err(MutationAppendError::Mutation(_))));
    assert_eq!(
        wal.resolve_staging_permission(TRANSACTION, 1, |_| Ok(
            PermissionResolution::ConfirmedNotApplied
        ))
        .unwrap(),
        PermissionResolution::ConfirmedNotApplied
    );
    wal
}

#[test]
fn resuming_a_replayed_wal_rebuilds_the_appended_ledger() {
    let mut wal = restored_wal(&[(0, 3), (1, 4), (2, 5)]);
    wal.transition(TRANSACTION, TransactionState::Restored)
        .unwrap();
    assert_resumed_ledger(wal);
}

#[test]
fn replay_preserves_intent_order_when_an_inverse_has_a_lower_id() {
    let mut wal = restored_wal(&[(9, 2)]);
    wal.transition(TRANSACTION, TransactionState::Restored)
        .unwrap();
    let replay = replay_bytes(&wal.writer.bytes);
    assert_eq!(
        replay.permissions[&TRANSACTION]
            .iter()
            .map(|permission| permission.mutation_id)
            .collect::<Vec<_>>(),
        vec![9, 2]
    );
    assert_resumed_ledger(wal);
}

fn assert_resumed_ledger(wal: SealWal<FaultWriter>) {
    let SealWal {
        writer, ledgers, ..
    } = wal;
    let replay = replay_bytes(&writer.bytes);
    let resumed = SealWal::resume(writer, &replay).unwrap();
    assert_eq!(resumed.ledgers[&TRANSACTION], ledgers[&TRANSACTION]);
    assert_matches_scans(&resumed.ledgers[&TRANSACTION]);
}

#[test]
fn permission_records_are_read_in_mutation_id_order() {
    let wal = restored_wal(&[(9, 2)]);
    assert_eq!(
        wal.permission_records(TRANSACTION)
            .iter()
            .map(|permission| permission.mutation_id)
            .collect::<Vec<_>>(),
        vec![2, 9]
    );
}
