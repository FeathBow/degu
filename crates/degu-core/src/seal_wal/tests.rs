use super::*;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::Path;

fn tx(byte: u8) -> TransactionId {
    TransactionId([byte; 16])
}

fn evidence(path: &str) -> PersistentRecoveryEvidence {
    evidence_mode(path, 0o500)
}

fn evidence_mode(path: &str, mode: u32) -> PersistentRecoveryEvidence {
    PersistentRecoveryEvidence::new(
        PathBuf::from(path),
        Some("local-fs".to_string()),
        11,
        22,
        Some(33),
        mode,
    )
    .unwrap()
}

fn state(transaction: TransactionId, state: TransactionState) -> SealRecord {
    SealRecord::State { transaction, state }
}

fn frame(record: &SealRecord) -> Vec<u8> {
    encode_frame(record).unwrap()
}

fn replay_bytes(bytes: &[u8]) -> Replay {
    let parsed = parse_frames(bytes).unwrap();
    let committed_len = parsed.committed_len as u64;
    let mut replay = replay_records(parsed.records).unwrap();
    replay.committed_len = committed_len;
    replay
}

fn open_rw(path: &Path) -> File {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

#[derive(Default)]
struct FaultWriter {
    bytes: Vec<u8>,
    max_chunk: usize,
    write_error_after: Option<(usize, i32)>,
    fail_sync_at: Option<(usize, i32)>,
    sync_count: usize,
}

impl Write for FaultWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some((limit, errno)) = self.write_error_after
            && self.bytes.len() >= limit
        {
            return Err(io::Error::from_raw_os_error(errno));
        }
        let remaining = self.write_error_after.map_or(bytes.len(), |(limit, _)| {
            limit.saturating_sub(self.bytes.len())
        });
        let chunk = if self.max_chunk == 0 {
            bytes.len()
        } else {
            self.max_chunk.min(bytes.len())
        }
        .min(remaining);
        if chunk == 0 {
            return Err(io::Error::new(ErrorKind::WriteZero, "injected zero write"));
        }
        self.bytes.extend_from_slice(&bytes[..chunk]);
        Ok(chunk)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableWrite for FaultWriter {
    fn sync_record(&mut self) -> io::Result<()> {
        let call = self.sync_count;
        self.sync_count += 1;
        match self.fail_sync_at {
            Some((fail_at, errno)) if call == fail_at => Err(io::Error::from_raw_os_error(errno)),
            _ => Ok(()),
        }
    }

    fn prepare_append(&mut self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
}

#[test]
fn short_writes_are_completed_and_frames_replay() {
    let writer = FaultWriter {
        max_chunk: 3,
        ..FaultWriter::default()
    };
    let mut wal = SealWal::new(writer).unwrap();
    wal.append_synced(&state(tx(1), TransactionState::Prepared))
        .unwrap();
    let parsed = parse_frames(&wal.into_inner().bytes).unwrap();
    let replay = replay_records(parsed.records).unwrap();
    assert_eq!(
        replay.transactions[&tx(1)].state,
        TransactionState::Prepared
    );
}

#[test]
fn write_resource_and_io_failures_poison_the_writer() {
    for errno in [28, 122, 5] {
        let writer = FaultWriter {
            max_chunk: 4,
            write_error_after: Some((7, errno)),
            ..FaultWriter::default()
        };
        let mut wal = SealWal::new(writer).unwrap();
        let error = wal
            .append_synced(&state(tx(2), TransactionState::Prepared))
            .unwrap_err();
        assert_eq!(
            match error {
                AppendError::Io(error) => error.raw_os_error(),
                AppendError::Poisoned
                | AppendError::InvalidState(_)
                | AppendError::Frame(_)
                | AppendError::TotalSize { .. } => None,
            },
            Some(errno)
        );
        assert!(matches!(
            wal.append_synced(&state(tx(2), TransactionState::Prepared)),
            Err(AppendError::Poisoned)
        ));
    }
}

#[test]
fn sync_failure_before_mutation_prevents_mutation() {
    let writer = FaultWriter {
        fail_sync_at: Some((2, 5)),
        ..FaultWriter::default()
    };
    let mut wal = SealWal::new(writer).unwrap();
    wal.begin(tx(3)).unwrap();
    wal.transition(tx(3), TransactionState::ParentSealIntent)
        .unwrap();
    let called = Cell::new(false);
    let error = wal
        .apply_permission_mutation(
            PermissionIntent {
                transaction: tx(3),
                mutation_id: 1,
                evidence: evidence("child"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || {
                called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(matches!(error, MutationAppendError::IntentWal(_)));
    assert!(!called.get());
}

#[test]
fn applied_is_synced_only_after_successful_mutation() {
    let writer = FaultWriter::default();
    let mut wal = SealWal::new(writer).unwrap();
    wal.begin(tx(4)).unwrap();
    wal.transition(tx(4), TransactionState::ParentSealIntent)
        .unwrap();
    let called = Cell::new(false);
    wal.apply_permission_mutation(
        PermissionIntent {
            transaction: tx(4),
            mutation_id: 9,
            evidence: evidence("tree/child"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        || {
            called.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(called.get());
    let parsed = parse_frames(&wal.into_inner().bytes).unwrap();
    let replay = replay_records(parsed.records).unwrap();
    assert_eq!(
        replay.transactions[&tx(4)].permissions[0].application,
        ApplicationStatus::Applied
    );
}

#[test]
fn mutation_failure_leaves_durable_uncertain_intent_without_applied() {
    let writer = FaultWriter::default();
    let mut wal = SealWal::new(writer).unwrap();
    wal.begin(tx(5)).unwrap();
    wal.transition(tx(5), TransactionState::ParentSealIntent)
        .unwrap();
    let error = wal
        .apply_permission_mutation(
            PermissionIntent {
                transaction: tx(5),
                mutation_id: 7,
                evidence: evidence("tree"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Err(io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
    assert!(matches!(error, MutationAppendError::Mutation(_)));
    let parsed = parse_frames(&wal.into_inner().bytes).unwrap();
    let replay = replay_records(parsed.records).unwrap();
    assert_eq!(
        replay.transactions[&tx(5)].permissions[0].application,
        ApplicationStatus::IntentDurableApplicationUnknown
    );
}

#[test]
fn applied_sync_failure_is_reported_after_mutation_and_poisoned() {
    let writer = FaultWriter {
        // prepared 0, phase 1, permission intent 2, applied 3
        fail_sync_at: Some((3, 5)),
        ..FaultWriter::default()
    };
    let mut wal = SealWal::new(writer).unwrap();
    wal.begin(tx(6)).unwrap();
    wal.transition(tx(6), TransactionState::ParentSealIntent)
        .unwrap();
    let called = Cell::new(false);
    let error = wal
        .apply_permission_mutation(
            PermissionIntent {
                transaction: tx(6),
                mutation_id: 1,
                evidence: evidence("x"),
                pre_mode: 0o700,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || {
                called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        MutationAppendError::AppliedWal {
            mutation_applied: true,
            ..
        }
    ));
    assert!(called.get());
    assert!(matches!(
        wal.append_synced(&state(tx(6), TransactionState::RecoveryRequired)),
        Err(AppendError::Poisoned)
    ));
}

#[test]
fn torn_final_frame_is_truncated_under_recovery_lock() {
    let temp = tempfile::tempdir().unwrap();
    let wal_path = temp.path().join("seal.wal");
    let first = frame(&state(tx(7), TransactionState::Prepared));
    let second = frame(&state(tx(7), TransactionState::ParentSealIntent));
    let mut bytes = first.clone();
    bytes.extend_from_slice(&second[..second.len() - 3]);
    std::fs::write(&wal_path, bytes).unwrap();

    let mut recovery = RecoverySession::try_acquire(open_rw(&wal_path)).unwrap();
    let replay = recovery.replay_and_repair().unwrap();
    assert_eq!(
        replay.tail_repair,
        Some(TailRepair {
            truncated_bytes: (second.len() - 3) as u64
        })
    );
    assert_eq!(
        std::fs::metadata(&wal_path).unwrap().len(),
        first.len() as u64
    );
}

#[test]
fn torn_tail_repair_positions_plain_file_for_resume_append_and_replay() {
    let temp = tempfile::tempdir().unwrap();
    let wal_path = temp.path().join("resume.wal");
    let first = frame(&state(tx(20), TransactionState::Prepared));
    let next_record = state(tx(20), TransactionState::ParentSealIntent);
    let second = frame(&next_record);
    let mut torn = first.clone();
    torn.extend_from_slice(&second[..second.len() - 2]);
    std::fs::write(&wal_path, torn).unwrap();

    let mut recovery = RecoverySession::try_acquire(open_rw(&wal_path)).unwrap();
    let replay = recovery.replay_and_repair().unwrap();
    assert!(replay.tail_repair.is_some());

    // Resume consumes the exact locked descriptor and retains its lease until
    // the writer is dropped.
    let mut resumed = recovery.resume().unwrap();
    resumed
        .transition(tx(20), TransactionState::ParentSealIntent)
        .unwrap();
    drop(resumed);
    let mut recovery = RecoverySession::try_acquire(open_rw(&wal_path)).unwrap();
    let replay = recovery.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&tx(20)].state,
        TransactionState::ParentSealIntent
    );
    assert_eq!(replay.tail_repair, None);

    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(std::fs::read(wal_path).unwrap(), expected);
}

#[test]
fn checksum_unknown_version_and_malformed_interior_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let good = frame(&state(tx(8), TransactionState::Prepared));

    let checksum_path = temp.path().join("checksum.wal");
    let mut checksum = good.clone();
    *checksum.last_mut().unwrap() ^= 1;
    std::fs::write(&checksum_path, &checksum).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&checksum_path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::Checksum { .. })
    ));
    drop(lock);
    assert_eq!(std::fs::read(&checksum_path).unwrap(), checksum);

    let version_path = temp.path().join("version.wal");
    let mut version = good.clone();
    version[4..6].copy_from_slice(&2_u16.to_le_bytes());
    let version_header_crc = crc32(&version[4..12]);
    version[12..16].copy_from_slice(&version_header_crc.to_le_bytes());
    std::fs::write(&version_path, &version).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&version_path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::UnknownVersion { version: 2, .. })
    ));
    drop(lock);

    let interior_path = temp.path().join("interior.wal");
    let mut interior = good;
    interior.extend_from_slice(b"BAD!committed-looking-interior");
    interior.extend_from_slice(&frame(&state(tx(9), TransactionState::Prepared)));
    std::fs::write(&interior_path, &interior).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&interior_path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::Malformed { .. })
    ));
    assert_eq!(std::fs::read(&interior_path).unwrap(), interior);
}

#[test]
fn checksummed_frame_with_out_of_schema_mode_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("high-mode.wal");
    let frame = frame(&SealRecord::PermissionIntent {
        transaction: tx(19),
        mutation_id: 1,
        evidence: evidence("tree"),
        pre_mode: 0o10_770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    });
    std::fs::write(&path, &frame).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::Malformed {
            reason: "permission mode exceeds the supported mode-bit schema",
            ..
        })
    ));
    assert_eq!(std::fs::read(path).unwrap(), frame);
}

#[test]
fn recovery_lock_is_exclusive_and_nonblocking() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lock");
    let first = RecoverySession::try_acquire(open_rw(&path)).unwrap();
    assert!(matches!(
        RecoverySession::try_acquire(open_rw(&path)),
        Err(RecoveryLockError::Busy)
    ));
    drop(first);
    RecoverySession::try_acquire(open_rw(&path)).unwrap();
}

#[test]
fn recovery_drop_unlocks_a_fork_inherited_file_description() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("inherited-lock");
    let file = open_rw(&path);
    let inherited = file.try_clone().unwrap();
    let session = RecoverySession::try_acquire(file).unwrap();

    drop(session);
    RecoverySession::try_acquire(open_rw(&path)).unwrap();

    drop(inherited);
}

fn replayed(state: TransactionState) -> ReplayedTransaction {
    ReplayedTransaction {
        id: tx(10),
        state,
        permissions: vec![DurablePermission {
            mutation_id: 1,
            phase: TransactionState::TreeSealIntent,
            evidence: evidence("tree/dir"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
            application: ApplicationStatus::Applied,
        }],
    }
}

#[test]
fn decision_engine_separates_before_after_and_committed_recovery() {
    assert!(matches!(
        decide_recovery(&replayed(TransactionState::TreeSealed), |_| {
            RecoveryIdentity::Reestablished
        }),
        RecoveryWork::RestoreBeforeRename { .. }
    ));
    assert!(matches!(
        decide_recovery(&replayed(TransactionState::StagedUnverified), |_| {
            RecoveryIdentity::Reestablished
        }),
        RecoveryWork::VerifyOrQuarantineAfterRename { .. }
    ));
    assert!(matches!(
        decide_recovery(&replayed(TransactionState::VerifiedCommitted), |_| {
            RecoveryIdentity::Insufficient
        }),
        RecoveryWork::PreserveCommittedSeal { .. }
    ));
}

#[test]
fn insufficient_identity_never_produces_mutation_work() {
    let result = decide_recovery(&replayed(TransactionState::TreeSealed), |_| {
        RecoveryIdentity::Insufficient
    });
    assert_eq!(
        result,
        RecoveryWork::RecoveryRequired {
            transaction: tx(10),
            reason: RecoveryRequiredReason::InsufficientPersistentIdentity,
        }
    );
}

#[test]
fn confined_evidence_rejects_absolute_and_parent_paths() {
    assert!(
        PersistentRecoveryEvidence::new(PathBuf::from("/tmp/x"), None, 1, 2, None, 0).is_none()
    );
    assert!(
        PersistentRecoveryEvidence::new(PathBuf::from("a/../b"), None, 1, 2, None, 0).is_none()
    );
}

#[test]
fn invalid_history_fails_closed() {
    let records = vec![
        state(tx(11), TransactionState::Prepared),
        SealRecord::PermissionApplied {
            transaction: tx(11),
            mutation_id: 99,
        },
    ];
    assert!(matches!(
        replay_records(records),
        Err(ReplayError::InvalidHistory(_))
    ));
}

#[test]
fn decision_callback_receives_evidence_but_not_authority() {
    let seen = Cell::new(false);
    let _ = decide_recovery(&replayed(TransactionState::TreeSealed), |item| {
        assert_eq!(item.relative_path(), Path::new("tree/dir"));
        seen.set(true);
        RecoveryIdentity::Reestablished
    });
    assert!(seen.get());
}

#[test]
fn terminal_states_have_no_outgoing_transitions() {
    use TransactionState as S;
    let terminals = [
        S::Purged,
        S::Restored,
        S::RolledBack,
        S::Quarantined,
        S::RecoveryRequired,
    ];
    let exception_targets = [
        S::RollbackIntent,
        S::RestoreIntent,
        S::Quarantined,
        S::RecoveryRequired,
    ];
    for terminal in terminals {
        for target in exception_targets {
            assert!(
                !valid_transition(terminal, target),
                "{terminal:?} -> {target:?}"
            );
        }
    }
}

#[test]
fn permission_records_are_confined_to_seal_intent_phase() {
    let transaction = tx(12);
    let intent = SealRecord::PermissionIntent {
        transaction,
        mutation_id: 1,
        evidence: evidence("tree"),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    assert!(matches!(
        replay_records(vec![
            state(transaction, TransactionState::Prepared),
            state(transaction, TransactionState::ParentSealIntent),
            intent.clone(),
            state(transaction, TransactionState::ParentSealed),
        ]),
        Err(ReplayError::InvalidHistory(
            "state advanced with an unresolved permission intent"
        ))
    ));
    assert!(matches!(
        replay_records(vec![
            state(transaction, TransactionState::Prepared),
            state(transaction, TransactionState::ParentSealIntent),
            state(transaction, TransactionState::ParentSealed),
            state(transaction, TransactionState::TreeSealIntent),
            state(transaction, TransactionState::TreeSealed),
            state(transaction, TransactionState::RenameIntent),
            intent,
        ]),
        Err(ReplayError::InvalidHistory(
            "permission intent is outside a permission-intent phase"
        ))
    ));
}

#[test]
fn applied_record_must_share_the_intent_phase() {
    let transaction = tx(13);
    let records = vec![
        state(transaction, TransactionState::Prepared),
        state(transaction, TransactionState::ParentSealIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: evidence("parent"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 1,
        },
        state(transaction, TransactionState::ParentSealed),
    ];
    assert!(replay_records(records).is_ok());
}

#[test]
fn quarantine_is_not_reported_as_a_committed_seal() {
    let result = decide_recovery(&replayed(TransactionState::Quarantined), |_| {
        RecoveryIdentity::Insufficient
    });
    assert_eq!(
        result,
        RecoveryWork::PreserveQuarantine {
            transaction: tx(10)
        }
    );
}

#[test]
fn inverse_binding_rejects_changed_stable_identity_and_cross_transaction_matches() {
    let original_evidence = evidence("source/tree");
    assert!(same_recovery_object(
        &original_evidence,
        &evidence("trash/tree")
    ));
    for changed in [
        PersistentRecoveryEvidence::new(
            PathBuf::from("trash/tree"),
            Some("other-fs".to_string()),
            11,
            22,
            Some(33),
            0o770,
        )
        .unwrap(),
        PersistentRecoveryEvidence::new(
            PathBuf::from("trash/tree"),
            Some("local-fs".to_string()),
            11,
            99,
            Some(33),
            0o770,
        )
        .unwrap(),
        PersistentRecoveryEvidence::new(
            PathBuf::from("trash/tree"),
            Some("local-fs".to_string()),
            11,
            22,
            Some(99),
            0o770,
        )
        .unwrap(),
    ] {
        assert!(!same_recovery_object(&original_evidence, &changed));
    }
    let transaction = tx(25);
    let changed = PersistentRecoveryEvidence::new(
        PathBuf::from("trash/tree"),
        Some("local-fs".to_string()),
        99,
        22,
        Some(33),
        0o770,
    )
    .unwrap();
    let changed_identity = vec![
        state(transaction, TransactionState::Prepared),
        state(transaction, TransactionState::ParentSealIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: evidence("source/tree"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 1,
        },
        state(transaction, TransactionState::ParentSealed),
        state(transaction, TransactionState::RestoreIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 2,
            evidence: changed,
            pre_mode: 0o500,
            expected_mode: 0o770,
            reverses_mutation_id: Some(1),
        },
    ];
    assert!(matches!(
        replay_records(changed_identity),
        Err(ReplayError::InvalidHistory(
            "permission inverse does not match its applied seal mutation"
        ))
    ));

    let other = tx(26);
    let mut records = Vec::new();
    for owner in [transaction, other] {
        records.extend([
            state(owner, TransactionState::Prepared),
            state(owner, TransactionState::ParentSealIntent),
            SealRecord::PermissionIntent {
                transaction: owner,
                mutation_id: 1,
                evidence: evidence("source/tree"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            SealRecord::PermissionApplied {
                transaction: owner,
                mutation_id: 1,
            },
            state(owner, TransactionState::ParentSealed),
            state(owner, TransactionState::RestoreIntent),
        ]);
    }
    records.extend([
        SealRecord::PermissionIntent {
            transaction: other,
            mutation_id: 2,
            evidence: evidence_mode("trash/tree", 0o770),
            pre_mode: 0o500,
            expected_mode: 0o770,
            reverses_mutation_id: Some(1),
        },
        SealRecord::PermissionApplied {
            transaction: other,
            mutation_id: 2,
        },
        state(other, TransactionState::Restored),
        state(transaction, TransactionState::Restored),
    ]);
    assert!(matches!(
        replay_records(records),
        Err(ReplayError::InvalidHistory(
            "terminal restore lacks an applied inverse for an applied seal"
        ))
    ));
}

#[test]
fn oversized_wal_fails_closed_without_allocating_its_claimed_size() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.wal");
    let wal = open_rw(&path);
    wal.set_len(MAX_WAL_LEN + 1).unwrap();
    drop(wal);
    let mut lock = RecoverySession::try_acquire(open_rw(&path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::TooLarge { limit: MAX_WAL_LEN })
    ));
    assert_eq!(std::fs::metadata(path).unwrap().len(), MAX_WAL_LEN + 1);
}

#[test]
fn restore_and_rollback_phases_accept_separate_permission_mutations() {
    let transaction = tx(14);
    let same_object = evidence("parent/tree");
    let restore_records = vec![
        state(transaction, TransactionState::Prepared),
        state(transaction, TransactionState::ParentSealIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: same_object.clone(),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 1,
        },
        state(transaction, TransactionState::ParentSealed),
        state(transaction, TransactionState::RestoreIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 2,
            evidence: evidence_mode("trash/tree", 0o770),
            pre_mode: 0o500,
            expected_mode: 0o770,
            reverses_mutation_id: Some(1),
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 2,
        },
        state(transaction, TransactionState::Restored),
    ];
    let replay = replay_records(restore_records).unwrap();
    assert_eq!(replay.transactions[&transaction].permissions.len(), 2);
    assert_eq!(
        replay.transactions[&transaction].permissions[1].phase,
        TransactionState::RestoreIntent
    );
    let mut before_terminal = replay.transactions[&transaction].clone();
    before_terminal.state = TransactionState::RestoreIntent;
    assert!(matches!(
        decide_recovery(&before_terminal, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::RestoreBeforeRename { permissions, .. } if permissions.is_empty()
    ));

    assert!(valid_transition(
        TransactionState::StagedUnverified,
        TransactionState::RollbackIntent
    ));
    assert!(valid_transition(
        TransactionState::RollbackIntent,
        TransactionState::RolledBack
    ));
}

#[test]
fn replay_resume_resolves_applied_then_records_restore_to_restored() {
    let transaction = tx(16);
    let mut first = SealWal::new(FaultWriter::default()).unwrap();
    first.begin(transaction).unwrap();
    first
        .transition(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    assert!(matches!(
        first.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: evidence("parent"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Err(io::Error::from_raw_os_error(5)),
        ),
        Err(MutationAppendError::Mutation(_))
    ));
    let bytes = first.into_inner().bytes;
    let replay = replay_bytes(&bytes);
    let mut resumed = SealWal::resume(
        FaultWriter {
            bytes,
            ..FaultWriter::default()
        },
        &replay,
    )
    .unwrap();
    resumed
        .resolve_unresolved_permission(transaction, 1, |_| Ok(PermissionResolution::Applied))
        .unwrap();
    resumed
        .transition(transaction, TransactionState::ParentSealed)
        .unwrap();
    resumed
        .transition(transaction, TransactionState::RestoreIntent)
        .unwrap();
    resumed
        .apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 2,
                evidence: evidence_mode("restored/parent", 0o770),
                pre_mode: 0o500,
                expected_mode: 0o770,
                reverses_mutation_id: Some(1),
            },
            || Ok(()),
        )
        .unwrap();
    resumed
        .transition(transaction, TransactionState::Restored)
        .unwrap();
    let parsed = parse_frames(&resumed.into_inner().bytes).unwrap();
    let replay = replay_records(parsed.records).unwrap();
    let recovered = &replay.transactions[&transaction];
    assert_eq!(recovered.state, TransactionState::Restored);
    assert_eq!(
        recovered.permissions[0].phase,
        TransactionState::ParentSealIntent
    );
    assert_eq!(
        recovered.permissions[1].phase,
        TransactionState::RestoreIntent
    );
    assert!(
        recovered
            .permissions
            .iter()
            .all(|permission| permission.application == ApplicationStatus::Applied)
    );
}

#[test]
fn confirmed_not_applied_does_not_require_identity_or_restore_work() {
    let transaction = tx(17);
    let records = [
        state(transaction, TransactionState::Prepared),
        state(transaction, TransactionState::ParentSealIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: evidence("parent"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
    ];
    let bytes = records.iter().flat_map(frame).collect::<Vec<_>>();
    let replay = replay_bytes(&bytes);
    let mut resumed = SealWal::resume(
        FaultWriter {
            bytes,
            ..FaultWriter::default()
        },
        &replay,
    )
    .unwrap();
    resumed
        .resolve_unresolved_permission(transaction, 1, |_| {
            Ok(PermissionResolution::ConfirmedNotApplied)
        })
        .unwrap();
    let bytes = resumed.into_inner().bytes;
    let replay = replay_bytes(&bytes);
    let transaction = &replay.transactions[&transaction];
    assert_eq!(
        transaction.permissions[0].application,
        ApplicationStatus::ConfirmedNotApplied
    );
    assert!(matches!(
        decide_recovery(transaction, |_| panic!("identity must not be consulted")),
        RecoveryWork::RestoreBeforeRename { permissions, .. } if permissions.is_empty()
    ));
}

#[test]
fn writer_rejects_modes_inconsistent_with_recovery_evidence() {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(tx(18)).unwrap();
    wal.transition(tx(18), TransactionState::ParentSealIntent)
        .unwrap();
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction: tx(18),
                mutation_id: 1,
                evidence: evidence("tree"),
                pre_mode: 0o10_770,
                expected_mode: 0o700,
                reverses_mutation_id: None,
            },
            || panic!("invalid intent must not mutate")
        ),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "permission modes are invalid or inconsistent with recovery evidence"
        )))
    ));
}

#[test]
fn oversized_intent_and_total_limit_fail_before_write_or_mutation() {
    let transaction = tx(21);
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(transaction).unwrap();
    wal.transition(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    let before = wal.writer.bytes.clone();
    let called = Cell::new(false);
    let huge = PersistentRecoveryEvidence::new(
        PathBuf::from("tree"),
        Some("x".repeat(MAX_PAYLOAD_LEN + 1)),
        11,
        22,
        Some(33),
        0o500,
    )
    .unwrap();
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: huge,
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || {
                called.set(true);
                Ok(())
            }
        ),
        Err(MutationAppendError::IntentWal(AppendError::Frame(
            FrameError::PayloadTooLarge { .. }
        )))
    ));
    assert!(!called.get());
    assert_eq!(wal.writer.bytes, before);
    assert!(
        replay_bytes(&before)
            .transactions
            .contains_key(&transaction)
    );

    let prepared = frame(&state(tx(22), TransactionState::Prepared));
    let phase = frame(&state(tx(22), TransactionState::ParentSealIntent));
    let intent = PermissionIntent {
        transaction: tx(22),
        mutation_id: 1,
        evidence: evidence("tree"),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    let intent_len = frame(&intent.clone().into_record()).len() as u64;
    let limit = (prepared.len() + phase.len()) as u64 + intent_len - 1;
    let mut limited = SealWal::new_with_limit(FaultWriter::default(), limit).unwrap();
    limited.begin(tx(22)).unwrap();
    limited
        .transition(tx(22), TransactionState::ParentSealIntent)
        .unwrap();
    let stable = limited.writer.bytes.clone();
    assert!(matches!(
        limited.apply_permission_mutation(intent, || panic!("must preflight total size")),
        Err(MutationAppendError::IntentWal(
            AppendError::TotalSize { .. }
        ))
    ));
    assert_eq!(limited.writer.bytes, stable);
    assert!(replay_bytes(&stable).transactions.contains_key(&tx(22)));
}

#[test]
fn unknown_intent_only_produces_resolution_work_and_can_stop_recovery() {
    let transaction = tx(23);
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(transaction).unwrap();
    wal.transition(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: evidence("tree"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Err(io::Error::from_raw_os_error(5))
        ),
        Err(MutationAppendError::Mutation(_))
    ));
    let replay = replay_bytes(&wal.writer.bytes);
    assert!(matches!(
        decide_recovery(&replay.transactions[&transaction], |_| {
            panic!("uncertain intent must be resolved before identity work")
        }),
        RecoveryWork::ResolveUncertainPermissions { .. }
    ));
    wal.transition(transaction, TransactionState::RecoveryRequired)
        .unwrap();
    let before = wal.writer.bytes.clone();
    assert!(matches!(
        wal.resolve_unresolved_permission(transaction, 1, |_| Ok(PermissionResolution::Applied)),
        Err(ResolveError::WrongPhase)
    ));
    assert_eq!(wal.writer.bytes, before);
    let replay = replay_bytes(&before);
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RecoveryRequired
    );
}

#[test]
fn protected_header_length_corruption_fails_closed_without_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("length.wal");
    let mut corrupted = frame(&state(tx(24), TransactionState::Prepared));
    corrupted[8] ^= 0x40;
    std::fs::write(&path, &corrupted).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::HeaderChecksum { .. })
    ));
    assert_eq!(std::fs::read(path).unwrap(), corrupted);
}

#[test]
fn confirmed_not_applied_seal_cannot_complete_its_phase() {
    let transaction = tx(27);
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(transaction).unwrap();
    wal.transition(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: evidence("parent"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Err(io::Error::from_raw_os_error(5)),
        ),
        Err(MutationAppendError::Mutation(_))
    ));
    wal.resolve_unresolved_permission(transaction, 1, |_| {
        Ok(PermissionResolution::ConfirmedNotApplied)
    })
    .unwrap();
    assert!(matches!(
        wal.transition(transaction, TransactionState::ParentSealed),
        Err(AppendError::InvalidState(
            "seal phase contains a permission intent not durably applied"
        ))
    ));

    let bytes = wal.into_inner().bytes;
    let replay = replay_bytes(&bytes);
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::ParentSealIntent
    );
    let mut records = parse_frames(&bytes).unwrap().records;
    records.push(state(transaction, TransactionState::ParentSealed));
    assert!(matches!(
        replay_records(records),
        Err(ReplayError::InvalidHistory(
            "seal phase contains a permission intent not durably applied"
        ))
    ));
}

#[test]
fn confirmed_not_applied_inverse_can_be_retried_and_folded() {
    let transaction = tx(28);
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(transaction).unwrap();
    wal.transition(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    wal.apply_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: evidence("source/parent"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        || Ok(()),
    )
    .unwrap();
    wal.transition(transaction, TransactionState::ParentSealed)
        .unwrap();
    wal.transition(transaction, TransactionState::RestoreIntent)
        .unwrap();

    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 2,
                evidence: evidence_mode("trash/parent", 0o770),
                pre_mode: 0o500,
                expected_mode: 0o770,
                reverses_mutation_id: Some(1),
            },
            || Err(io::Error::from_raw_os_error(5)),
        ),
        Err(MutationAppendError::Mutation(_))
    ));
    wal.resolve_unresolved_permission(transaction, 2, |_| {
        Ok(PermissionResolution::ConfirmedNotApplied)
    })
    .unwrap();
    wal.apply_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 3,
            evidence: evidence_mode("restored/parent", 0o770),
            pre_mode: 0o500,
            expected_mode: 0o770,
            reverses_mutation_id: Some(1),
        },
        || Ok(()),
    )
    .unwrap();
    wal.transition(transaction, TransactionState::Restored)
        .unwrap();

    let replay = replay_bytes(&wal.into_inner().bytes);
    let recovered = &replay.transactions[&transaction];
    assert_eq!(recovered.state, TransactionState::Restored);
    assert_eq!(
        recovered.permissions[1].application,
        ApplicationStatus::ConfirmedNotApplied
    );
    assert_eq!(
        recovered.permissions[2].application,
        ApplicationStatus::Applied
    );
    let mut before_terminal = recovered.clone();
    before_terminal.state = TransactionState::RestoreIntent;
    assert!(matches!(
        decide_recovery(&before_terminal, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::RestoreBeforeRename { permissions, .. } if permissions.is_empty()
    ));
}

#[test]
fn public_writer_rejects_illegal_runtime_transitions() {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(tx(15)).unwrap();
    assert!(matches!(
        wal.transition(tx(15), TransactionState::Purged),
        Err(AppendError::InvalidState("invalid transaction transition"))
    ));
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction: tx(15),
                mutation_id: 1,
                evidence: evidence("tree"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Ok(())
        ),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(_)))
    ));
}
