use super::*;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
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

fn checked_frame(version: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&version.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32(&frame[4..12]).to_le_bytes());
    frame.extend_from_slice(&crc32(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn legacy_frame(version: u16, record: &SealRecord) -> Vec<u8> {
    checked_frame(version, encode_record(record).unwrap())
}

fn legacy_v3_staging_begin(
    transaction: TransactionId,
    metadata: &StagingTransactionMetadata,
) -> Vec<u8> {
    fn identity(output: &mut Vec<u8>, identity: StrongObjectIdentity) {
        output.extend_from_slice(&identity.device().to_le_bytes());
        output.extend_from_slice(&identity.inode().to_le_bytes());
        output.extend_from_slice(&identity.incarnation().get().to_le_bytes());
    }
    fn locator(output: &mut Vec<u8>, locator: &StagingLocator) {
        put_bytes(output, locator.relative_path().as_os_str().as_bytes()).unwrap();
        put_bytes(output, locator.filesystem_id().as_bytes()).unwrap();
    }
    let mut payload = vec![5];
    payload.extend_from_slice(&transaction.0);
    locator(&mut payload, metadata.source_parent());
    identity(&mut payload, metadata.source_parent_identity());
    put_bytes(&mut payload, metadata.source_basename().as_bytes()).unwrap();
    identity(&mut payload, metadata.root_identity());
    locator(&mut payload, metadata.destination_parent());
    identity(&mut payload, metadata.destination_parent_identity());
    put_bytes(&mut payload, metadata.destination_basename().as_bytes()).unwrap();
    payload.push(match metadata.backend() {
        CertifiedLocalBackend::Ext4 => 1,
        CertifiedLocalBackend::Xfs => 2,
        CertifiedLocalBackend::Apfs => 3,
    });
    payload.push(1); // PermissionSeal
    checked_frame(3, payload)
}

#[test]
fn older_frame_versions_reject_states_introduced_by_newer_schemas() {
    for (version, state) in [
        (4, TransactionState::SourceParentRestoreIntent),
        (5, TransactionState::UndoIntent),
    ] {
        let transaction = tx(version as u8);
        let mut payload = vec![1];
        payload.extend_from_slice(&transaction.0);
        payload.push(encode_state(state));
        let error = parse_frames(&checked_frame(version, payload))
            .err()
            .unwrap();
        assert!(matches!(
            error,
            ReplayError::Malformed {
                reason: "transaction state is unknown for this frame version",
                ..
            }
        ));
    }
}

#[test]
fn version_seven_staging_and_content_manifest_remain_replayable() {
    let transaction = tx(0x77);
    let metadata = staging_metadata().with_production_association(
        ProductionAssociation::new("v7-production".to_string()).unwrap(),
    );
    let manifest = DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count: 4,
        sha256: [0x77; 32],
    };
    let parsed = parse_frames(
        &[
            legacy_frame(
                7,
                &SealRecord::StagingBegin {
                    transaction,
                    metadata: metadata.clone(),
                },
            ),
            legacy_frame(
                7,
                &SealRecord::TreeManifestComplete {
                    transaction,
                    manifest,
                },
            ),
        ]
        .concat(),
    )
    .unwrap();
    let SealRecord::StagingBegin {
        metadata: decoded, ..
    } = &parsed.records[0].record
    else {
        panic!("expected v7 staging metadata")
    };
    assert_eq!(decoded, &metadata);
    let SealRecord::TreeManifestComplete {
        manifest: decoded, ..
    } = parsed.records[1].record
    else {
        panic!("expected v7 content manifest")
    };
    assert_eq!(decoded, manifest);
    assert!(decoded.has_content_proof());
}

#[test]
fn version_six_manifest_decodes_as_metadata_only_content_unproven() {
    let transaction = tx(0x76);
    let mut payload = vec![6];
    payload.extend_from_slice(&transaction.0);
    payload.extend_from_slice(&3_u64.to_le_bytes());
    payload.extend_from_slice(&[0x5a; 32]);
    let parsed = parse_frames(&checked_frame(6, payload)).unwrap();
    let SealRecord::TreeManifestComplete { manifest, .. } = &parsed.records[0].record else {
        panic!("expected manifest");
    };
    assert_eq!(manifest.schema_version, 1);
    assert!(!manifest.has_content_proof());
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

fn replay_checked_fixture(bytes: &[u8]) -> Replay {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("legacy.wal");
    std::fs::write(&path, bytes).unwrap();
    let mut session = RecoverySession::try_acquire(open_rw(&path)).unwrap();
    session.replay_and_repair().unwrap().clone()
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
    version[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
    let version_header_crc = crc32(&version[4..12]);
    version[12..16].copy_from_slice(&version_header_crc.to_le_bytes());
    std::fs::write(&version_path, &version).unwrap();
    let mut lock = RecoverySession::try_acquire(open_rw(&version_path)).unwrap();
    assert!(matches!(
        lock.replay_and_repair(),
        Err(ReplayError::UnsupportedLegacyVersion { version, .. }) if version == VERSION + 1
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
fn legacy_v1_checksummed_unresolved_permission_replays_explicitly() {
    let transaction = tx(0x31);
    let intent = SealRecord::PermissionIntent {
        transaction,
        mutation_id: 9,
        evidence: evidence("legacy/tree"),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    let bytes = [
        legacy_frame(1, &state(transaction, TransactionState::Prepared)),
        legacy_frame(1, &state(transaction, TransactionState::ParentSealIntent)),
        legacy_frame(1, &intent),
    ]
    .concat();
    let replay = replay_checked_fixture(&bytes);
    let transaction = &replay.transactions[&transaction];
    assert_eq!(transaction.staging_schema_version, None);
    assert_eq!(
        transaction.permissions[0].application,
        ApplicationStatus::IntentDurableApplicationUnknown
    );
}

#[test]
fn legacy_v3_staging_frame_replays_without_inventing_mount_authority() {
    let transaction = tx(0x33);
    let metadata = staging_metadata();
    let intent = SealRecord::PermissionIntent {
        transaction,
        mutation_id: 1,
        evidence: staging_evidence("source-parent", metadata.source_parent_identity(), 0o500),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    let bytes = [
        legacy_v3_staging_begin(transaction, &metadata),
        legacy_frame(3, &state(transaction, TransactionState::ParentSealIntent)),
        legacy_frame(3, &intent),
    ]
    .concat();
    let replay = replay_checked_fixture(&bytes);
    let legacy = &replay.transactions[&transaction];
    assert_eq!(legacy.staging_schema_version, Some(3));
    assert_eq!(
        legacy.staging.as_ref().unwrap().root_identity().mount_id(),
        0
    );
    assert_eq!(
        legacy.permissions[0].application,
        ApplicationStatus::IntentDurableApplicationUnknown
    );
    assert!(matches!(
        decide_recovery(legacy, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::RecoveryRequired {
            reason: RecoveryRequiredReason::LegacySchemaMissingMountIdentity { version: 3 },
            ..
        }
    ));
    let resumed = SealWal::resume(
        FaultWriter {
            bytes,
            ..FaultWriter::default()
        },
        &replay,
    )
    .unwrap();
    assert_eq!(
        resumed
            .recovery_snapshot(transaction)
            .unwrap()
            .staging_schema_version,
        Some(3)
    );
}

#[test]
fn staging_begin_version_not_transaction_minimum_controls_mount_authority() {
    let transaction = tx(0x34);
    let metadata = staging_metadata();
    let bytes = [
        frame(&SealRecord::StagingBegin {
            transaction,
            metadata,
        }),
        legacy_frame(3, &state(transaction, TransactionState::ParentSealIntent)),
    ]
    .concat();
    let replay = replay_checked_fixture(&bytes);
    let current_metadata = &replay.transactions[&transaction];
    assert_eq!(current_metadata.staging_schema_version, Some(VERSION));
    assert!(!matches!(
        decide_recovery(current_metadata, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::RecoveryRequired {
            reason: RecoveryRequiredReason::LegacySchemaMissingMountIdentity { .. },
            ..
        }
    ));
}

#[test]
fn terminal_legacy_staging_metadata_does_not_block_the_next_transaction() {
    let old_id = tx(0x35);
    let metadata = staging_metadata();
    let mut legacy = replay_checked_fixture(&legacy_v3_staging_begin(old_id, &metadata))
        .transactions
        .remove(&old_id)
        .unwrap();
    assert_eq!(legacy.staging_schema_version, Some(3));
    for (index, terminal) in [
        TransactionState::VerifiedCommitted,
        TransactionState::Restored,
        TransactionState::RolledBack,
        TransactionState::Purged,
    ]
    .into_iter()
    .enumerate()
    {
        legacy.state = terminal;
        let replay = Replay {
            transactions: [(old_id, legacy.clone())].into_iter().collect(),
            transaction_order: vec![old_id],
            tail_repair: None,
            committed_len: 0,
        };
        assert!(!matches!(
            decide_recovery(&legacy, |_| RecoveryIdentity::Reestablished),
            RecoveryWork::RecoveryRequired {
                reason: RecoveryRequiredReason::LegacySchemaMissingMountIdentity { .. },
                ..
            }
        ));
        let mut wal = SealWal::resume(FaultWriter::default(), &replay).unwrap();
        assert!(wal.can_begin_staging_transaction());
        wal.begin_staging(tx(0x40 + index as u8), staging_metadata())
            .unwrap();
    }
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
        staging_schema_version: None,
        permissions: vec![DurablePermission {
            mutation_id: 1,
            phase: TransactionState::TreeSealIntent,
            evidence: evidence("tree/dir"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
            application: ApplicationStatus::Applied,
        }],
        staging: None,
        tree_manifest: None,
        rename_outcome: None,
        undo_rename_outcome: None,
        purge_removed_entries: 0,
        purge_last_path: None,
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
    let terminals = [S::Purged, S::Restored, S::RolledBack, S::RecoveryRequired];
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
    assert!(valid_transition(S::Quarantined, S::RecoveryRequired));
    assert!(!valid_transition(S::Quarantined, S::RestoreIntent));
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
            state(transaction, TransactionState::RecoveryRequired),
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
    assert!(matches!(
        result,
        RecoveryWork::RestoreQuarantinedSeals { transaction, permissions }
            if transaction == tx(10) && permissions.len() == 1
    ));
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
    records.push(state(transaction, TransactionState::ParentSealed).into_versioned());
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

fn strong(device: u64, inode: u64, incarnation: u64) -> StrongObjectIdentity {
    StrongObjectIdentity {
        device,
        inode,
        incarnation: ObjectIncarnation::new(incarnation),
        mount_id: 7,
    }
}

fn staging_metadata() -> StagingTransactionMetadata {
    let source_parent = StagingLocator::new(PathBuf::from("source-parent"), "fs-1".into()).unwrap();
    let source_parent_identity = strong(1, 10, 100);
    StagingTransactionMetadata::new(
        source_parent.clone(),
        source_parent_identity,
        std::ffi::OsString::from("root"),
        strong(1, 11, 101),
        StagingLocator::new(PathBuf::from("trash-parent"), "fs-1".into()).unwrap(),
        strong(1, 12, 102),
        std::ffi::OsString::from("staged-root"),
        CertifiedLocalBackend::Ext4,
        DurableSourceParentStrategy::AlreadyExclusive(DurableAlreadyExclusiveParent {
            source_parent,
            source_parent_identity,
            observed_mode: 0o700,
        }),
    )
    .unwrap()
}

fn permission_seal_staging_metadata() -> StagingTransactionMetadata {
    let mut metadata = staging_metadata();
    metadata.source_parent_strategy = DurableSourceParentStrategy::PermissionSeal;
    metadata
}

fn staging_tree_evidence(path: &str, inode: u64) -> PersistentRecoveryEvidence {
    PersistentRecoveryEvidence::new(
        PathBuf::from(path),
        Some("fs-1".into()),
        1,
        inode,
        Some(inode + 100),
        0o500,
    )
    .unwrap()
}

fn advance_to_tree_intent(wal: &mut SealWal<FaultWriter>, transaction: TransactionId) {
    wal.transition_staging(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::ParentSealed)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::TreeSealIntent)
        .unwrap();
}

#[test]
fn staging_begin_is_one_first_frame_and_roundtrips_complete_metadata() {
    let transaction = tx(71);
    let metadata = staging_metadata();
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata.clone()).unwrap();
    let parsed = parse_frames(&wal.into_inner().bytes).unwrap();
    assert_eq!(parsed.records.len(), 1);
    assert!(matches!(
        &parsed.records[0].record,
        SealRecord::StagingBegin { transaction: id, metadata: actual }
            if *id == transaction && actual == &metadata
    ));
    let replay = replay_records(parsed.records).unwrap();
    assert_eq!(
        replay.transactions[&transaction].staging.as_ref(),
        Some(&metadata)
    );
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::Prepared
    );
}

#[test]
fn staging_begin_sync_failure_does_not_publish_an_in_memory_transaction() {
    let transaction = tx(72);
    let mut wal = SealWal::new(FaultWriter {
        fail_sync_at: Some((0, libc::EIO)),
        ..FaultWriter::default()
    })
    .unwrap();
    assert!(matches!(
        wal.begin_staging(transaction, staging_metadata()),
        Err(AppendError::Io(_))
    ));
    assert_eq!(wal.transaction_state(transaction), None);
    assert!(matches!(
        wal.begin_staging(transaction, staging_metadata()),
        Err(AppendError::Poisoned)
    ));
}

#[test]
fn manifest_and_explicit_rename_intent_enforce_order_and_uniqueness() {
    let transaction = tx(73);
    let metadata = staging_metadata();
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata).unwrap();
    advance_to_tree_intent(&mut wal, transaction);
    assert!(matches!(
        wal.transition_staging(transaction, TransactionState::TreeSealed),
        Err(AppendError::InvalidState(_))
    ));
    let manifest = DurableTreeManifest {
        schema_version: 2,
        entry_count: 9,
        sha256: [0x5a; 32],
    };
    wal.complete_tree_manifest(transaction, manifest).unwrap();
    assert!(matches!(
        wal.complete_tree_manifest(transaction, manifest),
        Err(AppendError::InvalidState(_))
    ));
    wal.transition_staging(transaction, TransactionState::TreeSealed)
        .unwrap();
    assert!(matches!(
        wal.transition_staging(transaction, TransactionState::RenameIntent),
        Err(AppendError::InvalidState(_))
    ));
    wal.record_rename_intent(transaction).unwrap();

    // There is intentionally no writer API for a rename outcome until the
    // held-tree executor can retain both authenticated parent capabilities.
    let parsed = parse_frames(&wal.into_inner().bytes).unwrap();
    let replay = replay_records(parsed.records).unwrap();
    assert_eq!(
        replay.transactions[&transaction].tree_manifest,
        Some(manifest)
    );
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RenameIntent
    );
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
}
fn replay_rename_crash_boundary(
    transaction: TransactionId,
    outcome: Option<DurableRenameOutcome>,
) -> ReplayedTransaction {
    let metadata = staging_metadata();
    let mut records = vec![
        SealRecord::StagingBegin {
            transaction,
            metadata,
        },
        state(transaction, TransactionState::ParentSealIntent),
        state(transaction, TransactionState::ParentSealed),
        state(transaction, TransactionState::TreeSealIntent),
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: staging_tree_evidence("tree", 20),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 1,
        },
        SealRecord::PermissionIntent {
            transaction,
            mutation_id: 2,
            evidence: staging_tree_evidence("tree/child", 21),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        SealRecord::PermissionApplied {
            transaction,
            mutation_id: 2,
        },
        SealRecord::TreeManifestComplete {
            transaction,
            manifest: DurableTreeManifest {
                schema_version: 2,
                entry_count: 2,
                sha256: [0xa3; 32],
            },
        },
        state(transaction, TransactionState::TreeSealed),
        SealRecord::RenameIntent { transaction },
    ];
    if let Some(outcome) = outcome {
        records.push(SealRecord::RenameOutcome {
            transaction,
            outcome,
        });
    }
    replay_records(records)
        .unwrap()
        .transactions
        .remove(&transaction)
        .unwrap()
}

#[test]
fn crash_after_durable_applied_rename_outcome_routes_to_post_rename_verification() {
    let transaction = tx(77);
    let root = staging_metadata().root_identity;
    let replayed = replay_rename_crash_boundary(
        transaction,
        Some(DurableRenameOutcome::AppliedAndParentsSynced(root)),
    );
    assert_eq!(replayed.state, TransactionState::RenameIntent);
    assert!(matches!(
        decide_recovery(&replayed, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: id,
            permissions,
        } if id == transaction
            && permissions.iter().map(|permission| permission.mutation_id).collect::<Vec<_>>()
                == vec![1, 2]
    ));
    assert_eq!(
        decide_recovery(&replayed, |_| RecoveryIdentity::Insufficient),
        RecoveryWork::RecoveryRequired {
            transaction,
            reason: RecoveryRequiredReason::InsufficientPersistentIdentity,
        }
    );
}

#[test]
fn crash_after_durable_not_applied_rename_outcome_restores_deepest_first() {
    let transaction = tx(78);
    let root = staging_metadata().root_identity;
    let replayed = replay_rename_crash_boundary(
        transaction,
        Some(DurableRenameOutcome::ConfirmedNotAppliedAtSource(root)),
    );
    assert_eq!(replayed.state, TransactionState::RenameIntent);
    assert!(matches!(
        decide_recovery(&replayed, |_| RecoveryIdentity::Reestablished),
        RecoveryWork::RestoreBeforeRename {
            transaction: id,
            permissions,
        } if id == transaction
            && permissions.iter().map(|permission| permission.mutation_id).collect::<Vec<_>>()
                == vec![2, 1]
    ));
}

#[test]
fn crash_after_rename_intent_without_outcome_requires_outcome_recovery() {
    let transaction = tx(79);
    let replayed = replay_rename_crash_boundary(transaction, None);
    assert_eq!(replayed.state, TransactionState::RenameIntent);
    assert_eq!(replayed.rename_outcome, None);
    assert_eq!(
        decide_recovery(&replayed, |_| panic!(
            "no mutation identity needed without an outcome"
        )),
        RecoveryWork::RecoveryRequired {
            transaction,
            reason: RecoveryRequiredReason::RenameOutcomeUnknown,
        }
    );
}

#[test]
fn replay_rejects_bare_or_duplicate_staging_history_and_conflicting_outcomes() {
    let transaction = tx(74);
    let metadata = staging_metadata();
    assert!(matches!(
        replay_records(vec![
            state(transaction, TransactionState::Prepared),
            SealRecord::RenameIntent { transaction },
        ]),
        Err(ReplayError::InvalidHistory(_))
    ));
    let mut conflicting = metadata.clone();
    conflicting.root_identity = strong(1, 700, 701);
    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            },
            SealRecord::StagingBegin {
                transaction,
                metadata: conflicting,
            },
        ]),
        Err(ReplayError::InvalidHistory(_))
    ));
    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            },
            SealRecord::RenameOutcome {
                transaction,
                outcome: DurableRenameOutcome::AppliedAndParentsSynced(metadata.root_identity),
            },
        ]),
        Err(ReplayError::InvalidHistory(_))
    ));
    let manifest = DurableTreeManifest {
        schema_version: 2,
        entry_count: 1,
        sha256: [9; 32],
    };
    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            },
            state(transaction, TransactionState::ParentSealIntent),
            state(transaction, TransactionState::ParentSealed),
            state(transaction, TransactionState::TreeSealIntent),
            SealRecord::TreeManifestComplete {
                transaction,
                manifest,
            },
            SealRecord::TreeManifestComplete {
                transaction,
                manifest,
            },
        ]),
        Err(ReplayError::InvalidHistory(_))
    ));
    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata,
            },
            state(transaction, TransactionState::ParentSealIntent),
            state(transaction, TransactionState::ParentSealed),
            state(transaction, TransactionState::TreeSealIntent),
            SealRecord::TreeManifestComplete {
                transaction,
                manifest,
            },
            state(transaction, TransactionState::TreeSealed),
            SealRecord::RenameIntent { transaction },
            SealRecord::RenameOutcome {
                transaction,
                outcome: DurableRenameOutcome::AppliedAndParentsSynced(strong(1, 11, 101)),
            },
            SealRecord::RenameOutcome {
                transaction,
                outcome: DurableRenameOutcome::AppliedAndParentsSynced(strong(1, 11, 101)),
            },
        ]),
        Err(ReplayError::InvalidHistory(_))
    ));
}

#[test]
fn replay_requires_the_post_stage_source_parent_restore_order() {
    let transaction = tx(75);
    let metadata = staging_metadata();
    let manifest = DurableTreeManifest {
        schema_version: 2,
        entry_count: 0,
        sha256: [7; 32],
    };
    let prefix = vec![
        SealRecord::StagingBegin {
            transaction,
            metadata: metadata.clone(),
        },
        state(transaction, TransactionState::ParentSealIntent),
        state(transaction, TransactionState::ParentSealed),
        state(transaction, TransactionState::TreeSealIntent),
        SealRecord::TreeManifestComplete {
            transaction,
            manifest,
        },
        state(transaction, TransactionState::TreeSealed),
        SealRecord::RenameIntent { transaction },
        SealRecord::RenameOutcome {
            transaction,
            outcome: DurableRenameOutcome::AppliedAndParentsSynced(metadata.root_identity),
        },
        state(transaction, TransactionState::StagedUnverified),
    ];
    let mut early_restore = prefix.clone();
    early_restore.push(state(
        transaction,
        TransactionState::SourceParentRestoreIntent,
    ));
    assert!(matches!(
        replay_records(early_restore),
        Err(ReplayError::InvalidHistory(
            "invalid transaction transition"
        ))
    ));

    let mut complete = prefix;
    complete.extend([
        state(transaction, TransactionState::StagedSealed),
        state(transaction, TransactionState::SourceParentRestoreIntent),
        state(transaction, TransactionState::SourceParentRestored),
        state(transaction, TransactionState::VerifiedCommitted),
    ]);
    assert_eq!(
        replay_records(complete).unwrap().transactions[&transaction].state,
        TransactionState::VerifiedCommitted
    );
}
fn staging_evidence(
    path: &str,
    identity: StrongObjectIdentity,
    expected_mode: u32,
) -> PersistentRecoveryEvidence {
    PersistentRecoveryEvidence::new(
        PathBuf::from(path),
        Some("fs-1".into()),
        identity.device,
        identity.inode,
        Some(identity.incarnation.get()),
        expected_mode,
    )
    .unwrap()
}

#[test]
fn manifest_completion_freezes_tree_permission_membership_at_runtime_and_replay() {
    let transaction = tx(77);
    let metadata = staging_metadata();
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata.clone()).unwrap();
    advance_to_tree_intent(&mut wal, transaction);
    wal.apply_staging_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: staging_evidence("source-parent/root/child", strong(1, 50, 500), 0o500),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        || Ok(()),
    )
    .unwrap();
    let manifest = DurableTreeManifest {
        schema_version: 2,
        entry_count: 1,
        sha256: [0x44; 32],
    };
    wal.complete_tree_manifest(transaction, manifest).unwrap();
    let called = Cell::new(false);
    assert!(matches!(
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 2,
                evidence: staging_evidence(
                    "source-parent/root/late-child",
                    strong(1, 51, 501),
                    0o500,
                ),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || {
                called.set(true);
                Ok(())
            },
        ),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "tree permission membership is frozen by the manifest"
        )))
    ));
    assert!(!called.get());

    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata,
            },
            state(transaction, TransactionState::ParentSealIntent),
            state(transaction, TransactionState::ParentSealed),
            state(transaction, TransactionState::TreeSealIntent),
            SealRecord::TreeManifestComplete {
                transaction,
                manifest,
            },
            SealRecord::PermissionIntent {
                transaction,
                mutation_id: 9,
                evidence: staging_evidence(
                    "source-parent/root/late-child",
                    strong(1, 59, 509),
                    0o500,
                ),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
        ]),
        Err(ReplayError::InvalidHistory(
            "tree permission membership changed after manifest completion"
        ))
    ));
}

#[test]
fn parent_seal_and_inverse_are_bound_to_exact_metadata_parent() {
    let transaction = tx(78);
    let metadata = permission_seal_staging_metadata();
    let parent = metadata.source_parent_identity;
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata.clone()).unwrap();
    wal.transition_staging(transaction, TransactionState::ParentSealIntent)
        .unwrap();

    let copied_identity_wrong_locator = PermissionIntent {
        transaction,
        mutation_id: 1,
        evidence: staging_evidence("other-parent", parent, 0o500),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    assert!(matches!(
        wal.apply_staging_permission_mutation(copied_identity_wrong_locator.clone(), || {
            panic!("mismatched parent must not mutate")
        }),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(_)))
    ));
    assert!(matches!(
        replay_records(vec![
            SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            },
            state(transaction, TransactionState::ParentSealIntent),
            copied_identity_wrong_locator.into_record(),
        ]),
        Err(ReplayError::InvalidHistory(
            "parent seal evidence differs from the metadata-bound source parent"
        ))
    ));

    wal.apply_staging_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 2,
            evidence: staging_evidence("source-parent", parent, 0o500),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        || Ok(()),
    )
    .unwrap();
    wal.transition_staging(transaction, TransactionState::ParentSealed)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::RestoreIntent)
        .unwrap();
    assert!(matches!(
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 3,
                evidence: staging_evidence("other-parent", parent, 0o770),
                pre_mode: 0o500,
                expected_mode: 0o770,
                reverses_mutation_id: Some(2),
            },
            || panic!("mismatched inverse must not mutate"),
        ),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(_)))
    ));
}

#[test]
fn already_exclusive_strategy_is_explicit_exact_and_non_vacuous() {
    let base = staging_metadata();
    let make = |proof: DurableAlreadyExclusiveParent| {
        StagingTransactionMetadata::new(
            base.source_parent.clone(),
            base.source_parent_identity,
            base.source_basename.clone(),
            base.root_identity,
            base.destination_parent.clone(),
            base.destination_parent_identity,
            base.destination_basename.clone(),
            base.backend,
            DurableSourceParentStrategy::AlreadyExclusive(proof),
        )
    };
    assert!(
        make(DurableAlreadyExclusiveParent {
            source_parent: base.source_parent.clone(),
            source_parent_identity: strong(1, 999, 999),
            observed_mode: 0o700,
        })
        .is_none()
    );
    assert!(
        make(DurableAlreadyExclusiveParent {
            source_parent: base.source_parent.clone(),
            source_parent_identity: base.source_parent_identity,
            observed_mode: 0o770,
        })
        .is_none()
    );

    let metadata = make(DurableAlreadyExclusiveParent {
        source_parent: base.source_parent.clone(),
        source_parent_identity: base.source_parent_identity,
        observed_mode: 0o700,
    })
    .unwrap();
    let transaction = tx(79);
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata).unwrap();
    wal.transition_staging(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::ParentSealed)
        .unwrap();
}

fn wal_at_rename_intent(transaction: TransactionId) -> SealWal<FaultWriter> {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, staging_metadata()).unwrap();
    advance_to_tree_intent(&mut wal, transaction);
    wal.complete_tree_manifest(
        transaction,
        DurableTreeManifest {
            schema_version: 2,
            entry_count: 0,
            sha256: [0xa3; 32],
        },
    )
    .unwrap();
    wal.transition_staging(transaction, TransactionState::TreeSealed)
        .unwrap();
    wal.record_rename_intent(transaction).unwrap();
    wal
}

fn wal_at_staged_unverified(transaction: TransactionId) -> SealWal<FaultWriter> {
    let mut wal = wal_at_rename_intent(transaction);
    wal.record_applied_rename_for_test(transaction).unwrap();
    wal.transition_staging(transaction, TransactionState::StagedUnverified)
        .unwrap();
    wal
}

#[test]
fn rename_outcome_and_staged_state_real_writer_failures_poison_without_success() {
    // Partial outcome frame: replay sees only the durable RenameIntent prefix.
    let transaction = tx(0xb2);
    let mut partial = wal_at_rename_intent(transaction);
    partial.writer.write_error_after = Some((partial.writer.bytes.len() + 7, libc::EIO));
    assert!(partial.record_applied_rename_for_test(transaction).is_err());
    assert_eq!(
        partial.transaction_state(transaction),
        Some(TransactionState::RenameIntent)
    );
    assert_eq!(
        partial
            .recovery_snapshot(transaction)
            .unwrap()
            .rename_outcome,
        None
    );
    assert!(matches!(
        partial.append_synced(&state(transaction, TransactionState::RecoveryRequired)),
        Err(AppendError::Poisoned)
    ));
    let replay = replay_bytes(&partial.into_inner().bytes);
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);

    // Outcome sync failure may leave the complete frame physically visible, but
    // the live writer is poisoned and publishes no in-memory transition token.
    let transaction = tx(0xb3);
    let mut outcome_sync = wal_at_rename_intent(transaction);
    outcome_sync.writer.fail_sync_at = Some((outcome_sync.writer.sync_count, libc::EIO));
    assert!(
        outcome_sync
            .record_applied_rename_for_test(transaction)
            .is_err()
    );
    assert_eq!(
        outcome_sync.transaction_state(transaction),
        Some(TransactionState::RenameIntent)
    );
    assert_eq!(
        outcome_sync
            .recovery_snapshot(transaction)
            .unwrap()
            .rename_outcome,
        None
    );

    // The applied outcome is durable, but the following state sync fails. The
    // outcome remains the only published in-memory fact and the writer poisons.
    let transaction = tx(0xb4);
    let mut state_sync = wal_at_rename_intent(transaction);
    state_sync
        .record_applied_rename_for_test(transaction)
        .unwrap();
    state_sync.writer.fail_sync_at = Some((state_sync.writer.sync_count, libc::EIO));
    assert!(
        state_sync
            .transition_staging(transaction, TransactionState::StagedUnverified)
            .is_err()
    );
    assert_eq!(
        state_sync.transaction_state(transaction),
        Some(TransactionState::RenameIntent)
    );
    assert!(matches!(
        state_sync
            .recovery_snapshot(transaction)
            .unwrap()
            .rename_outcome,
        Some(DurableRenameOutcome::AppliedAndParentsSynced(_))
    ));
    assert!(matches!(
        state_sync.transition_staging(transaction, TransactionState::StagedUnverified),
        Err(AppendError::Poisoned)
    ));
}

#[test]
fn staged_verification_state_sync_failure_never_publishes_success_or_quarantine() {
    for next in [
        TransactionState::StagedSealed,
        TransactionState::Quarantined,
    ] {
        let transaction = tx(if next == TransactionState::StagedSealed {
            0xa1
        } else {
            0xa2
        });
        let mut wal = wal_at_staged_unverified(transaction);
        wal.writer.fail_sync_at = Some((wal.writer.sync_count, libc::EIO));
        assert!(wal.transition_staging(transaction, next).is_err());
        assert_eq!(
            wal.transaction_state(transaction),
            Some(TransactionState::StagedUnverified)
        );
    }
}

#[test]
fn foundation_transition_seam_cannot_bypass_verification_commit_or_purge_proofs() {
    let transaction = tx(0xaf);
    let mut wal = wal_at_staged_unverified(transaction);
    for forbidden in [
        TransactionState::StagedSealed,
        TransactionState::RollbackIntent,
        TransactionState::RolledBack,
        TransactionState::SourceParentRestoreIntent,
        TransactionState::SourceParentRestored,
        TransactionState::VerifiedCommitted,
        TransactionState::Purgeable,
        TransactionState::Purged,
    ] {
        assert!(matches!(
            wal.transition_staging_foundation(transaction, forbidden),
            Err(AppendError::InvalidState(
                "staging state requires an unavailable authority proof"
            ))
        ));
        assert_eq!(
            wal.transaction_state(transaction),
            Some(TransactionState::StagedUnverified)
        );
    }
}

#[test]
fn authority_neutral_public_methods_cannot_drive_a_staging_transaction() {
    let transaction = tx(80);
    let metadata = staging_metadata();
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata.clone()).unwrap();
    assert!(matches!(
        wal.transition(transaction, TransactionState::ParentSealIntent),
        Err(AppendError::InvalidState(
            "staging transitions require the high-level engine"
        ))
    ));
    assert!(matches!(
        wal.apply_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: staging_evidence("source-parent/root", metadata.root_identity, 0o500,),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || panic!("public authority-neutral seam must not mutate staging"),
        ),
        Err(MutationAppendError::IntentWal(AppendError::InvalidState(
            "staging permission mutation requires the high-level engine"
        )))
    ));
    for next in [TransactionState::Purgeable, TransactionState::Purged] {
        assert!(wal.transition_staging(transaction, next).is_err());
    }
}

#[test]
fn purge_authorization_sync_failure_never_publishes_purgeable() {
    let transaction = tx(0xc6);
    let metadata = staging_metadata()
        .with_production_association(ProductionAssociation::new("purge-sync".to_string()).unwrap());
    let manifest = DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count: 0,
        sha256: [0xa3; 32],
    };
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin_staging(transaction, metadata).unwrap();
    advance_to_tree_intent(&mut wal, transaction);
    wal.complete_tree_manifest(transaction, manifest).unwrap();
    wal.transition_staging(transaction, TransactionState::TreeSealed)
        .unwrap();
    wal.record_rename_intent(transaction).unwrap();
    wal.record_applied_rename_for_test(transaction).unwrap();
    wal.transition_staging(transaction, TransactionState::StagedUnverified)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::StagedSealed)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::SourceParentRestoreIntent)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::SourceParentRestored)
        .unwrap();
    wal.transition_staging(transaction, TransactionState::VerifiedCommitted)
        .unwrap();

    wal.writer.fail_sync_at = Some((wal.writer.sync_count, libc::EIO));
    let proof = crate::staging_recovery::ExactPurgeVerification::for_test(transaction, manifest);
    assert!(matches!(
        wal.record_purgeable(proof),
        Err(AppendError::Io(_))
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(matches!(
        wal.transition_recovery_required(transaction),
        Err(AppendError::Poisoned)
    ));
}

#[test]
fn purgeable_has_only_the_explicit_v8_authorization_record() {
    assert!(valid_transition(
        TransactionState::VerifiedCommitted,
        TransactionState::Purgeable
    ));
    assert!(!valid_transition(
        TransactionState::Purgeable,
        TransactionState::Purged
    ));

    let transaction = tx(0xc5);
    let metadata = staging_metadata().with_production_association(
        ProductionAssociation::new("purge-group".to_string()).unwrap(),
    );
    let manifest = DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count: 1,
        sha256: [0x5a; 32],
    };
    let prefix = vec![
        SealRecord::StagingBegin {
            transaction,
            metadata: metadata.clone(),
        },
        state(transaction, TransactionState::ParentSealIntent),
        state(transaction, TransactionState::ParentSealed),
        state(transaction, TransactionState::TreeSealIntent),
        SealRecord::TreeManifestComplete {
            transaction,
            manifest,
        },
        state(transaction, TransactionState::TreeSealed),
        SealRecord::RenameIntent { transaction },
        SealRecord::RenameOutcome {
            transaction,
            outcome: DurableRenameOutcome::AppliedAndParentsSynced(metadata.root_identity()),
        },
        state(transaction, TransactionState::StagedUnverified),
        state(transaction, TransactionState::StagedSealed),
        state(transaction, TransactionState::SourceParentRestoreIntent),
        state(transaction, TransactionState::SourceParentRestored),
        state(transaction, TransactionState::VerifiedCommitted),
    ];

    let mut generic = prefix.clone();
    generic.push(state(transaction, TransactionState::Purgeable));
    let generic_result = replay_records(generic);
    assert!(
        matches!(
            generic_result,
            Err(ReplayError::InvalidHistory(
                "purgeable must use its explicit authorization record"
            ))
        ),
        "unexpected generic replay result: {generic_result:?}"
    );

    let mut explicit = prefix.clone();
    explicit.push(SealRecord::PurgeAuthorized {
        transaction,
        commitment: DurablePurgeCommitment::exact(&metadata, manifest),
    });
    let replayed = replay_records(explicit).unwrap();
    assert_eq!(
        replayed.transactions[&transaction].state,
        TransactionState::Purgeable
    );
    assert!(matches!(
        decide_recovery(&replayed.transactions[&transaction], |_| {
            RecoveryIdentity::Reestablished
        }),
        RecoveryWork::PreserveCommittedSeal {
            state: TransactionState::Purgeable,
            ..
        }
    ));

    let mut forged = prefix;
    let mut commitment = DurablePurgeCommitment::exact(&metadata, manifest);
    commitment.root_identity = strong(9, 9, 9);
    forged.push(SealRecord::PurgeAuthorized {
        transaction,
        commitment,
    });
    assert!(matches!(
        replay_records(forged),
        Err(ReplayError::InvalidHistory(
            "purge authorization does not bind the exact committed object"
        ))
    ));
}

#[test]
fn v10_purge_claim_and_progress_replay_fail_closed_on_every_invalid_shape() {
    let transaction = tx(0xc7);
    let metadata = staging_metadata().with_production_association(
        ProductionAssociation::new("progress-group".to_string()).unwrap(),
    );
    let manifest = DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count: 2,
        sha256: [0x6b; 32],
    };
    let authorized = || {
        vec![
            SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            },
            state(transaction, TransactionState::ParentSealIntent),
            state(transaction, TransactionState::ParentSealed),
            state(transaction, TransactionState::TreeSealIntent),
            SealRecord::TreeManifestComplete {
                transaction,
                manifest,
            },
            state(transaction, TransactionState::TreeSealed),
            SealRecord::RenameIntent { transaction },
            SealRecord::RenameOutcome {
                transaction,
                outcome: DurableRenameOutcome::AppliedAndParentsSynced(metadata.root_identity()),
            },
            state(transaction, TransactionState::StagedUnverified),
            state(transaction, TransactionState::StagedSealed),
            state(transaction, TransactionState::SourceParentRestoreIntent),
            state(transaction, TransactionState::SourceParentRestored),
            state(transaction, TransactionState::VerifiedCommitted),
            SealRecord::PurgeAuthorized {
                transaction,
                commitment: DurablePurgeCommitment::exact(&metadata, manifest),
            },
        ]
    };
    let claim = || SealRecord::PurgeClaimed {
        transaction,
        commitment: DurablePurgeCommitment::exact(&metadata, manifest),
    };
    let progress = |removed_entries, last_path: &str| SealRecord::PurgeProgress {
        transaction,
        removed_entries,
        last_path: PathBuf::from(last_path),
    };

    let cases = [
        {
            let mut records = authorized();
            records.push(progress(1, "child"));
            records
        },
        {
            let mut records = authorized();
            records.extend([claim(), progress(2, "child")]);
            records
        },
        {
            let mut records = authorized();
            records.extend([claim(), progress(1, "../escape")]);
            records
        },
        {
            let mut records = authorized();
            records.extend([claim(), progress(1, "child"), progress(1, "child")]);
            records
        },
        {
            let mut records = authorized();
            records.extend([
                claim(),
                progress(1, "child"),
                state(transaction, TransactionState::PurgeOutcome),
            ]);
            records
        },
    ];
    for records in cases {
        assert!(matches!(
            replay_records(records),
            Err(ReplayError::InvalidHistory(_))
        ));
    }

    let mut forged_claim = authorized();
    let mut commitment = DurablePurgeCommitment::exact(&metadata, manifest);
    commitment.destination_basename = std::ffi::OsString::from("other-root");
    forged_claim.push(SealRecord::PurgeClaimed {
        transaction,
        commitment,
    });
    assert!(matches!(
        replay_records(forged_claim),
        Err(ReplayError::InvalidHistory(
            "purge claim is not bound to the exact authorized object"
        ))
    ));
}

#[test]
fn production_association_round_trips_in_atomic_staging_begin() {
    let transaction = tx(0xc4);
    let metadata = staging_metadata().with_production_association(
        ProductionAssociation::new("reclamation-production".to_string()).unwrap(),
    );
    let replay = replay_bytes(&frame(&SealRecord::StagingBegin {
        transaction,
        metadata,
    }));
    let transaction = &replay.transactions[&transaction];
    let metadata = transaction.staging.as_ref().unwrap();
    assert_eq!(transaction.staging_schema_version, Some(VERSION));
    assert_eq!(
        metadata.production_association().unwrap().reclamation_id(),
        "reclamation-production"
    );
    assert_eq!(metadata.destination_basename(), "staged-root");
    assert_eq!(metadata.root_identity(), strong(1, 11, 101));
}

#[test]
fn version_four_staging_replays_without_inventing_production_authority() {
    let transaction = tx(0xc5);
    let metadata = staging_metadata();
    let mut payload = encode_record(&SealRecord::StagingBegin {
        transaction,
        metadata,
    })
    .unwrap();
    assert_eq!(payload.pop(), Some(0), "v5 optional association tag");
    let replay = replay_bytes(&checked_frame(4, payload));
    let metadata = replay.transactions[&transaction].staging.as_ref().unwrap();
    assert!(metadata.production_association().is_none());
    assert_eq!(
        replay.transactions[&transaction].staging_schema_version,
        Some(4)
    );
}
