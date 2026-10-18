//! Reading a permission record back out of the frame it was written as.
//!
//! The ledger keeps the extent of each admitted intent's frame and no copy of
//! the record, so every decision that wants a record reads one. These tests
//! hold that read to one property: what comes back is the record that went in,
//! or nothing at all.

use super::*;
use crate::seal::wal::permission_ledger::PermissionEntry;

const TRANSACTION: TransactionId = TransactionId([0x6d; 16]);

/// A transaction that has applied one parent seal and is in the phase its
/// inverse belongs to. The seal's extent comes from a replay, so a WAL built on
/// top of this one carries an extent from each source.
fn sealed() -> SealWal<FaultWriter> {
    let mut first = SealWal::new(FaultWriter::default()).unwrap();
    first.begin(TRANSACTION).unwrap();
    first
        .transition(TRANSACTION, TransactionState::ParentSealIntent)
        .unwrap();
    first
        .apply_permission_mutation(
            PermissionIntent {
                transaction: TRANSACTION,
                mutation_id: 1,
                evidence: evidence("parent"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Ok(()),
        )
        .unwrap();
    // Resuming rebuilds the ledger from the frames, so mutation 1's extent is
    // the one the parse recorded rather than the one the append reported.
    let bytes = first.into_inner().bytes;
    let replay = replay_bytes(&bytes);
    let mut resumed = SealWal::resume(
        FaultWriter {
            bytes,
            ..FaultWriter::default()
        },
        replay,
    )
    .unwrap();
    resumed
        .transition(TRANSACTION, TransactionState::ParentSealed)
        .unwrap();
    resumed
        .transition(TRANSACTION, TransactionState::RestoreIntent)
        .unwrap();
    resumed
}

/// The inverse of the seal [`sealed`] applied.
fn inverse_intent() -> PermissionIntent {
    PermissionIntent {
        transaction: TRANSACTION,
        mutation_id: 2,
        evidence: evidence_mode("parent", 0o770),
        pre_mode: 0o500,
        expected_mode: 0o770,
        reverses_mutation_id: Some(1),
    }
}

/// [`sealed`], with the inverse applied on top.
fn seal_and_inverse() -> SealWal<FaultWriter> {
    let mut wal = sealed();
    wal.apply_permission_mutation(inverse_intent(), || Ok(()))
        .unwrap();
    wal
}

/// The records this WAL must answer with, written out rather than taken from
/// the ledger, so the assertion is anchored on the intents the test appended.
fn expected_records() -> Vec<DurablePermission> {
    vec![
        DurablePermission {
            mutation_id: 1,
            phase: TransactionState::ParentSealIntent,
            evidence: evidence("parent"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
            application: ApplicationStatus::Applied,
        },
        DurablePermission {
            mutation_id: 2,
            phase: TransactionState::RestoreIntent,
            evidence: evidence_mode("parent", 0o770),
            pre_mode: 0o500,
            expected_mode: 0o770,
            reverses_mutation_id: Some(1),
            application: ApplicationStatus::Applied,
        },
    ]
}

fn entry_mut(wal: &mut SealWal<FaultWriter>, mutation_id: u64) -> &mut PermissionEntry {
    wal.ledgers
        .get_mut(&TRANSACTION)
        .unwrap()
        .permissions
        .get_mut(&mutation_id)
        .unwrap()
}

#[test]
fn records_come_back_from_their_frames_exactly() {
    let wal = seal_and_inverse();
    assert_eq!(
        wal.permission_records(TRANSACTION).unwrap(),
        expected_records()
    );
}

#[test]
fn an_extent_naming_another_frame_is_refused() {
    let mut wal = seal_and_inverse();
    let inverse = entry_mut(&mut wal, 2).frame;
    // Both frames are valid, checksummed and in this transaction, so the
    // mutation id the frame names is the only thing that gives the pairing
    // away. Nothing else in the decode looks at it.
    entry_mut(&mut wal, 1).frame = inverse;
    assert!(matches!(
        wal.permission_records(TRANSACTION).unwrap_err(),
        PermissionReadError::Mismatch { mutation_id: 1, .. }
    ));
}

#[test]
fn an_extent_naming_a_frame_that_is_not_an_intent_is_refused() {
    let mut wal = seal_and_inverse();
    // The transaction's first frame is its `State` record, at offset zero.
    let state_frame = frame(&state(TRANSACTION, TransactionState::Prepared));
    entry_mut(&mut wal, 1).frame = FrameExtent::new(0, state_frame.len());
    assert!(matches!(
        wal.permission_records(TRANSACTION).unwrap_err(),
        PermissionReadError::Mismatch { mutation_id: 1, .. }
    ));
}

#[test]
fn an_unframed_intent_is_refused() {
    let mut wal = seal_and_inverse();
    entry_mut(&mut wal, 2).frame = None;
    assert!(matches!(
        wal.permission_records(TRANSACTION).unwrap_err(),
        PermissionReadError::Unframed { mutation_id: 2 }
    ));
}

#[test]
fn an_extent_past_the_committed_tail_is_refused() {
    let mut wal = seal_and_inverse();
    let committed = wal.writer.bytes.len();
    entry_mut(&mut wal, 1).frame = FrameExtent::new(committed - HEADER_LEN, HEADER_LEN + 1);
    let error = wal.permission_records(TRANSACTION).unwrap_err();
    assert!(
        matches!(error, PermissionReadError::Io { mutation_id: 1, .. }),
        "a read beyond the tail must fail rather than return a short frame: {error:?}"
    );
}

/// A frame passes its checksum when the index is built and is read back later,
/// so a byte that changed in between is not covered by that first check. On a
/// real store the read goes to disk, where the bytes can rot after the replay
/// that admitted them.
#[test]
fn a_frame_that_changed_after_it_was_indexed_is_refused() {
    let mut wal = seal_and_inverse();
    // A byte of the recorded path, so the frame still decodes: it decodes to a
    // record naming another directory. Nothing but the checksum separates that
    // from the record the entry indexed.
    let start = entry_mut(&mut wal, 1).frame.unwrap().start() as usize;
    let path = start
        + wal.writer.bytes[start..]
            .windows(6)
            .position(|window| window == b"parent")
            .expect("the seal's path is in its own frame");
    wal.writer.bytes[path] = b'P';
    let error = wal.permission_records(TRANSACTION).unwrap_err();
    assert!(
        matches!(error, PermissionReadError::Mismatch { mutation_id: 1, .. }),
        "a frame that decodes to another record must be refused: {error:?}"
    );
}

/// The projection a directory query consumes is built from the same read, so a
/// refused record must refuse the projection rather than leave a seal out of it.
#[test]
fn an_unreadable_record_refuses_the_applied_mode_projection() {
    let wal = seal_and_inverse();
    assert_eq!(
        wal.applied_tree_seal_modes(TRANSACTION).unwrap().mode(
            Path::new("parent"),
            11,
            22,
            33,
            0o770
        ),
        None,
        "a reversed parent seal is not an applied tree seal"
    );
    let mut wal = wal;
    entry_mut(&mut wal, 1).frame = None;
    assert!(wal.applied_tree_seal_modes(TRANSACTION).is_err());
}

/// The evidence and modes an inverse is checked against are in the seal's
/// frame, so an inverse whose seal cannot be read is refused rather than
/// admitted against whatever is left in the ledger.
#[test]
fn an_inverse_whose_seal_cannot_be_read_is_refused() {
    let mut wal = sealed();
    wal.apply_permission_mutation(inverse_intent(), || Ok(()))
        .expect("a readable seal admits its inverse");

    let mut wal = sealed();
    entry_mut(&mut wal, 1).frame = None;
    let error = wal
        .apply_permission_mutation(inverse_intent(), || {
            panic!("a refused inverse must not mutate")
        })
        .unwrap_err();
    assert!(
        matches!(
            error,
            MutationAppendError::PermissionRecord(PermissionReadError::Unframed { mutation_id: 1 })
        ),
        "{error:?}"
    );
}

/// Replay reads the seal an inverse names out of the bytes it was handed. Given
/// none, it says that, rather than saying the inverse does not match: a fixture
/// that models an inverse without framing it would otherwise see the refusal it
/// was fishing for and pass for the wrong reason.
#[test]
fn a_replay_given_no_frames_refuses_the_seal_it_cannot_read() {
    let bytes = seal_and_inverse().into_inner().bytes;
    let error = replay_records(parse_frames(&bytes).unwrap().records, &[]).unwrap_err();
    assert!(
        matches!(
            error,
            ReplayError::PermissionRecord(PermissionReadError::Io { mutation_id: 1, .. })
        ),
        "{error:?}"
    );
    assert!(replay_records(parse_frames(&bytes).unwrap().records, &bytes).is_ok());
}

/// A fixture can replay records it never framed, and the ledger then holds no
/// extent to read. Asking for one of those records must say so, even with the
/// bytes in hand: decoding whatever sits at offset zero would hand a decision
/// another mutation's record, which is how a fixture's refusal comes to pass
/// for a reason it does not name.
#[test]
fn an_unframed_replay_has_no_record_to_give() {
    let records = vec![
        state(TRANSACTION, TransactionState::Prepared),
        state(TRANSACTION, TransactionState::ParentSealIntent),
        SealRecord::PermissionIntent {
            transaction: TRANSACTION,
            mutation_id: 1,
            evidence: evidence("parent"),
            pre_mode: 0o770,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
    ];
    let bytes = framed(&records);

    let unframed = replay_unframed(records).unwrap();
    let error = unframed
        .permission_records(TRANSACTION, &bytes)
        .unwrap_err();
    assert!(
        matches!(error, PermissionReadError::Unframed { mutation_id: 1 }),
        "{error:?}"
    );

    let framed = replay_records(parse_frames(&bytes).unwrap().records, &bytes).unwrap();
    assert_eq!(
        framed
            .permission_records(TRANSACTION, &bytes)
            .unwrap()
            .len(),
        1,
        "the same records, framed, come back"
    );
}

/// An authorized resolver is handed the whole record, which comes out of the
/// frame. An intent that cannot be read back is therefore not resolved at all,
/// rather than resolved against a copy the ledger kept.
#[test]
fn an_unreadable_intent_is_not_resolved() {
    let seen = std::cell::RefCell::new(None);
    let mut wal = uncertain_intent();
    wal.resolve_unresolved_permission(TRANSACTION, 1, |record| {
        *seen.borrow_mut() = Some(record.clone());
        Ok(PermissionResolution::ConfirmedNotApplied)
    })
    .unwrap();
    assert_eq!(
        seen.into_inner().unwrap().evidence,
        evidence("parent"),
        "the resolver decides on the record the frame holds"
    );

    let mut wal = uncertain_intent();
    entry_mut(&mut wal, 1).frame = None;
    let error = wal
        .resolve_unresolved_permission(TRANSACTION, 1, |_| {
            panic!("an unreadable intent must not reach the resolver")
        })
        .unwrap_err();
    assert!(
        matches!(
            error,
            ResolveError::PermissionRecord(PermissionReadError::Unframed { mutation_id: 1 })
        ),
        "{error:?}"
    );
}

/// The resolution an inverse is checked against comes from the entry, not from
/// the frame the seal was read out of -- an intent frame carries no resolution.
///
/// A seal confirmed not applied is the reachable case. It is resolved, so it
/// does not block the move to `RestoreIntent`, and that edge needs no completed
/// seal phase; but it sealed nothing, so nothing may claim to reverse it. An
/// unresolved seal cannot get this far: the transition out of its phase refuses
/// first.
#[test]
fn an_inverse_of_a_seal_confirmed_not_applied_is_refused() {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(TRANSACTION).unwrap();
    for next in [
        TransactionState::ParentSealIntent,
        TransactionState::ParentSealed,
        TransactionState::TreeSealIntent,
    ] {
        wal.transition(TRANSACTION, next).unwrap();
    }
    let seal = PermissionIntent {
        transaction: TRANSACTION,
        mutation_id: 1,
        evidence: evidence("tree"),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
    };
    let error = wal
        .apply_permission_mutation(seal.clone(), || Err(io::Error::from_raw_os_error(5)))
        .unwrap_err();
    assert!(matches!(error, MutationAppendError::Mutation(_)));
    assert_eq!(
        wal.resolve_unresolved_permission(TRANSACTION, 1, |_| Ok(
            PermissionResolution::ConfirmedNotApplied
        ))
        .unwrap(),
        PermissionResolution::ConfirmedNotApplied
    );
    wal.transition(TRANSACTION, TransactionState::RestoreIntent)
        .unwrap();
    let inverse = PermissionIntent {
        transaction: TRANSACTION,
        mutation_id: 2,
        evidence: evidence_mode("tree", 0o770),
        pre_mode: 0o500,
        expected_mode: 0o770,
        reverses_mutation_id: Some(1),
    };
    let error = wal
        .apply_permission_mutation(inverse.clone(), || {
            panic!("a refused inverse must not mutate")
        })
        .unwrap_err();
    assert!(
        matches!(
            error,
            MutationAppendError::IntentWal(AppendError::InvalidState(
                "permission inverse does not match its applied seal mutation"
            ))
        ),
        "{error:?}"
    );

    // Replay refuses the same history, reading the seal back out of its frame.
    let bytes = framed(&[
        state(TRANSACTION, TransactionState::Prepared),
        state(TRANSACTION, TransactionState::ParentSealIntent),
        state(TRANSACTION, TransactionState::ParentSealed),
        state(TRANSACTION, TransactionState::TreeSealIntent),
        seal.into_record(),
        SealRecord::PermissionNotApplied {
            transaction: TRANSACTION,
            mutation_id: 1,
        },
        state(TRANSACTION, TransactionState::RestoreIntent),
        inverse.into_record(),
    ]);
    let error = replay_records(parse_frames(&bytes).unwrap().records, &bytes).unwrap_err();
    assert!(
        matches!(
            error,
            ReplayError::InvalidHistory(
                "permission inverse does not match its applied seal mutation"
            )
        ),
        "{error:?}"
    );
}

/// A durable intent whose mutation failed, which is the one state a resolution
/// is allowed to act on.
fn uncertain_intent() -> SealWal<FaultWriter> {
    let mut wal = SealWal::new(FaultWriter::default()).unwrap();
    wal.begin(TRANSACTION).unwrap();
    wal.transition(TRANSACTION, TransactionState::ParentSealIntent)
        .unwrap();
    let error = wal
        .apply_permission_mutation(
            PermissionIntent {
                transaction: TRANSACTION,
                mutation_id: 1,
                evidence: evidence("parent"),
                pre_mode: 0o770,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || Err(io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
    assert!(matches!(error, MutationAppendError::Mutation(_)));
    wal
}
