//! A full disk or quota while a check writes its private scratch. The check has
//! learned nothing about the tree, so nothing durable may say it did, and the
//! same check must pass once there is room.

use super::*;
use crate::seal::sidecar::{SCRATCH_MEMORY, ScratchFault, ScratchStep, arm_fault, disarm_fault};
use crate::staging::{ReadyStagingEngine, VerifiedPurgeError, VerifiedUndoError};

const FULL: [i32; 2] = [libc::ENOSPC, libc::EDQUOT];
const WRITES: [ScratchStep; 3] = [ScratchStep::Create, ScratchStep::Write, ScratchStep::Finish];
const ROOT: TransactionId = TransactionId([0xf1; 16]);

fn fault(step: ScratchStep, run: u32, errno: i32) -> ScratchFault {
    ScratchFault { step, run, errno }
}

fn reopen(fixture: &Fixture) -> ReadyStagingEngine {
    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    engine
        .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
        .unwrap()
        .0
}

fn scratch_left(fixture: &Fixture) -> usize {
    std::fs::read_dir(fixture.base.join("wal-store"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tree-scratch-v1-")
        })
        .count()
}

fn request_purge(
    ready: &mut ReadyStagingEngine,
    fixture: &Fixture,
) -> Result<(), VerifiedPurgeError> {
    ready
        .request_verified_purge(verified_purge_request(fixture, ROOT, "undo-group"))
        .map(drop)
}

fn run_undo(ready: &mut ReadyStagingEngine, fixture: &Fixture) -> Result<(), VerifiedUndoError> {
    let token = ready.verified_undo_token(ROOT, "undo-group").unwrap();
    ready
        .undo_verified(token, verified_undo_request(fixture))
        .map(drop)
}

fn finish_purge(ready: &mut ReadyStagingEngine, fixture: &Fixture, label: &str) {
    let authority = ready
        .request_verified_purge(verified_purge_request(fixture, ROOT, "undo-group"))
        .expect(label);
    ready.execute_verified_purge(authority).expect(label);
    assert_eq!(ready.state(ROOT), Some(TransactionState::Purged), "{label}");
    assert!(!fixture.destination_root.exists(), "{label}");
}

fn assert_restored(fixture: &Fixture, label: &str) {
    assert!(!fixture.destination_root.exists(), "{label}");
    assert_eq!(mode(&fixture.source_root), 0o770, "{label}");
    assert_eq!(mode(&fixture.source_root.join("child")), 0o770, "{label}");
    assert_eq!(
        std::fs::read(fixture.source_root.join("child/data")).unwrap(),
        b"sealed staging",
        "{label}"
    );
}

/// Walks every run the check starts. Each pass stages afresh, fails one run, and
/// asserts in `at_run`; it stops at the first run index the check never reaches.
fn each_run(
    budget: Option<usize>,
    step: ScratchStep,
    errno: i32,
    mut at_run: impl FnMut(Fixture, u32) -> bool,
) -> u32 {
    let mut run = 0;
    loop {
        let Some(fixture) = Fixture::new() else {
            return u32::MAX;
        };
        SCRATCH_MEMORY.with(|memory| memory.set(budget));
        let reached = at_run(fixture, run);
        SCRATCH_MEMORY.with(|memory| memory.set(None));
        assert!(!disarm_fault(), "a pass must consume or report its fault");
        if !reached {
            return run;
        }
        run += 1;
        assert!(run < 200, "{step:?} {errno}: the walk never ended");
    }
}

fn purge_pass(budget: Option<usize>, step: ScratchStep, errno: i32) -> u32 {
    each_run(budget, step, errno, |fixture, run| {
        let label = format!("purge {budget:?} {step:?} errno {errno} run {run}");
        SCRATCH_MEMORY.with(|memory| memory.set(None));
        let mut ready = stage_production(&fixture, ROOT);
        SCRATCH_MEMORY.with(|memory| memory.set(budget));
        arm_fault(fault(step, run, errno));
        let result =
            ready.request_verified_purge(verified_purge_request(&fixture, ROOT, "undo-group"));
        if disarm_fault() {
            result.expect(&label);
            return false;
        }
        let Err(error) = result else {
            panic!("{label}: the failed run must refuse");
        };
        assert_eq!(
            error.disposition(),
            VerifiedPurgeFailureDisposition::NotStarted,
            "{label}: {error}"
        );
        assert!(error.is_disk_full(), "{label}: {error}");
        assert_eq!(
            ready.state(ROOT),
            Some(TransactionState::VerifiedCommitted),
            "{label}"
        );
        assert!(
            fixture.destination_root.join("child/data").is_file(),
            "{label}"
        );

        // What matters is what a later process reads back.
        drop(ready);
        SCRATCH_MEMORY.with(|memory| memory.set(None));
        let mut ready = reopen(&fixture);
        assert_eq!(
            ready.state(ROOT),
            Some(TransactionState::VerifiedCommitted),
            "{label}"
        );
        assert_eq!(scratch_left(&fixture), 0, "{label}");
        finish_purge(&mut ready, &fixture, &label);
        true
    })
}

#[test]
fn purge_stays_committed() {
    // Manifest, hardlink, structure and purge-plan runs of one small tree.
    for errno in FULL {
        for step in WRITES {
            let runs = purge_pass(None, step, errno);
            if runs != u32::MAX {
                assert_eq!(runs, 4, "{step:?} {errno}");
            }
        }
    }
}

#[test]
fn purge_spill_stays() {
    // With almost no sort memory every record spills while its producer is still
    // running, which is the only way a large tree's structure walk can fail here.
    for errno in FULL {
        let runs = purge_pass(Some(1), ScratchStep::Create, errno);
        if runs != u32::MAX {
            assert!(runs > 8, "only {runs} runs with no sort memory");
        }
    }
}

#[test]
fn undo_retries_cleanly() {
    // The first check runs before anything has changed; the second after the
    // modes are restored. Neither may leave anything but a retry behind.
    for errno in FULL {
        let mut before_intent = 0;
        let mut after_modes = 0;
        let runs = each_run(None, ScratchStep::Create, errno, |fixture, run| {
            let label = format!("undo errno {errno} run {run}");
            let mut ready = stage_production(&fixture, ROOT);
            arm_fault(fault(ScratchStep::Create, run, errno));
            let result = run_undo(&mut ready, &fixture);
            if disarm_fault() {
                result.expect(&label);
                assert_restored(&fixture, &label);
                return false;
            }
            let error = result.expect_err(&label);
            assert!(error.is_disk_full(), "{label}: {error}");
            assert!(!fixture.source_root.exists(), "{label}");
            assert!(fixture.destination_root.is_dir(), "{label}");
            match error.disposition() {
                VerifiedUndoFailureDisposition::NotStarted => {
                    before_intent += 1;
                    assert_eq!(
                        ready.state(ROOT),
                        Some(TransactionState::VerifiedCommitted),
                        "{label}"
                    );
                    assert_eq!(mode(&fixture.destination_root), 0o750, "{label}");
                    drop(ready);
                    let mut ready = reopen(&fixture);
                    assert_eq!(
                        ready.state(ROOT),
                        Some(TransactionState::VerifiedCommitted),
                        "{label}"
                    );
                    run_undo(&mut ready, &fixture).expect(&label);
                }
                VerifiedUndoFailureDisposition::RecoveryBlocked => {
                    after_modes += 1;
                    assert_eq!(
                        ready.state(ROOT),
                        Some(TransactionState::UndoModesRestored),
                        "{label}"
                    );
                    drop(ready);
                    // Still no room when the next process starts: it waits again.
                    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
                    arm_fault(fault(ScratchStep::Create, 0, errno));
                    let waited = engine.recover_startup(report, |_, _| Ok(fixture.raw_anchors()));
                    assert!(waited.is_err(), "{label}");
                    assert!(!disarm_fault(), "{label}");
                    drop(waited);
                    let ready = reopen(&fixture);
                    assert_eq!(
                        ready.state(ROOT),
                        Some(TransactionState::Restored),
                        "{label}"
                    );
                }
                other => panic!("{label}: {other:?}"),
            }
            assert_restored(&fixture, &label);
            true
        });
        if runs != u32::MAX {
            assert_eq!(before_intent, 3, "manifest, hardlink, structure");
            assert_eq!(after_modes, 3, "manifest, hardlink, structure");
        }
    }
}

fn stage_awaiting(
    fixture: &Fixture,
    step: ScratchStep,
    run: u32,
    errno: i32,
) -> Option<(ReadyStagingEngine, ForwardFailureDisposition)> {
    set_mode(&fixture.source_parent, 0o700);
    let mut ready = fixture.ready_engine();
    let association = ProductionAssociation::new("undo-group".into()).unwrap();
    AFTER_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || arm_fault(fault(step, run, errno))));
    });
    let result = ready.stage_to_verified_commit(
        ROOT,
        fixture
            .forward_request("root", "staged")
            .with_production_association(association)
            .with_recovery_anchor(fixture.base.clone()),
    );
    if disarm_fault() {
        result.unwrap();
        return None;
    }
    Some((ready, result.err().unwrap().disposition()))
}

#[test]
fn staged_awaits_room() {
    // After the rename, no room to check must not quarantine: the entry would
    // stay in the trash for good, neither restorable nor purgeable.
    for errno in FULL {
        for step in WRITES {
            let runs = each_run(None, step, errno, |fixture, run| {
                let label = format!("staged {step:?} errno {errno} run {run}");
                let Some((ready, disposition)) = stage_awaiting(&fixture, step, run, errno) else {
                    return false;
                };
                assert_eq!(
                    disposition,
                    ForwardFailureDisposition::AwaitingRoom,
                    "{label}"
                );
                assert_eq!(
                    ready.state(ROOT),
                    Some(TransactionState::StagedUnverified),
                    "{label}"
                );
                assert!(!fixture.source_root.exists(), "{label}");
                assert!(fixture.destination_root.is_dir(), "{label}");
                drop(ready);

                let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
                arm_fault(fault(step, 0, errno));
                let waited = engine.recover_startup(report, |_, _| Ok(fixture.raw_anchors()));
                assert!(waited.is_err(), "{label}");
                assert!(!disarm_fault(), "{label}");
                drop(waited);

                let mut ready = reopen(&fixture);
                assert_eq!(
                    ready.state(ROOT),
                    Some(TransactionState::VerifiedCommitted),
                    "{label}"
                );
                assert_eq!(mode(&fixture.source_parent), 0o700, "{label}");
                run_undo(&mut ready, &fixture).expect(&label);
                assert_restored(&fixture, &label);
                true
            });
            if runs != u32::MAX {
                assert_eq!(runs, 3, "{step:?} {errno}");
            }
        }
    }
}

#[test]
fn parent_stays_writable() {
    // Waiting holds the source parent's seal, which keeps its owner's write and
    // search bits and only takes write from group and other. So a program of the
    // owner's can go on writing beside the staged entry, and doing so does not
    // stop the check from finishing later.
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let (ready, disposition) =
        stage_awaiting(&fixture, ScratchStep::Create, 0, libc::EDQUOT).unwrap();
    assert_eq!(disposition, ForwardFailureDisposition::AwaitingRoom);
    drop(ready);

    assert_eq!(mode(&fixture.source_parent) & 0o700, 0o700);
    std::fs::write(fixture.source_parent.join("sibling"), b"still writable").unwrap();
    std::fs::create_dir(&fixture.source_root).unwrap();
    std::fs::write(fixture.source_root.join("fresh"), b"a new cache").unwrap();

    let mut ready = reopen(&fixture);
    assert_eq!(ready.state(ROOT), Some(TransactionState::VerifiedCommitted));
    assert_eq!(mode(&fixture.source_parent), 0o700);
    finish_purge(&mut ready, &fixture, "entry");
    assert_eq!(
        std::fs::read(fixture.source_root.join("fresh")).unwrap(),
        b"a new cache"
    );
}

/// Changes the committed tree the way an outside writer or a damaged store could.
fn drift(fixture: &Fixture, kind: &str) {
    let child = fixture.destination_root.join("child");
    match kind {
        "content" => std::fs::write(child.join("data"), b"evil!! staging").unwrap(),
        "mode" => set_mode(&child, 0o700),
        "name" => {
            let sealed = mode(&child);
            set_mode(&child, 0o700);
            std::fs::rename(child.join("data"), child.join("renamed")).unwrap();
            set_mode(&child, sealed);
        }
        "hardlink" => {
            std::fs::hard_link(child.join("data"), fixture.base.join("alias")).unwrap();
        }
        "sidecar" => {
            let store = fixture.base.join("wal-store");
            let sidecar = std::fs::read_dir(&store)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sidecar")
                })
                .unwrap();
            let bytes = std::fs::read(&sidecar).unwrap();
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&sidecar)
                .unwrap();
            file.set_len(bytes.len() as u64 - 1).unwrap();
        }
        other => panic!("{other}"),
    }
}

const DRIFTS: [&str; 5] = ["content", "mode", "name", "hardlink", "sidecar"];

#[test]
fn purge_retry_rejects() {
    // A refusal for lack of room earns no trust: what changes while it waits is
    // caught by the retry, and nothing is deleted.
    for kind in DRIFTS {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let mut ready = stage_production(&fixture, ROOT);
        arm_fault(fault(ScratchStep::Create, 0, libc::EDQUOT));
        request_purge(&mut ready, &fixture).expect_err(kind);
        assert_eq!(
            ready.state(ROOT),
            Some(TransactionState::VerifiedCommitted),
            "{kind}"
        );
        drift(&fixture, kind);
        let error = request_purge(&mut ready, &fixture).expect_err(kind);
        assert!(!error.is_disk_full(), "{kind}");
        assert_eq!(
            ready.state(ROOT),
            Some(TransactionState::RecoveryRequired),
            "{kind}"
        );
        assert!(fixture.destination_root.is_dir(), "{kind}");
    }
}

#[test]
fn undo_retry_rejects() {
    for kind in DRIFTS {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let mut ready = stage_production(&fixture, ROOT);
        arm_fault(fault(ScratchStep::Create, 0, libc::EDQUOT));
        run_undo(&mut ready, &fixture).expect_err(kind);
        drift(&fixture, kind);
        let error = run_undo(&mut ready, &fixture).expect_err(kind);
        assert!(!error.is_disk_full(), "{kind}");
        assert!(!fixture.source_root.exists(), "{kind}");
        assert!(fixture.destination_root.is_dir(), "{kind}");
    }
}

#[test]
fn staged_retry_quarantines() {
    // The wait does not excuse the check: a tree that changed is quarantined when
    // the check finally runs, and the source parent still gets its mode back.
    for kind in ["content", "name", "hardlink"] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let (ready, disposition) =
            stage_awaiting(&fixture, ScratchStep::Create, 0, libc::ENOSPC).unwrap();
        assert_eq!(
            disposition,
            ForwardFailureDisposition::AwaitingRoom,
            "{kind}"
        );
        drop(ready);
        drift(&fixture, kind);
        let ready = reopen(&fixture);
        assert_eq!(
            ready.state(ROOT),
            Some(TransactionState::Quarantined),
            "{kind}"
        );
        assert!(fixture.destination_root.is_dir(), "{kind}");
    }
    // A changed directory mode stops the rebind before the check, as it does
    // after a crash at this point. Nothing commits and nothing moves.
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let (ready, _) = stage_awaiting(&fixture, ScratchStep::Create, 0, libc::ENOSPC).unwrap();
    drop(ready);
    drift(&fixture, "mode");
    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(
        engine
            .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
            .is_err()
    );
    assert!(fixture.destination_root.is_dir());
}

#[test]
fn removal_stays_committed() {
    // Removing the scratch when nothing is wrong: the check could not finish
    // tidying up, so the entry stays committed and the leftovers go at the next open.
    for errno in FULL {
        let runs = each_run(None, ScratchStep::Remove, errno, |fixture, run| {
            let label = format!("removal errno {errno} run {run}");
            let mut ready = stage_production(&fixture, ROOT);
            arm_fault(fault(ScratchStep::Remove, run, errno));
            let result = request_purge(&mut ready, &fixture);
            if disarm_fault() {
                result.expect(&label);
                return false;
            }
            let error = result.expect_err(&label);
            assert_eq!(
                error.disposition(),
                VerifiedPurgeFailureDisposition::NotStarted,
                "{label}: {error}"
            );
            drop(ready);
            let mut ready = reopen(&fixture);
            assert_eq!(scratch_left(&fixture), 0, "{label}");
            finish_purge(&mut ready, &fixture, &label);
            true
        });
        if runs != u32::MAX {
            assert!(runs >= 3, "only {runs} removals");
        }
    }
}

#[test]
fn tree_outranks_removal() {
    // A check that found a difference and then could not tidy up for lack of room
    // still reports the difference: otherwise purge would not record the block.
    for errno in FULL {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let mut ready = stage_production(&fixture, ROOT);
        drift(&fixture, "content");
        arm_fault(fault(ScratchStep::Remove, 0, errno));
        let error = request_purge(&mut ready, &fixture).unwrap_err();
        assert!(!disarm_fault(), "the removal must have failed");
        assert!(!error.is_disk_full(), "{error}");
        assert_eq!(
            error.disposition(),
            VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
        );
    }
}

#[test]
fn structure_outranks_removal() {
    // The same when the difference only shows in the structure comparison, whose
    // scratch is the third one removed.
    for errno in FULL {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let mut ready = stage_production(&fixture, ROOT);
        let child = fixture.destination_root.join("child");
        crate::staging::recovery::before_structure_walk(move || set_mode(&child, 0o700));
        arm_fault(fault(ScratchStep::Remove, 2, errno));
        let error = request_purge(&mut ready, &fixture).unwrap_err();
        assert!(!disarm_fault(), "the removal must have failed");
        assert!(!error.is_disk_full(), "{error}");
        assert_eq!(
            error.disposition(),
            VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
        );
    }
}

#[test]
fn damage_outranks_difference() {
    // A damaged scratch proves nothing about the tree, so it keeps priority over
    // a difference read from it, and an undo still records the block.
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = stage_production(&fixture, ROOT);
    let child = fixture.destination_root.join("child");
    crate::staging::recovery::before_structure_walk(move || set_mode(&child, 0o700));
    arm_fault(fault(ScratchStep::Corrupt, 2, 0));
    let error = run_undo(&mut ready, &fixture).unwrap_err();
    assert!(!disarm_fault(), "the run must have been damaged");
    assert!(!error.is_disk_full(), "{error}");
    assert_eq!(ready.state(ROOT), Some(TransactionState::RecoveryRequired));
    assert!(fixture.destination_root.is_dir());
}

#[test]
fn other_errors_unchanged() {
    // The exemption is for a full disk alone: every other errno keeps the outcome
    // each path gave it before.
    let eio = libc::EIO;
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = stage_production(&fixture, ROOT);
    arm_fault(fault(ScratchStep::Create, 0, eio));
    let error = request_purge(&mut ready, &fixture).unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired),
        "a purge check's I/O failure is recorded"
    );

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = stage_production(&fixture, ROOT);
    arm_fault(fault(ScratchStep::Create, 3, eio));
    let error = request_purge(&mut ready, &fixture).unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted,
        "a purge plan's failure has always been retryable"
    );
    assert_eq!(ready.state(ROOT), Some(TransactionState::VerifiedCommitted));
    finish_purge(&mut ready, &fixture, "plan");

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = stage_production(&fixture, ROOT);
    arm_fault(fault(ScratchStep::Create, 0, eio));
    run_undo(&mut ready, &fixture).unwrap_err();
    assert_eq!(
        ready.state(ROOT),
        Some(TransactionState::RecoveryRequired),
        "an undo check's sidecar failure is recorded"
    );

    // A spill during the structure walk read as the tree having changed, which an
    // undo does not record.
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = stage_production(&fixture, ROOT);
    SCRATCH_MEMORY.with(|memory| memory.set(Some(1)));
    // Runs 0 to 4 are the manifest's and the hardlinks'; 5 spills the structure.
    arm_fault(fault(ScratchStep::Create, 5, eio));
    let error = run_undo(&mut ready, &fixture).unwrap_err();
    SCRATCH_MEMORY.with(|memory| memory.set(None));
    assert!(!disarm_fault(), "the spill must have failed");
    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::NotStarted,
        "{error}"
    );
    assert_eq!(ready.state(ROOT), Some(TransactionState::VerifiedCommitted));

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let (ready, disposition) = stage_awaiting(&fixture, ScratchStep::Create, 0, eio).unwrap();
    assert_eq!(
        disposition,
        ForwardFailureDisposition::Terminal(TransactionState::Quarantined),
        "a staged check's other failures still quarantine"
    );
    assert_eq!(ready.state(ROOT), Some(TransactionState::Quarantined));
}
