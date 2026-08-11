use super::*;
use crate::seal_store::SealWalStore;
use crate::seal_wal::DurableRenameOutcome;
use crate::sealed_staging::SealedStagingEngine;
use crate::staging_recovery::{
    RecoveryAnchors, RecoveryFilesystemAnchor, StagedVerificationOutcome, StartupRecoveryCapability,
};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _temp: tempfile::TempDir,
    base: std::path::PathBuf,
    source_parent: std::path::PathBuf,
    source_root: std::path::PathBuf,
    destination_parent: std::path::PathBuf,
    destination_root: std::path::PathBuf,
    store: SealWalStore,
    filesystem_id: String,
}

impl Fixture {
    fn new() -> Option<Self> {
        let temp = crate::secure_test_tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source_parent = base.join("source-parent");
        let source_root = source_parent.join("root");
        let destination_parent = base.join("destination-parent");
        let destination_root = destination_parent.join("staged");
        std::fs::create_dir(&source_parent).unwrap();
        std::fs::create_dir(&source_root).unwrap();
        std::fs::create_dir(source_root.join("child")).unwrap();
        std::fs::write(source_root.join("child/data"), b"sealed staging").unwrap();
        std::fs::create_dir(&destination_parent).unwrap();
        set_mode(&source_parent, 0o770);
        set_mode(&source_root, 0o770);
        set_mode(&source_root.join("child"), 0o770);
        set_mode(&destination_parent, 0o700);

        let source_fd: OwnedFd = std::fs::File::open(&source_parent).unwrap().into();
        let filesystem_id = match held_filesystem_id(&source_fd) {
            Ok(id) => id,
            Err(RecoveryRebindError::StrongIdentityUnavailable) => return None,
            Err(error) => panic!("filesystem id failed: {error}"),
        };
        match certify_held_fd(rustix::io::dup(&source_fd).unwrap()) {
            Ok(_) => {}
            Err(CertificationError::UnsupportedFilesystem) => return None,
            Err(error) => panic!("unexpected source certification failure: {error:?}"),
        }
        let store = SealWalStore::open_or_create(&base.join("wal-store")).unwrap();
        Some(Self {
            _temp: temp,
            base,
            source_parent,
            source_root,
            destination_parent,
            destination_root,
            store,
            filesystem_id,
        })
    }

    fn anchors(&self) -> RecoveryAnchors {
        RecoveryAnchors {
            source: RecoveryFilesystemAnchor::certify(
                std::fs::File::open(&self.base).unwrap().into(),
                self.filesystem_id.clone(),
            )
            .unwrap(),
            destination: RecoveryFilesystemAnchor::certify(
                std::fs::File::open(&self.base).unwrap().into(),
                self.filesystem_id.clone(),
            )
            .unwrap(),
        }
    }

    fn prepare(&self) -> PreparedRootBinding {
        let anchors = self.anchors();
        PreparedRootBinding::prepare(
            anchors.source,
            std::fs::File::open(&self.source_parent).unwrap().into(),
            StagingLocator::new(
                std::path::PathBuf::from("source-parent"),
                self.filesystem_id.clone(),
            )
            .unwrap(),
            OsString::from("root"),
            anchors.destination,
            std::fs::File::open(&self.destination_parent)
                .unwrap()
                .into(),
            StagingLocator::new(
                std::path::PathBuf::from("destination-parent"),
                self.filesystem_id.clone(),
            )
            .unwrap(),
            OsString::from("staged"),
        )
        .unwrap()
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn exact_held_tree_reaches_only_staged_unverified() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let transaction = TransactionId([0xa3; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.candidates.is_empty());

    let staged = engine.stage_prepared_root(transaction, binding).unwrap();
    assert_eq!(staged.transaction(), transaction);
    assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
    assert!(staged.startup_is_blocked());
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(
        std::fs::read(fixture.destination_root.join("child/data")).unwrap(),
        b"sealed staging"
    );
    assert_eq!(mode(&fixture.source_parent), 0o750);
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);
    drop(staged);
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::StagedUnverified)
    );
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let recovered = &replay.transactions[&transaction];
    assert_eq!(recovered.state, TransactionState::StagedUnverified);
    assert!(matches!(
        recovered.rename_outcome,
        Some(DurableRenameOutcome::AppliedAndParentsSynced(identity))
            if identity == recovered.staging.as_ref().unwrap().root_identity()
    ));
    assert_eq!(recovered.permissions.len(), 3);
    assert!(recovered.tree_manifest.is_some());
    drop(lease);

    let (mut recovered_engine, mut report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let capability = recovered_engine
        .prepare_startup_recovery(report.candidates.pop().unwrap(), fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("applied rename must require staged verification")
    };
    let outcome = pending.verify_or_quarantine().unwrap();
    let StagedVerificationOutcome::StagedSealed(verified) = outcome else {
        panic!("exact A3c2 output must satisfy the A3c1 verifier")
    };
    assert_eq!(verified.transaction(), transaction);
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
    assert!(verified.startup_is_blocked());
}

#[test]
fn occupied_destination_is_never_replaced() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    std::fs::create_dir(&fixture.destination_root).unwrap();
    std::fs::write(fixture.destination_root.join("sentinel"), b"keep").unwrap();
    let transaction = TransactionId([0xa4; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();

    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::Binding(
            PreparedRootError::DestinationOccupied
        ))
    ));
    assert!(fixture.source_root.is_dir());
    assert_eq!(
        std::fs::read(fixture.destination_root.join("sentinel")).unwrap(),
        b"keep"
    );
    assert_eq!(engine.state(transaction), None);
    assert_eq!(mode(&fixture.source_parent), 0o770);
}

#[test]
fn noreplace_race_is_durably_confirmed_without_moving_source() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let destination = fixture.destination_root.clone();
    BEFORE_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::create_dir(&destination).unwrap();
            std::fs::write(destination.join("sentinel"), b"keep").unwrap();
        }));
    });
    let transaction = TransactionId([0xa5; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();

    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::ConfirmedNotApplied(_))
    ));
    assert!(fixture.source_root.is_dir());
    assert_eq!(
        std::fs::read(fixture.destination_root.join("sentinel")).unwrap(),
        b"keep"
    );
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::RenameIntent)
    );
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert!(matches!(
        replay.transactions[&transaction].rename_outcome,
        Some(DurableRenameOutcome::ConfirmedNotAppliedAtSource(_))
    ));
}

#[test]
fn unsupported_noreplace_error_remains_unknown_without_fallback() {
    for (index, errno) in [
        libc::EINVAL,
        libc::ENOSYS,
        libc::EINTR,
        libc::EIO,
        libc::EXDEV,
    ]
    .into_iter()
    .enumerate()
    {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let binding = fixture.prepare();
        RENAME_ERROR.with(|error| error.set(Some(errno)));
        let transaction = TransactionId([0xb5 + index as u8; 16]);
        let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();

        assert!(matches!(
            engine.stage_prepared_root(transaction, binding),
            Err(StagingRenameError::RenameOutcomeUnknown(_))
        ));
        RENAME_ERROR.with(|error| error.set(None));
        assert!(fixture.source_root.is_dir());
        assert!(!fixture.destination_root.exists());
        assert_eq!(
            engine.state(transaction),
            Some(TransactionState::RenameIntent)
        );
        drop(engine);

        let mut lease = fixture.store.try_lease().unwrap();
        let replay = lease.replay_and_repair().unwrap();
        assert_eq!(replay.transactions[&transaction].rename_outcome, None);
    }
}

#[test]
fn parent_fsync_failure_publishes_no_applied_outcome_or_success_token() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    FAIL_PARENT_SYNC.with(|failure| failure.set(Some("destination")));
    let transaction = TransactionId([0xa6; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();

    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::ParentSync {
            which: "destination",
            ..
        })
    ));
    FAIL_PARENT_SYNC.with(|failure| failure.set(None));
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::RenameIntent)
    );
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
}

#[test]
fn source_parent_fsync_failure_publishes_no_applied_outcome() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    FAIL_PARENT_SYNC.with(|failure| failure.set(Some("source")));
    let transaction = TransactionId([0xaa; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();

    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::ParentSync {
            which: "source",
            ..
        })
    ));
    FAIL_PARENT_SYNC.with(|failure| failure.set(None));
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
}

#[test]
fn source_basename_replacement_before_rename_never_publishes_success() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let source = fixture.source_root.clone();
    let original = fixture.source_parent.join("original-root");
    BEFORE_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&source, &original).unwrap();
            std::fs::create_dir(&source).unwrap();
        }));
    });
    let transaction = TransactionId([0xba; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::AppliedButUnverified(_))
    ));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::RenameIntent)
    );
    drop(engine);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
}

#[test]
fn post_rename_binding_swap_publishes_no_outcome() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let destination = fixture.destination_root.clone();
    let diverted = fixture.destination_parent.join("diverted");
    AFTER_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&destination, &diverted).unwrap();
            std::fs::create_dir(&destination).unwrap();
        }));
    });
    let transaction = TransactionId([0xac; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::AppliedButUnverified(_))
    ));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::RenameIntent)
    );
    drop(engine);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
}

#[test]
fn applied_outcome_append_boundary_publishes_no_success() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    FAIL_WAL_STEP.with(|failure| failure.set(Some("applied-outcome")));
    let transaction = TransactionId([0xad; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::AppliedOutcomeNotDurable(_))
    ));
    FAIL_WAL_STEP.with(|failure| failure.set(None));
    assert!(fixture.destination_root.is_dir());
    drop(engine);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].rename_outcome, None);
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RenameIntent
    );
}

#[test]
fn staged_state_append_boundary_keeps_durable_applied_outcome() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    FAIL_WAL_STEP.with(|failure| failure.set(Some("staged-state")));
    let transaction = TransactionId([0xae; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::StagedStateNotDurable(_))
    ));
    FAIL_WAL_STEP.with(|failure| failure.set(None));
    assert!(fixture.destination_root.is_dir());
    drop(engine);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert!(matches!(
        replay.transactions[&transaction].rename_outcome,
        Some(DurableRenameOutcome::AppliedAndParentsSynced(_))
    ));
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RenameIntent
    );
    drop(lease);

    let (mut recovered_engine, mut report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let capability = recovered_engine
        .prepare_startup_recovery(report.candidates.pop().unwrap(), fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("durable applied rename outcome must normalize into verification")
    };
    assert_eq!(
        pending.wal_state(),
        Some(TransactionState::StagedUnverified)
    );
    let StagedVerificationOutcome::StagedSealed(verified) = pending.verify_or_quarantine().unwrap()
    else {
        panic!("exact recovered A3c2 tree must verify")
    };
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
    assert!(verified.startup_is_blocked());
}

#[test]
fn direct_executor_cannot_bypass_startup_block() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let mut wal = fixture.store.try_lease().unwrap().into_new_wal().unwrap();
    let mut startup_blocked = true;
    assert!(matches!(
        execute_prepared_rename(
            &mut wal,
            &mut startup_blocked,
            TransactionId([0xb1; 16]),
            binding,
        ),
        Err(StagingRenameError::StartupBlocked)
    ));
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
}

#[test]
fn startup_recovery_block_refuses_new_seals_and_rename() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let existing = TransactionId([0xa7; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
        engine
            .begin_transaction(existing, binding.metadata().clone())
            .unwrap();
    }
    let (mut blocked, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert!(matches!(
        blocked.stage_prepared_root(TransactionId([0xa8; 16]), binding),
        Err(StagingRenameError::StartupBlocked)
    ));
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
    assert_eq!(mode(&fixture.source_parent), 0o770);
}

#[test]
fn locator_paths_must_reopen_the_exact_held_parents() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    std::fs::create_dir(fixture.base.join("other-source")).unwrap();
    std::fs::create_dir(fixture.base.join("other-destination")).unwrap();
    let anchors = fixture.anchors();
    let error = PreparedRootBinding::prepare(
        anchors.source,
        std::fs::File::open(&fixture.source_parent).unwrap().into(),
        StagingLocator::new(
            std::path::PathBuf::from("other-source"),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        OsString::from("root"),
        anchors.destination,
        std::fs::File::open(&fixture.destination_parent)
            .unwrap()
            .into(),
        StagingLocator::new(
            std::path::PathBuf::from("other-destination"),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        OsString::from("staged"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PreparedRootError::Identity(RecoveryRebindError::BindingChanged)
    ));
    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.candidates.is_empty());
    drop(engine);
}

#[test]
fn retained_anchors_reject_locator_detachment_before_wal_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let detached = fixture.base.join("detached-source-parent");
    std::fs::rename(&fixture.source_parent, &detached).unwrap();
    std::fs::create_dir(&fixture.source_parent).unwrap();
    let transaction = TransactionId([0xb0; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(matches!(
        engine.stage_prepared_root(transaction, binding),
        Err(StagingRenameError::Binding(PreparedRootError::Identity(
            RecoveryRebindError::BindingChanged
        )))
    ));
    assert_eq!(engine.state(transaction), None);
    assert!(detached.join("root").is_dir());
}

#[test]
fn locator_controller_writers_are_rejected_before_wal_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    set_mode(&fixture.base, 0o770);
    let anchors = fixture.anchors();
    let error = PreparedRootBinding::prepare(
        anchors.source,
        std::fs::File::open(&fixture.source_parent).unwrap().into(),
        StagingLocator::new(
            std::path::PathBuf::from("source-parent"),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        OsString::from("root"),
        anchors.destination,
        std::fs::File::open(&fixture.destination_parent)
            .unwrap()
            .into(),
        StagingLocator::new(
            std::path::PathBuf::from("destination-parent"),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        OsString::from("staged"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PreparedRootError::Identity(RecoveryRebindError::LocatorControllerNotExclusive)
    ));
}

#[test]
fn preparation_rejects_foreign_writer_destination_before_wal_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    set_mode(&fixture.destination_parent, 0o770);
    let anchors = fixture.anchors();
    let error = PreparedRootBinding::prepare(
        anchors.source,
        std::fs::File::open(&fixture.source_parent).unwrap().into(),
        StagingLocator::new(
            std::path::PathBuf::from("source-parent"),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        OsString::from("root"),
        anchors.destination,
        std::fs::File::open(&fixture.destination_parent)
            .unwrap()
            .into(),
        StagingLocator::new(
            std::path::PathBuf::from("destination-parent"),
            fixture.filesystem_id,
        )
        .unwrap(),
        OsString::from("staged"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PreparedRootError::DestinationParentNotExclusive
    ));

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.candidates.is_empty());
    drop(engine);
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_noreplace_and_both_parent_fsync_contract_is_mandatory() {
    let fixture = Fixture::new().expect("macOS A3c2 tests require a certified APFS fixture");
    let binding = fixture.prepare();
    let transaction = TransactionId([0xab; 16]);
    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    let staged = engine.stage_prepared_root(transaction, binding).unwrap();
    assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
    assert!(fixture.destination_root.is_dir());
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}
