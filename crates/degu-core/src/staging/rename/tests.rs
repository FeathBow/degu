use super::*;
use crate::seal::store::SealWalStore;
use crate::seal::wal::{DurableRenameOutcome, ProductionAssociation};
use crate::staging::recovery::{
    RecoveryAnchors, RecoveryFilesystemAnchor, StagedVerificationFailure,
    StagedVerificationOutcome, StartupRecoveryCapability, install_recovery_fd_observer,
};
use crate::staging::{
    ForwardFailureDisposition, SealedStagingEngine, StartupRecoveryAnchors,
    VerifiedPurgeFailureDisposition, VerifiedPurgeRequest, VerifiedUndoFailureDisposition,
    VerifiedUndoRequest,
};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

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

    fn raw_anchors(&self) -> StartupRecoveryAnchors {
        StartupRecoveryAnchors::new(
            std::fs::File::open(&self.base).unwrap().into(),
            std::fs::File::open(&self.base).unwrap().into(),
        )
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

    fn forward_request(
        &self,
        source_basename: &str,
        destination_basename: &str,
    ) -> crate::staging::ForwardStagingRequest {
        crate::staging::ForwardStagingRequest::new(
            std::fs::File::open(&self.base).unwrap().into(),
            std::fs::File::open(&self.source_parent).unwrap().into(),
            StagingLocator::new(
                std::path::PathBuf::from("source-parent"),
                self.filesystem_id.clone(),
            )
            .unwrap(),
            OsString::from(source_basename),
            std::fs::File::open(&self.base).unwrap().into(),
            std::fs::File::open(&self.destination_parent)
                .unwrap()
                .into(),
            StagingLocator::new(
                std::path::PathBuf::from("destination-parent"),
                self.filesystem_id.clone(),
            )
            .unwrap(),
            OsString::from(destination_basename),
        )
    }

    fn ready_engine(&self) -> crate::staging::ReadyStagingEngine {
        let (engine, report) = SealedStagingEngine::open(&self.store).unwrap();
        assert!(report.is_empty());
        engine
            .recover_startup(report, |_, _| {
                Err(std::io::Error::other(
                    "empty startup report must not request anchors",
                ))
            })
            .unwrap()
            .0
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn assert_only_parent_seal_is_durable(fixture: &Fixture, transaction: TransactionId) {
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let recovered = &replay.transactions[&transaction];
    assert_eq!(recovered.permissions.len(), 1);
    assert_eq!(recovered.permissions[0].mutation_id, 0);
    assert_eq!(
        recovered.permissions[0].evidence.relative_path(),
        Path::new("source-parent")
    );
    assert_eq!(mode(&fixture.source_parent), 0o750);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn supplementary_group_other_than(current: u32) -> Option<u32> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return None;
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    (filled == count)
        .then_some(groups)
        .into_iter()
        .flatten()
        .find(|group| *group != current)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_group(path: &Path, gid: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let directory = std::fs::File::open(path)?;
    let result =
        unsafe { libc::fchown(directory.as_raw_fd(), !0 as libc::uid_t, gid as libc::gid_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn anonymous_directory_plan_preserves_reverse_bfs_wal_modes_and_restart_verification() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let grandchild = fixture.source_root.join("child/grandchild");
    std::fs::create_dir(&grandchild).unwrap();
    set_mode(&fixture.source_root, 0o770);
    set_mode(&fixture.source_root.join("child"), 0o700);
    set_mode(&grandchild, 0o777);

    let transaction = TransactionId([0x72; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    drop(
        engine
            .stage_prepared_root(transaction, fixture.prepare())
            .unwrap(),
    );
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let permissions = &replay.transactions[&transaction].permissions;
    assert_eq!(permissions.len(), 4);
    assert_eq!(
        permissions
            .iter()
            .map(|permission| (
                permission.mutation_id,
                permission.evidence.relative_path().to_path_buf(),
                permission.pre_mode,
                permission.expected_mode,
            ))
            .collect::<Vec<_>>(),
        vec![
            (0, PathBuf::from("source-parent"), 0o770, 0o750),
            (
                1,
                PathBuf::from("source-parent/root/child/grandchild"),
                0o777,
                0o755,
            ),
            (2, PathBuf::from("source-parent/root/child"), 0o700, 0o700,),
            (3, PathBuf::from("source-parent/root"), 0o770, 0o750,),
        ]
    );
    drop(lease);

    let (mut recovered, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let candidate = report.into_candidates().pop().unwrap();
    let capability = recovered
        .prepare_startup_recovery(candidate, fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("staged plan did not resume verification")
    };
    let StagedVerificationOutcome::StagedSealed(verified) = pending.verify_or_quarantine().unwrap()
    else {
        panic!("varied-mode tree failed exact restart verification")
    };
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
}

#[test]
fn component_order_prefix_paths_stage_and_restart_verify() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    for name in ["!", "!!", "!!!"] {
        std::fs::create_dir(fixture.source_root.join(name)).unwrap();
        std::fs::write(fixture.source_root.join(name).join("leaf"), name.as_bytes()).unwrap();
    }
    let transaction = TransactionId([0xdc; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let staged = engine
        .stage_prepared_root(transaction, fixture.prepare())
        .unwrap();
    assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
    drop(staged);
    drop(engine);

    let (mut recovered, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let candidate = report
        .into_candidates()
        .into_iter()
        .find(|candidate| candidate.transaction() == transaction)
        .unwrap();
    let capability = recovered
        .prepare_startup_recovery(candidate, fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("component-order prefix paths did not resume exact verification")
    };
    let StagedVerificationOutcome::StagedSealed(verified) = pending.verify_or_quarantine().unwrap()
    else {
        panic!("component-order prefix paths did not verify after restart")
    };
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
}

#[test]
fn internal_pair_cross_directory_and_three_aliases_fingerprint_and_restart_verify() {
    for (case, aliases) in [(0_u8, 2_u64), (1, 2), (2, 3)] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let original = fixture.source_root.join("child/data");
        match case {
            0 => std::fs::hard_link(&original, fixture.source_root.join("child/alias")).unwrap(),
            1 => std::fs::hard_link(&original, fixture.source_root.join("cross-alias")).unwrap(),
            2 => {
                std::fs::hard_link(&original, fixture.source_root.join("child/alias-one")).unwrap();
                std::fs::hard_link(&original, fixture.source_root.join("alias-two")).unwrap();
            }
            _ => unreachable!(),
        }
        let binding = fixture.prepare();
        let transaction = TransactionId([0xc0 + case; 16]);
        let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert!(report.is_empty());
        let staged = engine.stage_prepared_root(transaction, binding).unwrap();
        assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
        drop(staged);
        drop(engine);

        let mut lease = fixture.store.try_lease().unwrap();
        let replay = lease.replay_and_repair().unwrap();
        let manifest = replay.transactions[&transaction].tree_manifest.unwrap();
        assert!(manifest.has_content_proof());
        assert_ne!(manifest.sha256, [0; 32]);
        assert_eq!(
            std::fs::metadata(fixture.destination_root.join("child/data"))
                .unwrap()
                .nlink(),
            aliases
        );
        drop(lease);

        let (mut recovered, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        let candidate = report.into_candidates().pop().unwrap();
        let capability = recovered
            .prepare_startup_recovery(candidate, fixture.anchors())
            .unwrap();
        let StartupRecoveryCapability::PendingVerification(pending) = capability else {
            panic!("internal alias case {case} did not resume exact verification")
        };
        let StagedVerificationOutcome::StagedSealed(verified) =
            pending.verify_or_quarantine().unwrap()
        else {
            panic!("internal alias case {case} did not verify after restart")
        };
        assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
    }
}

#[test]
fn exact_held_tree_reaches_only_staged_unverified() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let binding = fixture.prepare();
    let transaction = TransactionId([0xa3; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());

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
    assert!(
        std::fs::read_dir(fixture.base.join("wal-store"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tree-scratch-v1-")),
        "successful forward staging must clean both structure scratch passes"
    );
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
    assert_eq!(
        recovered
            .permissions
            .iter()
            .map(|permission| permission.mutation_id)
            .collect::<Vec<_>>(),
        vec![0, 1, 2],
        "source parent remains mutation 0, then reverse-BFS child and root"
    );
    assert_eq!(
        recovered.permissions[1].evidence.relative_path(),
        Path::new("source-parent/root/child")
    );
    assert_eq!(
        recovered.permissions[2].evidence.relative_path(),
        Path::new("source-parent/root")
    );
    let manifest = recovered.tree_manifest.unwrap();
    let commitment = recovered
        .tree_sidecar
        .expect("v12 staging must durably bind its published sidecar");
    assert_eq!(commitment.transaction(), transaction);
    assert_eq!(commitment.record_count(), manifest.entry_count);
    fixture
        .store
        .tree_sidecar_store()
        .unwrap()
        .verify(commitment)
        .unwrap();
    drop(lease);

    let (mut recovered_engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    fixture
        .store
        .tree_sidecar_store()
        .unwrap()
        .verify(commitment)
        .expect("an active WAL reference must remain reachable across startup");
    let candidate = report.into_candidates().pop().unwrap();
    let capability = recovered_engine
        .prepare_startup_recovery(candidate, fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("applied rename must require staged verification")
    };
    let outcome = pending.verify_or_quarantine().unwrap();
    let StagedVerificationOutcome::StagedSealed(verified) = outcome else {
        panic!("exact sealed-rename output must satisfy the staged-tree verifier")
    };
    assert_eq!(verified.transaction(), transaction);
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
    assert!(verified.startup_is_blocked());
}

#[test]
fn unreferenced_final_sidecar_is_preserved_until_replay_then_collected() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xd7; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    FAIL_WAL_STEP.with(|failure| failure.set(Some("manifest-reference")));
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("poisoned manifest reference must not report staged success"),
        Err(error) => error,
    };
    FAIL_WAL_STEP.with(|failure| failure.set(None));
    assert!(matches!(
        error,
        StagingRenameError::Wal(AppendError::Poisoned)
    ));
    drop(engine);

    let final_sidecars = std::fs::read_dir(fixture.base.join("wal-store"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() == Some(OsStr::new("sidecar")))
        .collect::<Vec<_>>();
    assert_eq!(final_sidecars.len(), 1);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let replayed = &replay.transactions[&transaction];
    assert_eq!(replayed.state, TransactionState::TreeSealIntent);
    assert!(replayed.tree_manifest.is_none());
    assert!(replayed.tree_sidecar.is_none());
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
    drop(lease);

    let (reopened, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert!(
        std::fs::read_dir(fixture.base.join("wal-store"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .all(|path| path.extension() != Some(OsStr::new("sidecar"))),
        "replay-proven publication orphan must be removed and directory-synced"
    );
    drop(reopened);
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol loss of durable evidence
fn missing_wal_referenced_sidecar_is_durably_recovery_required_on_open() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xd8; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let staged = engine
        .stage_prepared_root(transaction, fixture.prepare())
        .unwrap();
    assert_eq!(staged.wal_state(), Some(TransactionState::StagedUnverified));
    drop(staged);
    drop(engine);

    let store_path = fixture.base.join("wal-store");
    let sidecar_path = std::fs::read_dir(&store_path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("sidecar")))
        .expect("forward staging must publish one final sidecar");
    std::fs::remove_file(&sidecar_path).unwrap();

    let (reopened, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(
        reopened.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    drop(reopened);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RecoveryRequired
    );
}

#[test]
fn consumed_pre_seal_expectation_rejects_same_size_content_drift_before_post_proof() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let data = fixture.source_root.join("child/data");
    AFTER_PRE_SEAL_INVENTORY_DROPPED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::write(data, b"evil!! staging").unwrap();
        }));
    });
    let transaction = TransactionId([0xd9; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());

    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("post-seal content drift must not reach rename"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StagingRenameError::HeldTree(HeldTreeError::PostChanged(path)) if path.as_os_str().is_empty()
    ));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::TreeSealIntent)
    );
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert!(replay.transactions[&transaction].tree_manifest.is_none());
    assert!(replay.transactions[&transaction].tree_sidecar.is_none());
}

#[test]
fn corrupted_anonymous_directory_plan_mutates_no_tree_directory() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x73; 16]);
    AFTER_PRE_SEAL_DIRECTORY_PLAN_PREFLIGHT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|plan| plan.corrupt_frame_for_test(1)));
    });
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("corrupt directory plan must fail before tree sealing"),
        Err(error) => error,
    };
    assert!(matches!(error, StagingRenameError::Sidecar(_)));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::TreeSealIntent)
    );
    assert_eq!(mode(&fixture.source_parent), 0o750);
    assert_eq!(mode(&fixture.source_root), 0o770);
    assert_eq!(mode(&fixture.source_root.join("child")), 0o770);
    assert!(fixture.source_root.join("child/data").is_file());
    assert!(!fixture.destination_root.exists());
    assert!(
        std::fs::read_dir(fixture.base.join("wal-store"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| !name.to_string_lossy().starts_with(".tree-scratch-v1-"))
    );
    drop(engine);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let recovered = &replay.transactions[&transaction];
    assert_eq!(recovered.permissions.len(), 1);
    assert!(recovered.tree_manifest.is_none());
    assert!(recovered.tree_sidecar.is_none());
    drop(lease);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let (ready, summary) = engine
        .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
        .unwrap();
    assert_eq!(summary.recovered.len(), 1);
    assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
    assert_eq!(mode(&fixture.source_parent), 0o770);
}

#[test]
fn pre_seal_scratch_crash_boundaries_cleanup_and_restore_exact_wal_prefix() {
    for (index, (boundary, expected_state, expected_permissions)) in [
        ("scratch-ready", TransactionState::ParentSealed, 1_usize),
        (
            "directories-sealed",
            TransactionState::TreeSealIntent,
            3_usize,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId([0x74 + index as u8; 16]);
        let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert!(report.is_empty());
        match boundary {
            "scratch-ready" => AFTER_PRE_SEAL_SCRATCH_READY.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(|| panic!("simulated pre-seal crash")));
            }),
            "directories-sealed" => AFTER_PRE_SEAL_DIRECTORY_SEALS.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(|| panic!("simulated pre-seal crash")));
            }),
            _ => unreachable!(),
        }

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = engine.stage_prepared_root(transaction, fixture.prepare());
        }));
        assert!(crashed.is_err(), "boundary={boundary}");
        assert_eq!(engine.state(transaction), Some(expected_state));
        assert!(
            std::fs::read_dir(fixture.base.join("wal-store"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .any(|name| name.to_string_lossy().starts_with(".tree-scratch-v1-")),
            "the simulated process death must strand unpublished scratch at {boundary}"
        );
        drop(engine);

        let mut lease = fixture.store.try_lease().unwrap();
        let replay = lease.replay_and_repair().unwrap();
        let recovered = &replay.transactions[&transaction];
        assert_eq!(recovered.state, expected_state);
        assert_eq!(recovered.permissions.len(), expected_permissions);
        assert!(recovered.tree_manifest.is_none());
        assert!(recovered.tree_sidecar.is_none());
        drop(lease);

        let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert_eq!(report.candidates().len(), 1);
        assert!(
            std::fs::read_dir(fixture.base.join("wal-store"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .all(|name| !name.to_string_lossy().starts_with(".tree-scratch-v1-")),
            "startup must remove unpublished pre-seal scratch at {boundary}"
        );
        let (ready, summary) = engine
            .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
            .unwrap();
        assert_eq!(summary.recovered.len(), 1);
        assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
        assert_eq!(mode(&fixture.source_parent), 0o770);
        assert_eq!(mode(&fixture.source_root), 0o770);
        assert_eq!(mode(&fixture.source_root.join("child")), 0o770);
        assert!(fixture.source_root.join("child/data").is_file());
        assert!(!fixture.destination_root.exists());
    }
}

#[test]
fn streamed_structure_scratch_reports_the_first_canonical_added_path() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let extra = fixture.source_root.join("extra");
    AFTER_STRUCTURE_SIDECAR_PREFLIGHT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::write(extra, b"late").unwrap();
        }));
    });
    let transaction = TransactionId([0xda; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());

    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("late added path must not reach rename"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StagingRenameError::HeldTree(HeldTreeError::PostAdded(path))
            if path == Path::new("extra")
    ));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::TreeSealIntent)
    );
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
}

#[test]
#[allow(clippy::disallowed_methods)]
fn sidecar_integrity_wins_over_concurrent_structure_traversal_failure() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let store = fixture.base.join("wal-store");
    let child = fixture.source_root.join("child");
    AFTER_STRUCTURE_SIDECAR_PREFLIGHT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let sidecar = std::fs::read_dir(store)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension() == Some(OsStr::new("sidecar")))
                .expect("published sidecar must exist before structure traversal");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(sidecar)
                .unwrap();
            file.set_len(file.metadata().unwrap().len() - 1).unwrap();
            std::fs::remove_file(child.join("data")).unwrap();
            std::fs::remove_dir(&child).unwrap();
        }));
    });
    let transaction = TransactionId([0xdb; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());

    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("corrupt sidecar and failed traversal must not reach rename"),
        Err(error) => error,
    };
    assert!(matches!(error, StagingRenameError::Sidecar(_)));
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::TreeSealIntent)
    );
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
}

#[test]
fn transient_seal_race_fails_identity_before_fchmod_and_keeps_parent_anchor_stable() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let source_parent_identity = std::fs::metadata(&fixture.source_parent).unwrap();
    let child = fixture.source_root.join("child");
    let displaced = fixture.source_root.join("displaced-child");
    let replacement = child.clone();
    crate::backend::held::install_transient_seal_test_hook(move |path| {
        assert_eq!(path, Path::new("child"));
        std::fs::rename(&child, &displaced).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        set_mode(&replacement, 0o700);
    });

    let transaction = TransactionId([0xb7; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("identity replacement must fail before transient fchmod"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StagingRenameError::TreeSeal(HeldTreeSealError::Tree(
            HeldTreeError::IdentityChanged(ref path)
        )) if path == Path::new("child")
    ));
    assert_eq!(mode(&fixture.source_root.join("displaced-child")), 0o770);
    assert_eq!(mode(&fixture.source_root.join("child")), 0o700);
    let after_parent = std::fs::metadata(&fixture.source_parent).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(source_parent_identity.dev(), after_parent.dev());
    assert_eq!(source_parent_identity.ino(), after_parent.ino());

    drop(engine);
    assert_only_parent_seal_is_durable(&fixture, transaction);
}

#[test]
fn transient_seal_mode_drift_fails_before_child_intent_or_fchmod() {
    use std::cell::Cell;
    use std::rc::Rc;

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let child = fixture.source_root.join("child");
    let fired = Rc::new(Cell::new(false));
    let hook_fired = Rc::clone(&fired);
    crate::backend::held::install_transient_seal_test_hook(move |path| {
        assert_eq!(path, Path::new("child"));
        assert!(!hook_fired.replace(true), "transient hook fired twice");
        set_mode(&child, 0o700);
    });

    let transaction = TransactionId([0xb8; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("mode drift must fail before transient fchmod"),
        Err(error) => error,
    };
    assert!(fired.get(), "transient seal race hook did not fire");
    assert!(matches!(
        error,
        StagingRenameError::TreeSeal(HeldTreeSealError::Tree(
            HeldTreeError::IdentityChanged(ref path)
        )) if path == Path::new("child")
    ));
    assert_eq!(mode(&fixture.source_root.join("child")), 0o700);

    drop(engine);
    assert_only_parent_seal_is_durable(&fixture, transaction);
}

#[test]
fn transient_seal_rejects_drift_to_same_minimal_target_as_old_mode() {
    use std::cell::Cell;
    use std::rc::Rc;

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let child = fixture.source_root.join("child");
    let fired = Rc::new(Cell::new(false));
    let hook_fired = Rc::clone(&fired);
    crate::backend::held::install_transient_seal_test_hook(move |path| {
        assert_eq!(path, Path::new("child"));
        assert!(!hook_fired.replace(true), "transient hook fired twice");
        // 0770 seals to 0750. Planting 0750 proves the executor must not
        // accept a new pre_mode merely because its target would be identical.
        set_mode(&child, 0o750);
    });

    let transaction = TransactionId([0xb9; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("same-target pre-mode drift must fail before transient fchmod"),
        Err(error) => error,
    };
    assert!(fired.get(), "transient seal race hook did not fire");
    assert!(matches!(
        error,
        StagingRenameError::TreeSeal(HeldTreeSealError::Tree(
            HeldTreeError::IdentityChanged(ref path)
        )) if path == Path::new("child")
    ));
    assert_eq!(mode(&fixture.source_root.join("child")), 0o750);

    drop(engine);
    assert_only_parent_seal_is_durable(&fixture, transaction);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn transient_seal_group_drift_fails_before_child_intent_or_fchmod_when_permitted() {
    use std::cell::Cell;
    use std::os::unix::fs::MetadataExt;
    use std::rc::Rc;

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let child = fixture.source_root.join("child");
    let collected_gid = std::fs::metadata(&child).unwrap().gid();
    let Some(alternate_gid) = supplementary_group_other_than(collected_gid) else {
        eprintln!(
            "group-drift fixture skipped: process has no supplementary group distinct from gid {collected_gid}"
        );
        return;
    };
    let probe = tempfile::tempdir_in(&fixture.base).unwrap();
    if let Err(error) = set_group(probe.path(), alternate_gid) {
        eprintln!(
            "group-drift fixture skipped: platform refused fchown to supplementary gid {alternate_gid}: {error}"
        );
        return;
    }
    drop(probe);

    let fired = Rc::new(Cell::new(false));
    let hook_fired = Rc::clone(&fired);
    crate::backend::held::install_transient_seal_test_hook(move |path| {
        assert_eq!(path, Path::new("child"));
        assert!(!hook_fired.replace(true), "transient hook fired twice");
        set_group(&child, alternate_gid).unwrap();
    });

    let transaction = TransactionId([0xba; 16]);
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let error = match engine.stage_prepared_root(transaction, fixture.prepare()) {
        Ok(_) => panic!("gid drift must fail before transient fchmod"),
        Err(error) => error,
    };
    assert!(fired.get(), "transient seal race hook did not fire");
    assert!(matches!(
        error,
        StagingRenameError::TreeSeal(HeldTreeSealError::Tree(
            HeldTreeError::IdentityChanged(ref path)
        )) if path == Path::new("child")
    ));
    assert_eq!(
        std::fs::metadata(fixture.source_root.join("child"))
            .unwrap()
            .gid(),
        alternate_gid
    );

    drop(engine);
    assert_only_parent_seal_is_durable(&fixture, transaction);
}

#[test]
fn verified_commit_hashes_each_payload_three_times() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let payload_bytes = std::fs::metadata(fixture.source_root.join("child/data"))
        .unwrap()
        .len();
    crate::backend::held::reset_regular_content_bytes_read();
    let transaction = TransactionId([0xc7; 16]);
    let mut ready = fixture.ready_engine();

    ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap();

    assert_eq!(
        crate::backend::held::regular_content_bytes_read(),
        payload_bytes * 3,
        "pre-seal, post-seal, and staged verification are the only full payload proofs"
    );
}

#[test]
fn forward_coordinator_reaches_verified_commit_before_returning() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc8; 16]);
    let mut ready = fixture.ready_engine();

    let committed = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap();

    assert_eq!(committed.transaction(), transaction);
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(mode(&fixture.source_parent), 0o770);
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);
}

fn stage_production(
    fixture: &Fixture,
    transaction: TransactionId,
) -> crate::staging::ReadyStagingEngine {
    set_mode(&fixture.source_parent, 0o700);
    let mut ready = fixture.ready_engine();
    let association = crate::seal::wal::ProductionAssociation::new("undo-group".into()).unwrap();
    ready
        .stage_to_verified_commit(
            transaction,
            fixture
                .forward_request("root", "staged")
                .with_production_association(association)
                .with_recovery_anchor(fixture.base.clone()),
        )
        .unwrap();
    ready
}

fn verified_undo_request(fixture: &Fixture) -> VerifiedUndoRequest {
    VerifiedUndoRequest::new(
        std::fs::File::open(&fixture.base).unwrap().into(),
        std::fs::File::open(&fixture.base).unwrap().into(),
    )
}

fn verified_purge_request(
    fixture: &Fixture,
    transaction: TransactionId,
    reclamation_id: &str,
) -> VerifiedPurgeRequest {
    VerifiedPurgeRequest::new(
        transaction,
        reclamation_id.to_owned(),
        std::fs::File::open(&fixture.base).unwrap().into(),
        std::fs::File::open(&fixture.base).unwrap().into(),
    )
}

#[test]
fn recovery_blocked_engine_refuses_later_purge_admission() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x90; 16]);
    let mut ready = stage_production(&fixture, transaction);
    // Force exact-object drift so the first request durably blocks recovery.
    std::fs::write(fixture.destination_root.join("late-drift"), b"drift").unwrap();
    let first = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert!(matches!(
        first.disposition(),
        VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
            | VerifiedPurgeFailureDisposition::RecoveryBlocked
    ));

    let later = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert_eq!(
        later.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(later.stage(), "ready-engine admission");
}

#[test]
#[allow(clippy::disallowed_methods)] // adversarially corrupts the published proof
fn verified_purge_corrupt_sidecar_fails_closed_before_authority() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x8d; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let store = fixture.base.join("wal-store");
    let sidecar = std::fs::read_dir(&store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("sidecar")))
        .expect("verified commit must retain its sidecar");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(sidecar)
        .unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();

    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(fixture.destination_root.is_dir());
    assert!(
        std::fs::read_dir(store)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| !name.to_string_lossy().starts_with(".tree-scratch-v1-"))
    );
}

#[test]
fn purge_plan_construction_failure_is_retryable_before_authorization() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x8b; 16]);
    let mut ready = stage_production(&fixture, transaction);
    crate::staging::recovery::PURGE_PLAN_FAIL_BUILD.with(|fail| fail.set(true));
    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    crate::staging::recovery::PURGE_PLAN_FAIL_BUILD.with(|fail| fail.set(false));
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(fixture.destination_root.join("child/data").is_file());

    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    ready.execute_verified_purge(authority).unwrap();
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
}

#[test]
fn purge_plan_failure_after_scratch_build_cleans_and_remains_retryable() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x87; 16]);
    let mut ready = stage_production(&fixture, transaction);
    crate::staging::recovery::PURGE_PLAN_FAIL_AFTER_SCRATCH_BUILD.with(|fail| fail.set(true));
    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    crate::staging::recovery::PURGE_PLAN_FAIL_AFTER_SCRATCH_BUILD.with(|fail| fail.set(false));
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(
        std::fs::read_dir(fixture.base.join("wal-store"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| !name.to_string_lossy().starts_with(".tree-scratch-v1-"))
    );
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    ready.execute_verified_purge(authority).unwrap();
}

#[test]
fn keyed_purge_plan_tamper_after_preflight_unlinks_nothing() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x8c; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::staging::recovery::AFTER_PURGE_PLAN_AUTH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|plan| plan.corrupt_frame_for_test(0)));
    });
    let error = ready.execute_verified_purge(authority).unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(fixture.destination_root.join("child/data").is_file());
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 0);
}

#[test]
fn later_keyed_purge_plan_tamper_preserves_canonical_progress_prefix() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x89; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::staging::recovery::AFTER_PURGE_PLAN_AUTH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|plan| plan.corrupt_frame_for_test(1)));
    });
    let error = ready.execute_verified_purge(authority).unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(!fixture.destination_root.join("child/data").exists());
    assert!(fixture.destination_root.join("child").is_dir());
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 1);
    assert_eq!(
        replay.transactions[&transaction].purge_last_path.as_deref(),
        Some(Path::new("child/data"))
    );
}

#[test]
fn live_replacement_after_plan_preflight_is_never_unlinked() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0x8a; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    let data = fixture.destination_root.join("child/data");
    let changed = data.clone();
    crate::staging::recovery::AFTER_PURGE_PLAN_AUTH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_| {
            std::fs::write(&changed, b"replacement after preflight").unwrap();
        }));
    });
    let error = ready.execute_verified_purge(authority).unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert_eq!(std::fs::read(data).unwrap(), b"replacement after preflight");
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 0);
}

#[test]
#[allow(clippy::disallowed_methods)] // constructs a root-only adversarial fixture
fn streamed_v3_purge_handles_root_only_tree_without_named_plan_residue() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    std::fs::remove_file(fixture.source_root.join("child/data")).unwrap();
    std::fs::remove_dir(fixture.source_root.join("child")).unwrap();
    let transaction = TransactionId([0x8e; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    assert!(
        std::fs::read_dir(fixture.base.join("wal-store"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| {
                let name = name.to_string_lossy();
                !name.starts_with(".tree-scratch-v1-") && !name.starts_with(".tree-purge-v1-")
            }),
        "purge authority must retain only an anonymous plan FD"
    );
    let commit = ready.execute_verified_purge(authority).unwrap();
    assert_eq!(commit.removed_entries(), 1);
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
    assert!(!fixture.destination_root.exists());
}

#[test]
fn streamed_v3_purge_preserves_non_utf8_plan_paths() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let name = OsStr::from_bytes(b"non-utf8-\xff");
    if let Err(error) = std::fs::write(fixture.source_root.join(name), b"opaque path") {
        if error.raw_os_error() == Some(libc::EILSEQ) {
            return;
        }
        panic!("failed to create non-UTF-8 purge fixture: {error}");
    }
    let transaction = TransactionId([0x8f; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    let commit = ready.execute_verified_purge(authority).unwrap();
    assert_eq!(commit.removed_entries(), 4);
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
    assert!(!fixture.destination_root.exists());
}

#[test]
fn verified_purge_mints_one_use_authority_after_durable_terminal_transition() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe1; 16]);
    let mut ready = stage_production(&fixture, transaction);

    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();

    assert_eq!(authority.transaction(), transaction);
    assert_eq!(authority.reclamation_id(), "undo-group");
    assert_eq!(ready.state(transaction), Some(TransactionState::Purgeable));
    assert!(fixture.destination_root.is_dir());
    assert!(
        ready
            .verified_undo_token(transaction, "undo-group")
            .is_none(),
        "Purgeable and verified undo must be mutually exclusive"
    );
    let second = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert_eq!(
        second.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    drop(authority);
    drop(ready);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty(), "Purgeable is startup terminal");
    let calls = std::cell::Cell::new(0);
    let (mut ready, summary) = engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other(
                "Purgeable startup must not acquire mutation anchors",
            ))
        })
        .unwrap();
    assert_eq!(calls.get(), 0);
    assert!(summary.recovered.is_empty());
    assert_eq!(ready.state(transaction), Some(TransactionState::Purgeable));
    assert!(fixture.destination_root.is_dir(), "startup must not delete");

    // A dropped pre-mutation authority is recreated only by a new WAL lease
    // generation and a fresh complete object rebind.
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    ready.execute_verified_purge(authority).unwrap();
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
    assert!(!fixture.destination_root.exists());
}

#[test]
fn internal_hardlink_purge_is_rejected_before_authority_and_restart_undo_preserves_aliases() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.source_root.join("child/data");
    let alias = fixture.source_root.join("child/data-alias");
    std::fs::hard_link(&original, &alias).unwrap();
    let transaction = TransactionId([0xeb; 16]);
    let mut ready = stage_production(&fixture, transaction);

    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert!(error.is_unsupported_internal_hard_links(), "{error}");
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    for path in [
        fixture.destination_root.join("child/data"),
        fixture.destination_root.join("child/data-alias"),
    ] {
        assert!(path.is_file());
        assert_eq!(std::fs::metadata(path).unwrap().nlink(), 2);
    }
    drop(ready);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let staged = &replay.transactions[&transaction];
    assert_eq!(staged.state, TransactionState::VerifiedCommitted);
    assert_eq!(staged.purge_removed_entries, 0);
    assert!(staged.purge_last_path.is_none());
    drop(lease);

    // A fresh engine generation must still regard the committed transaction as
    // healthy and permit exact undo without any recovery/quarantine promotion.
    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let (mut ready, summary) = engine
        .recover_startup(report, |_, _| {
            Err(std::io::Error::other(
                "VerifiedCommitted must not request startup recovery anchors",
            ))
        })
        .unwrap();
    assert!(summary.recovered.is_empty());
    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap();
    let restored = std::fs::metadata(&original).unwrap();
    let restored_alias = std::fs::metadata(&alias).unwrap();
    assert_eq!(restored.ino(), restored_alias.ino());
    assert_eq!(restored.nlink(), 2);
    assert_eq!(restored_alias.nlink(), 2);
    assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
}

#[test]
fn hardlink_topology_drift_after_stage_uses_existing_recovery_required_tamper_path() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xec; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let outside = fixture.base.join("post-stage-external-alias");
    std::fs::hard_link(fixture.destination_root.join("child/data"), &outside).unwrap();

    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert!(!error.is_unsupported_internal_hard_links());
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired)
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(fixture.destination_root.join("child/data").is_file());
    assert!(outside.is_file());
}

#[test]
fn purge_authority_itself_retains_the_exact_wal_lease() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xea; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    drop(ready);

    assert!(
        SealedStagingEngine::open(&fixture.store).is_err(),
        "dropping the engine must not release an authority-held WAL lease"
    );
    drop(authority);
    assert!(SealedStagingEngine::open(&fixture.store).is_ok());
}

#[test]
fn verified_purge_consumes_exact_tree_without_following_symlinks_and_reaches_purged() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let outside = fixture.base.join("outside");
    std::fs::write(&outside, b"retain me").unwrap();
    std::os::unix::fs::symlink(&outside, fixture.source_root.join("outside-link")).unwrap();
    let transaction = TransactionId([0xe6; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();

    let commit = ready.execute_verified_purge(authority).unwrap();

    assert_eq!(commit.transaction(), transaction);
    assert_eq!(commit.reclamation_id(), "undo-group");
    assert_eq!(commit.removed_entries(), 4);
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
    assert!(!fixture.destination_root.exists());
    assert_eq!(std::fs::read(outside).unwrap(), b"retain me");
    drop(ready);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    let (ready, _) = engine
        .recover_startup(report, |_, _| {
            Err(std::io::Error::other("Purged must not request anchors"))
        })
        .unwrap();
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
}

#[test]
fn purge_partial_unlink_failure_stays_at_intent_and_restart_fails_closed() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe7; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::backend::held::PURGE_FAIL_AFTER_REMOVALS.with(|limit| limit.set(Some(1)));
    let error = ready.execute_verified_purge(authority).unwrap_err();
    crate::backend::held::PURGE_FAIL_AFTER_REMOVALS.with(|limit| limit.set(None));

    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(fixture.destination_root.exists());
    drop(ready);

    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 1);
    assert_eq!(
        replay.transactions[&transaction].purge_last_path.as_deref(),
        Some(std::path::Path::new("child/data")),
        "streamed purge must preserve historical depth-descending reverse-path progress"
    );
    drop(lease);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    let restart = engine.recover_startup(report, |_, _| Ok(fixture.raw_anchors()));
    assert!(
        restart.is_err(),
        "partial deletion must never be guessed complete"
    );
}

#[test]
fn purge_parent_fsync_failure_records_no_outcome_or_purged_guess() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe8; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::backend::held::PURGE_FAIL_PARENT_FSYNC.with(|fail| fail.set(true));
    let error = ready.execute_verified_purge(authority).unwrap_err();
    crate::backend::held::PURGE_FAIL_PARENT_FSYNC.with(|fail| fail.set(false));

    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(!fixture.destination_root.exists());
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    let snapshot = &replay.transactions[&transaction];
    assert_eq!(
        snapshot.purge_removed_entries,
        snapshot.tree_manifest.unwrap().entry_count
    );
    assert_eq!(
        snapshot.purge_last_path.as_deref(),
        Some(std::path::Path::new(""))
    );
}

#[test]
fn durable_claim_precedes_every_namespace_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xf1; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::staging::recovery::PURGE_FAIL_AFTER_CLAIM.with(|fail| fail.set(true));
    let error = ready.execute_verified_purge(authority).unwrap_err();
    crate::staging::recovery::PURGE_FAIL_AFTER_CLAIM.with(|fail| fail.set(false));

    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(fixture.destination_root.join("child/data").exists());
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 0);
    drop(lease);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert!(
        engine
            .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
            .is_err()
    );
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RecoveryRequired
    );
}

#[test]
fn progress_sync_failure_stops_before_another_unlink_and_replays_bounded_progress() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xf2; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::staging::recovery::PURGE_FAIL_PROGRESS_AT.with(|at| at.set(Some(1)));
    let error = ready.execute_verified_purge(authority).unwrap_err();
    crate::staging::recovery::PURGE_FAIL_PROGRESS_AT.with(|at| at.set(None));

    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeIntent)
    );
    assert!(fixture.destination_root.exists());
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(replay.transactions[&transaction].purge_removed_entries, 0);
}

#[test]
fn durable_purge_outcome_restart_finalizes_without_namespace_lookup() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe9; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    crate::staging::recovery::PURGE_FAIL_AFTER_OUTCOME.with(|fail| fail.set(true));
    let error = ready.execute_verified_purge(authority).unwrap_err();
    crate::staging::recovery::PURGE_FAIL_AFTER_OUTCOME.with(|fail| fail.set(false));

    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::PurgeOutcome)
    );
    assert!(!fixture.destination_root.exists());
    drop(ready);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    let calls = std::cell::Cell::new(0);
    let (ready, summary) = engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other(
                "outcome finalization must not lookup",
            ))
        })
        .unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(
        summary.recovered[0].terminal_state,
        TransactionState::Purged
    );
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
}

#[test]
fn purge_request_selector_is_not_authority() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe2; 16]);
    let mut ready = stage_production(&fixture, transaction);

    let error = ready
        .request_verified_purge(verified_purge_request(
            &fixture,
            transaction,
            "oplog-forged-group",
        ))
        .unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(fixture.destination_root.is_dir());
}

#[test]
fn verified_purge_content_and_mode_drift_fail_closed_to_recovery_required() {
    for drift in ["content", "mode"] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId(if drift == "content" {
            [0xe3; 16]
        } else {
            [0xe4; 16]
        });
        let mut ready = stage_production(&fixture, transaction);
        if drift == "content" {
            std::fs::write(
                fixture.destination_root.join("child/data"),
                b"changed content",
            )
            .unwrap();
        } else {
            set_mode(&fixture.destination_root.join("child"), 0o700);
        }

        let error = ready
            .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
            .unwrap_err();
        assert_eq!(
            error.disposition(),
            VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired),
            "{drift}: {error}"
        );
        assert_eq!(
            ready.state(transaction),
            Some(TransactionState::RecoveryRequired)
        );
        assert!(fixture.destination_root.is_dir());
    }
}

#[test]
fn verified_purge_parent_or_root_replacement_never_mints_authority() {
    for replacement in ["parent", "root"] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId(if replacement == "parent" {
            [0xe5; 16]
        } else {
            [0xe6; 16]
        });
        let mut ready = stage_production(&fixture, transaction);
        if replacement == "parent" {
            let detached = fixture.base.join("detached-destination-parent");
            std::fs::rename(&fixture.destination_parent, detached).unwrap();
            std::fs::create_dir(&fixture.destination_parent).unwrap();
            set_mode(&fixture.destination_parent, 0o700);
        } else {
            let detached = fixture.destination_parent.join("detached-staged");
            std::fs::rename(&fixture.destination_root, detached).unwrap();
            std::fs::create_dir(&fixture.destination_root).unwrap();
            set_mode(&fixture.destination_root, 0o750);
        }

        let error = ready
            .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
            .unwrap_err();
        assert_eq!(
            error.disposition(),
            VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired),
            "{replacement}: {error}"
        );
        assert_eq!(
            ready.state(transaction),
            Some(TransactionState::RecoveryRequired)
        );
    }
}

#[test]
fn verified_undo_restores_committed_modes_before_fd_relative_rename_back() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xd8; 16]);
    let mut ready = stage_production(&fixture, transaction);
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let commit = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap();

    assert_eq!(commit.transaction(), transaction);
    assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
    assert_eq!(mode(&fixture.source_root), 0o770);
    assert_eq!(mode(&fixture.source_root.join("child")), 0o770);
    assert_eq!(
        std::fs::read(fixture.source_root.join("child/data")).unwrap(),
        b"sealed staging"
    );
    assert!(
        ready
            .verified_undo_token(transaction, "undo-group")
            .is_none()
    );
}

#[test]
fn verified_undo_preexisting_collision_never_replaces_or_writes_intent() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xd9; 16]);
    let mut ready = stage_production(&fixture, transaction);
    std::fs::create_dir(&fixture.source_root).unwrap();
    std::fs::write(fixture.source_root.join("replacement"), b"foreign").unwrap();

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();

    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert_eq!(
        std::fs::read(fixture.source_root.join("replacement")).unwrap(),
        b"foreign"
    );
    assert!(fixture.destination_root.is_dir());
    // A pre-existing collision is rejected before UndoIntent or mode mutation.
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);
}

#[test]
fn verified_undo_noreplace_race_reaches_durable_undo_conflict() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xdb; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let collision = fixture.source_root.clone();
    crate::staging::recovery::BEFORE_UNDO_RENAME.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            std::fs::create_dir(&collision).unwrap();
            std::fs::write(collision.join("replacement"), b"foreign").unwrap();
        }));
    });

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();

    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::Terminal(TransactionState::UndoConflict)
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::UndoConflict)
    );
    assert_eq!(
        std::fs::read(fixture.source_root.join("replacement")).unwrap(),
        b"foreign"
    );
    assert!(fixture.destination_root.is_dir());
    assert_eq!(mode(&fixture.destination_root), 0o770);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o770);
    drop(ready);
    let store_path = fixture.base.join("wal-store");
    assert!(
        std::fs::read_dir(&store_path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .any(|path| path.extension() == Some(OsStr::new("sidecar")))
    );

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    assert!(
        std::fs::read_dir(&store_path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .all(|path| path.extension() != Some(OsStr::new("sidecar"))),
        "an exact terminal WAL reference must be collected and directory-synced"
    );
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::UndoConflict)
    );
}

#[test]
fn verified_undo_content_drift_fails_before_durable_undo_intent() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xdc; 16]);
    let mut ready = stage_production(&fixture, transaction);
    // Same byte length defeats size-only manifests; the content digest and
    // fresh ctime/mtime evidence must still refuse undo.
    std::fs::write(
        fixture.destination_root.join("child/data"),
        b"evil!! staging",
    )
    .unwrap();

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
}

#[test]
fn verified_undo_mode_drift_fails_before_durable_undo_intent() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xda; 16]);
    let mut ready = stage_production(&fixture, transaction);
    set_mode(&fixture.destination_root.join("child"), 0o700);

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();

    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
}

#[test]
#[allow(clippy::disallowed_methods)] // adversarially corrupts the published proof
fn verified_undo_corrupt_sidecar_is_durably_recovery_required_before_undo_intent() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xdb; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let sidecar = std::fs::read_dir(fixture.base.join("wal-store"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("sidecar")))
        .expect("verified commit must retain its published sidecar");
    let sidecar_file = std::fs::OpenOptions::new()
        .write(true)
        .open(sidecar)
        .unwrap();
    sidecar_file
        .set_len(sidecar_file.metadata().unwrap().len() - 1)
        .unwrap();

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();

    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RecoveryRequired
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // adversarially corrupts the published proof
fn verified_undo_sidecar_corruption_after_mode_restore_is_durably_recovery_required() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xdd; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let store = fixture.base.join("wal-store");
    crate::staging::recovery::AFTER_UNDO_MODES_RESTORED.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let sidecar = std::fs::read_dir(&store)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension() == Some(OsStr::new("sidecar")))
                .expect("verified undo must retain its published sidecar");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(sidecar)
                .unwrap();
            file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        }));
    });

    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();

    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::RecoveryBlocked
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(mode(&fixture.destination_root), 0o770);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o770);
    drop(ready);
    let mut lease = fixture.store.try_lease().unwrap();
    let replay = lease.replay_and_repair().unwrap();
    assert_eq!(
        replay.transactions[&transaction].state,
        TransactionState::RecoveryRequired
    );
}

#[test]
fn verified_undo_crash_boundaries_replay_without_path_guessing() {
    for (index, step) in [
        "intent",
        "inverse-intent",
        "inverse-fchmod",
        "modes",
        "outcome",
    ]
    .into_iter()
    .enumerate()
    {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId([0xe0 + index as u8; 16]);
        let mut ready = stage_production(&fixture, transaction);
        let token = ready
            .verified_undo_token(transaction, "undo-group")
            .unwrap();
        crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(Some(step)));
        let error = ready
            .undo_verified(token, verified_undo_request(&fixture))
            .unwrap_err();
        crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(None));
        assert_eq!(
            error.disposition(),
            VerifiedUndoFailureDisposition::RecoveryBlocked
        );
        drop(ready);

        let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert_eq!(report.candidates().len(), 1, "step={step}");
        let (ready, summary) = engine
            .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
            .unwrap();
        assert_eq!(summary.recovered.len(), 1);
        assert_eq!(
            ready.state(transaction),
            Some(TransactionState::Restored),
            "step={step}"
        );
        assert!(fixture.source_root.is_dir());
        assert!(!fixture.destination_root.exists());
    }
}

#[test]
fn undo_rename_crash_window_becomes_manual_recovery_without_namespace_lookup() {
    for (index, step) in [
        "rename-intent",
        "rename",
        "destination-fsync",
        "source-fsync",
    ]
    .into_iter()
    .enumerate()
    {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId([0xe4 + index as u8; 16]);
        let mut ready = stage_production(&fixture, transaction);
        let token = ready
            .verified_undo_token(transaction, "undo-group")
            .unwrap();
        crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(Some(step)));
        let error = ready
            .undo_verified(token, verified_undo_request(&fixture))
            .unwrap_err();
        crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(None));
        assert_eq!(
            error.disposition(),
            VerifiedUndoFailureDisposition::RecoveryBlocked,
            "step={step}"
        );
        drop(ready);

        let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        let provider_calls = std::cell::Cell::new(0);
        let error = engine
            .recover_startup(report, |_, _| {
                provider_calls.set(provider_calls.get() + 1);
                Ok(fixture.raw_anchors())
            })
            .err()
            .unwrap();
        assert_eq!(provider_calls.get(), 0, "step={step}");
        assert_eq!(error.stage(), "manual recovery block", "step={step}");
        if step == "rename-intent" {
            assert!(fixture.destination_root.is_dir());
            assert!(!fixture.source_root.exists());
        } else {
            assert!(!fixture.destination_root.exists());
            assert!(fixture.source_root.is_dir());
        }
    }
}

#[test]
fn durable_undo_terminal_survives_crash_before_oplog_append_without_replay_work() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xef; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(Some("terminal")));
    let error = ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap_err();
    crate::staging::recovery::UNDO_FAIL_STEP.with(|slot| slot.set(None));
    assert_eq!(
        error.disposition(),
        VerifiedUndoFailureDisposition::Terminal(TransactionState::Restored)
    );
    drop(ready);
    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    assert_eq!(engine.state(transaction), Some(TransactionState::Restored));
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
}

#[test]
fn verified_undo_parent_and_root_replacement_fail_before_intent() {
    for replacement in ["source-parent", "destination-parent", "root"] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId([0xe8 + replacement.len() as u8; 16]);
        let mut ready = stage_production(&fixture, transaction);
        match replacement {
            "source-parent" => {
                let displaced = fixture.base.join("source-parent-displaced");
                std::fs::rename(&fixture.source_parent, &displaced).unwrap();
                std::fs::create_dir(&fixture.source_parent).unwrap();
                set_mode(&fixture.source_parent, 0o700);
            }
            "destination-parent" => {
                let displaced = fixture.base.join("destination-parent-displaced");
                std::fs::rename(&fixture.destination_parent, &displaced).unwrap();
                std::fs::create_dir(&fixture.destination_parent).unwrap();
                set_mode(&fixture.destination_parent, 0o700);
            }
            "root" => {
                let displaced = fixture.destination_parent.join("staged-displaced");
                std::fs::rename(&fixture.destination_root, &displaced).unwrap();
                std::fs::create_dir(&fixture.destination_root).unwrap();
                set_mode(&fixture.destination_root, 0o750);
            }
            _ => unreachable!(),
        }
        let token = ready
            .verified_undo_token(transaction, "undo-group")
            .unwrap();
        let error = ready
            .undo_verified(token, verified_undo_request(&fixture))
            .unwrap_err();
        assert_eq!(
            error.disposition(),
            VerifiedUndoFailureDisposition::NotStarted,
            "replacement={replacement}: {error}"
        );
        assert_eq!(
            ready.state(transaction),
            Some(TransactionState::VerifiedCommitted)
        );
    }
}

#[test]
fn production_association_is_read_back_only_from_the_exact_leased_wal() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc7; 16]);
    let mut ready = fixture.ready_engine();
    let association = ProductionAssociation::new("reclamation-c1".to_string()).unwrap();

    ready
        .stage_to_verified_commit(
            transaction,
            fixture
                .forward_request("root", "staged")
                .with_production_association(association)
                .with_recovery_anchor(fixture.base.clone()),
        )
        .unwrap();

    let entries = ready.production_entries();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.transaction(), transaction);
    assert_eq!(entry.state(), TransactionState::VerifiedCommitted);
    assert_eq!(
        entry.destination_parent().relative_path(),
        Path::new("destination-parent")
    );
    assert_eq!(entry.destination_basename(), "staged");
    assert_eq!(entry.reclamation_id(), "reclamation-c1");
    assert_eq!(entry.recovery_anchor(), Some(fixture.base.as_path()));
    let destination: OwnedFd = std::fs::File::open(&fixture.destination_root)
        .unwrap()
        .into();
    assert_eq!(
        entry.root_identity(),
        strong_identity_fd(&destination).unwrap()
    );
}

#[test]
fn forward_coordinator_allows_sequential_terminal_transactions() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = fixture.ready_engine();
    let first = TransactionId([0xc9; 16]);
    ready
        .stage_to_verified_commit(first, fixture.forward_request("root", "staged"))
        .unwrap();

    let second_source = fixture.source_parent.join("second-root");
    let second_destination = fixture.destination_parent.join("second-staged");
    std::fs::create_dir(&second_source).unwrap();
    std::fs::write(second_source.join("data"), b"second").unwrap();
    set_mode(&second_source, 0o770);
    let second = TransactionId([0xca; 16]);
    ready
        .stage_to_verified_commit(
            second,
            fixture.forward_request("second-root", "second-staged"),
        )
        .unwrap();

    assert_eq!(
        ready.state(first),
        Some(TransactionState::VerifiedCommitted)
    );
    assert_eq!(
        ready.state(second),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(!second_source.exists());
    assert_eq!(
        std::fs::read(second_destination.join("data")).unwrap(),
        b"second"
    );
    assert_eq!(mode(&fixture.source_parent), 0o770);
}

#[test]
fn forward_collision_is_restored_before_error_returns() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let destination = fixture.destination_root.clone();
    BEFORE_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::create_dir(&destination).unwrap();
            std::fs::write(destination.join("sentinel"), b"keep").unwrap();
        }));
    });
    let transaction = TransactionId([0xcb; 16]);
    let mut ready = fixture.ready_engine();

    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();

    assert_eq!(error.transaction(), transaction);
    assert_eq!(error.stage(), "seal and no-replace rename");
    assert_eq!(
        error.disposition(),
        ForwardFailureDisposition::Terminal(TransactionState::Restored)
    );
    assert_eq!(error.terminal_state(), Some(TransactionState::Restored));
    assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
    assert!(fixture.source_root.is_dir());
    assert_eq!(
        std::fs::read(fixture.destination_root.join("sentinel")).unwrap(),
        b"keep"
    );
    assert_eq!(mode(&fixture.source_parent), 0o770);
    assert_eq!(mode(&fixture.source_root), 0o770);

    let retry = TransactionId([0xce; 16]);
    ready
        .stage_to_verified_commit(retry, fixture.forward_request("root", "retry-staged"))
        .unwrap();
    assert_eq!(
        ready.state(retry),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(fixture.destination_parent.join("retry-staged").is_dir());
}

#[test]
fn uncertain_first_wal_frame_never_reports_not_started() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    FAIL_WAL_STEP.with(|failure| failure.set(Some("begin-poison")));
    let transaction = TransactionId([0xd4; 16]);
    let mut ready = fixture.ready_engine();
    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();
    FAIL_WAL_STEP.with(|failure| failure.set(None));

    assert_eq!(error.stage(), "seal and no-replace rename");
    assert_eq!(
        error.disposition(),
        ForwardFailureDisposition::RecoveryBlocked
    );
    assert_eq!(error.terminal_state(), None);
    assert_eq!(ready.state(transaction), None);
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());

    let blocked = ready
        .stage_to_verified_commit(
            TransactionId([0xd5; 16]),
            fixture.forward_request("root", "staged"),
        )
        .unwrap_err();
    assert_eq!(blocked.stage(), "transaction admission");
    assert_eq!(
        blocked.disposition(),
        ForwardFailureDisposition::RecoveryBlocked
    );
}

#[test]
fn unknown_forward_outcome_becomes_a_manual_block() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    RENAME_ERROR.with(|error| error.set(Some(libc::EIO)));
    let transaction = TransactionId([0xcf; 16]);
    let mut ready = fixture.ready_engine();
    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();
    RENAME_ERROR.with(|error| error.set(None));

    assert_eq!(error.stage(), "failed-forward recovery");
    assert_eq!(
        error.disposition(),
        ForwardFailureDisposition::RecoveryBlocked
    );
    assert_eq!(error.terminal_state(), None);
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(fixture.source_root.is_dir());
    assert!(!fixture.destination_root.exists());
    assert_eq!(mode(&fixture.source_parent), 0o750);

    let blocked = TransactionId([0xd0; 16]);
    let blocked_error = ready
        .stage_to_verified_commit(blocked, fixture.forward_request("root", "staged"))
        .unwrap_err();
    assert_eq!(blocked_error.stage(), "transaction admission");
    assert_eq!(
        blocked_error.disposition(),
        ForwardFailureDisposition::RecoveryBlocked
    );
    assert_eq!(blocked_error.terminal_state(), None);
    assert_eq!(ready.state(blocked), None);
}

#[test]
fn forward_verification_mismatch_quarantines_and_restores_seals() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let destination = fixture.destination_root.clone();
    AFTER_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::write(destination.join("unexpected"), b"mismatch").unwrap();
        }));
    });
    let transaction = TransactionId([0xcc; 16]);
    let mut ready = fixture.ready_engine();

    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();

    assert_eq!(error.stage(), "staged-tree verification");
    assert!(
        error
            .to_string()
            .contains("staged tree does not match its durable manifest"),
        "verification cause was lost: {error}"
    );
    assert_eq!(
        error.disposition(),
        ForwardFailureDisposition::Terminal(TransactionState::Quarantined)
    );
    assert_eq!(error.terminal_state(), Some(TransactionState::Quarantined));
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::Quarantined)
    );
    assert!(!fixture.source_root.exists());
    assert!(fixture.destination_root.is_dir());
    assert_eq!(mode(&fixture.source_parent), 0o770);
    assert_eq!(mode(&fixture.destination_root), 0o770);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o770);
}

#[test]
fn quarantine_root_cause_survives_a_later_restore_failure() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let destination = fixture.destination_root.clone();
    AFTER_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::write(destination.join("unexpected"), b"mismatch").unwrap();
        }));
    });
    let source_parent = fixture.source_parent.clone();
    let detached = fixture.base.join("detached-source-parent");
    crate::staging::AFTER_FORWARD_QUARANTINE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&source_parent, &detached).unwrap();
            std::fs::create_dir(&source_parent).unwrap();
            set_mode(&source_parent, 0o700);
        }));
    });
    let transaction = TransactionId([0xd6; 16]);
    let mut ready = fixture.ready_engine();

    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();

    assert_eq!(error.stage(), "forward commit recovery");
    assert_eq!(
        error.disposition(),
        ForwardFailureDisposition::RecoveryBlocked
    );
    assert!(
        error
            .to_string()
            .contains("staged tree does not match its durable manifest"),
        "verification cause was lost behind restore failure: {error}"
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
}

#[test]
fn forward_preparation_failure_writes_no_transaction() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    std::fs::create_dir(&fixture.destination_root).unwrap();
    let transaction = TransactionId([0xcd; 16]);
    let mut ready = fixture.ready_engine();

    let error = ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap_err();

    assert_eq!(error.stage(), "prepared root binding");
    assert_eq!(error.disposition(), ForwardFailureDisposition::NotStarted);
    assert_eq!(error.terminal_state(), None);
    assert_eq!(ready.state(transaction), None);
    assert!(fixture.source_root.is_dir());

    let next_source = fixture.source_parent.join("next-root");
    std::fs::create_dir(&next_source).unwrap();
    set_mode(&next_source, 0o700);
    let next = TransactionId([0xd1; 16]);
    ready
        .stage_to_verified_commit(next, fixture.forward_request("next-root", "next-staged"))
        .unwrap();
    assert_eq!(ready.state(next), Some(TransactionState::VerifiedCommitted));
}

#[test]
fn reused_transaction_id_never_inherits_an_old_terminal_receipt() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut ready = fixture.ready_engine();
    let transaction = TransactionId([0xd2; 16]);
    ready
        .stage_to_verified_commit(transaction, fixture.forward_request("root", "staged"))
        .unwrap();

    let second_source = fixture.source_parent.join("second-root");
    std::fs::create_dir(&second_source).unwrap();
    set_mode(&second_source, 0o700);
    let error = ready
        .stage_to_verified_commit(
            transaction,
            fixture.forward_request("second-root", "second-staged"),
        )
        .unwrap_err();

    assert_eq!(error.stage(), "transaction admission");
    assert_eq!(error.disposition(), ForwardFailureDisposition::NotStarted);
    assert_eq!(error.terminal_state(), None);
    assert!(second_source.is_dir());
    assert!(!fixture.destination_parent.join("second-staged").exists());

    let next = TransactionId([0xd3; 16]);
    ready
        .stage_to_verified_commit(
            next,
            fixture.forward_request("second-root", "second-staged"),
        )
        .unwrap();
    assert_eq!(ready.state(next), Some(TransactionState::VerifiedCommitted));
}

#[test]
fn startup_coordinator_verifies_restores_parent_and_commits() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc1; 16]);
    {
        let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert!(report.is_empty());
        drop(
            engine
                .stage_prepared_root(transaction, fixture.prepare())
                .unwrap(),
        );
    }

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let (ready, summary) = engine
        .recover_startup(report, |candidate, _| {
            assert_eq!(candidate, transaction);
            Ok(fixture.raw_anchors())
        })
        .unwrap();

    assert_eq!(summary.recovered.len(), 1);
    assert_eq!(
        summary.recovered[0].terminal_state,
        TransactionState::VerifiedCommitted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert_eq!(mode(&fixture.source_parent), 0o770);
    assert_eq!(mode(&fixture.destination_root), 0o750);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o750);
}

#[test]
fn startup_coordinator_quarantines_mismatch_then_restores_all_active_seals() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc2; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
        drop(
            engine
                .stage_prepared_root(transaction, fixture.prepare())
                .unwrap(),
        );
    }
    set_mode(&fixture.destination_root, 0o700);
    std::fs::write(fixture.destination_root.join("unexpected"), b"mismatch").unwrap();
    set_mode(&fixture.destination_root, 0o750);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let (ready, summary) = engine
        .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
        .unwrap();

    assert_eq!(summary.recovered.len(), 1);
    assert_eq!(
        summary.recovered[0].terminal_state,
        TransactionState::Quarantined
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::Quarantined)
    );
    assert_eq!(mode(&fixture.source_parent), 0o770);
    assert_eq!(mode(&fixture.destination_root), 0o770);
    assert_eq!(mode(&fixture.destination_root.join("child")), 0o770);
}

#[test]
fn source_parent_restored_crash_reopens_to_state_only_verified_commit() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc5; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
        drop(
            engine
                .stage_prepared_root(transaction, fixture.prepare())
                .unwrap(),
        );
    }

    let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
    let mut provider = |_, _: &StagingTransactionMetadata| Ok(fixture.raw_anchors());
    let error = engine
        .recover_transaction_with_step_limit_for_test(transaction, &mut provider, 2)
        .unwrap_err();
    assert_eq!(error.stage(), "step exhaustion");
    assert_eq!(
        engine.state(transaction),
        Some(TransactionState::SourceParentRestored)
    );
    drop(engine);

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let calls = std::cell::Cell::new(0);
    let (ready, summary) = engine
        .recover_startup(report, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other(
                "state-only finalization must not request anchors",
            ))
        })
        .unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert_eq!(
        summary.recovered[0].terminal_state,
        TransactionState::VerifiedCommitted
    );
}

#[test]
fn startup_anchor_failure_returns_no_ready_engine_and_remains_replayable() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xc3; 16]);
    {
        let (mut engine, _) = SealedStagingEngine::open(&fixture.store).unwrap();
        drop(
            engine
                .stage_prepared_root(transaction, fixture.prepare())
                .unwrap(),
        );
    }

    let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let error = engine
        .recover_startup(report, |_, _| {
            Err(std::io::Error::other("injected anchor refusal"))
        })
        .err()
        .unwrap();
    assert_eq!(error.transaction(), Some(transaction));
    assert_eq!(error.stage(), "anchor acquisition");

    let (mut reopened, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    let metadata = reopened.metadata(transaction).unwrap().clone();
    assert!(
        reopened
            .begin_transaction(TransactionId([0xc4; 16]), metadata)
            .is_err()
    );
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

    let (mut recovered_engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let candidate = report.into_candidates().pop().unwrap();
    let capability = recovered_engine
        .prepare_startup_recovery(candidate, fixture.anchors())
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
        panic!("exact recovered sealed tree must verify")
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
            &fixture.store.tree_sidecar_store().unwrap(),
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
    assert_eq!(report.candidates().len(), 1);
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
    assert!(report.is_empty());
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
    assert!(report.is_empty());
    drop(engine);
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_noreplace_and_both_parent_fsync_contract_is_mandatory() {
    let fixture = Fixture::new().expect("macOS held-rename tests require a certified APFS fixture");
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

#[cfg(target_os = "linux")]
#[test]
fn verified_purge_rejects_admitted_regular_xattrs_without_leaving_committed_state() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let data = fixture.source_root.join("child/data");
    let data = std::ffi::CString::new(data.as_os_str().as_bytes()).unwrap();
    let value = b"ordinary metadata";
    // SAFETY: the C path, name, and value buffer remain live for the syscall.
    let result = unsafe {
        libc::setxattr(
            data.as_ptr(),
            c"user.degu-test".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(result, 0, "failed to plant ordinary xattr");
    let transaction = TransactionId([0x88; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert!(error.is_unsupported_regular_xattrs(), "{error}");
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::NotStarted
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    assert!(fixture.destination_root.join("child/data").is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn verified_purge_acl_drift_fails_closed_to_recovery_required() {
    use std::os::unix::ffi::OsStrExt;

    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xe7; 16]);
    let mut ready = stage_production(&fixture, transaction);
    let child = fixture.destination_root.join("child");
    let child = std::ffi::CString::new(child.as_os_str().as_bytes()).unwrap();
    let acl: [u8; 28] = [
        2, 0, 0, 0, // version
        1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ
        4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ
        0x20, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER
    ];
    // SAFETY: both C path and ACL buffer remain live for the syscall.
    let result = unsafe {
        libc::setxattr(
            child.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    assert_eq!(
        result,
        0,
        "failed to plant test ACL: {}",
        std::io::Error::last_os_error()
    );

    let error = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap_err();
    assert_eq!(
        error.disposition(),
        VerifiedPurgeFailureDisposition::Terminal(TransactionState::RecoveryRequired),
        "{error}"
    );
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(fixture.destination_root.is_dir());
}

#[test]
fn every_postorder_progress_boundary_stops_without_outcome_or_replacement_deletion() {
    for progress in 1..=3 {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let transaction = TransactionId([0xf3 + progress as u8; 16]);
        let mut ready = stage_production(&fixture, transaction);
        let authority = ready
            .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
            .unwrap();
        crate::staging::recovery::PURGE_FAIL_PROGRESS_AT.with(|at| at.set(Some(progress)));
        assert!(ready.execute_verified_purge(authority).is_err());
        crate::staging::recovery::PURGE_FAIL_PROGRESS_AT.with(|at| at.set(None));
        assert_eq!(
            ready.state(transaction),
            Some(TransactionState::PurgeIntent)
        );
        drop(ready);

        let mut lease = fixture.store.try_lease().unwrap();
        let replay = lease.replay_and_repair().unwrap();
        assert_eq!(
            replay.transactions[&transaction].purge_removed_entries,
            progress - 1
        );
        drop(lease);

        // Even when the root unlink happened before the failed final progress
        // sync, startup never treats absence or a newly planted name as proof.
        if !fixture.destination_root.exists() {
            std::fs::create_dir(&fixture.destination_root).unwrap();
            std::fs::write(fixture.destination_root.join("replacement"), b"retain").unwrap();
        }
        let (engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
        assert!(
            engine
                .recover_startup(report, |_, _| Ok(fixture.raw_anchors()))
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.destination_root.join("replacement"))
                .ok()
                .as_deref(),
            (progress == 3).then_some(b"retain".as_slice())
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_recovery_tree_seals_fit_bounded_process_fd_budget() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    for index in 0..240 {
        let sibling = fixture.source_root.join(format!("bounded-{index:03}"));
        std::fs::create_dir(&sibling).unwrap();
        set_mode(&sibling, 0o770);
    }

    // This subprocess-only reduction never raises the inherited limit. The old
    // rebound vector needed several descriptors per directory and deterministically
    // exhausted this budget before staged verification or verified undo.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = limit.rlim_cur.min(128);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

    let fd_directory = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let baseline = std::fs::read_dir(fd_directory).unwrap().count();
    let peak = std::rc::Rc::new(std::cell::Cell::new(baseline));
    let observed_peak = std::rc::Rc::clone(&peak);
    let _observer = install_recovery_fd_observer(move || {
        observed_peak.set(
            observed_peak
                .get()
                .max(std::fs::read_dir(fd_directory).unwrap().count()),
        );
    });

    let transaction = TransactionId([0xf6; 16]);
    let mut ready = stage_production(&fixture, transaction);
    assert_eq!(
        ready.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    let token = ready
        .verified_undo_token(transaction, "undo-group")
        .unwrap();
    ready
        .undo_verified(token, verified_undo_request(&fixture))
        .unwrap();
    assert_eq!(ready.state(transaction), Some(TransactionState::Restored));
    assert!(fixture.source_root.is_dir());
    assert!(
        peak.get().saturating_sub(baseline) <= 24,
        "recovery retained per-directory descriptors: baseline={baseline}, peak={}",
        peak.get()
    );
    assert_eq!(
        std::fs::read_dir(&fixture.source_root).unwrap().count(),
        241,
        "all 240 siblings plus the content-bearing child must survive undo"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn staged_verification_and_verified_undo_are_bounded_across_240_tree_seals() {
    const CHILD_MARKER_ENV: &str = "DEGU_RECOVERY_FD_OBSERVATION_CHILD_MARKER";
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        assert_recovery_tree_seals_fit_bounded_process_fd_budget();
        std::fs::write(marker, b"observed").unwrap();
        return;
    }

    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("completed");
    let test_name = format!(
        "{}::staged_verification_and_verified_undo_are_bounded_across_240_tree_seals",
        module_path!()
            .strip_prefix("degu_core::")
            .unwrap_or(module_path!())
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .unwrap();
    assert!(status.success(), "isolated recovery FD test failed");
    assert!(marker.exists(), "isolated recovery FD test did not execute");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_deep_restart_verification_and_undo_fit_process_fd_budget() {
    fn add_deep_branch(fixture: &Fixture) {
        let mut directory = fixture.source_root.clone();
        for _ in 0..96 {
            directory.push("d");
            std::fs::create_dir(&directory).unwrap();
            set_mode(&directory, 0o770);
        }
        std::fs::write(directory.join("deep-data"), b"depth-bounded recovery").unwrap();
    }

    let Some(restart_fixture) = Fixture::new() else {
        return;
    };
    let Some(undo_fixture) = Fixture::new() else {
        return;
    };
    add_deep_branch(&restart_fixture);
    add_deep_branch(&undo_fixture);

    let restart_transaction = TransactionId([0xf8; 16]);
    let (mut restart_engine, report) = SealedStagingEngine::open(&restart_fixture.store).unwrap();
    assert!(report.is_empty());
    drop(
        restart_engine
            .stage_prepared_root(restart_transaction, restart_fixture.prepare())
            .unwrap(),
    );
    drop(restart_engine);

    let undo_transaction = TransactionId([0xf9; 16]);
    let mut undo_ready = stage_production(&undo_fixture, undo_transaction);

    // Reduce only after both forward publications. Restart verification and the
    // two verified-undo proof passes must each fit one active directory chain
    // plus fixed scratch/cursor descriptors; the old resident recovery
    // inventory overlapped retained directory FDs with the deep traversal chain.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = limit.rlim_cur.min(160);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

    let (restart_engine, report) = SealedStagingEngine::open(&restart_fixture.store).unwrap();
    let (restart_ready, summary) = restart_engine
        .recover_startup(report, |_, _| Ok(restart_fixture.raw_anchors()))
        .unwrap();
    assert_eq!(summary.recovered.len(), 1);
    assert_eq!(
        restart_ready.state(restart_transaction),
        Some(TransactionState::VerifiedCommitted)
    );
    drop(restart_ready);

    let token = undo_ready
        .verified_undo_token(undo_transaction, "undo-group")
        .unwrap();
    undo_ready
        .undo_verified(token, verified_undo_request(&undo_fixture))
        .unwrap();
    assert_eq!(
        undo_ready.state(undo_transaction),
        Some(TransactionState::Restored)
    );
    let restored = undo_fixture
        .source_root
        .join(std::iter::repeat_n("d", 96).collect::<PathBuf>())
        .join("deep-data");
    assert_eq!(std::fs::read(restored).unwrap(), b"depth-bounded recovery");
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn deep_restart_verification_and_verified_undo_are_fd_bounded() {
    const CHILD_MARKER_ENV: &str = "DEGU_DEEP_RECOVERY_FD_CHILD_MARKER";
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        assert_deep_restart_verification_and_undo_fit_process_fd_budget();
        std::fs::write(marker, b"observed").unwrap();
        return;
    }

    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("completed");
    let test_name = format!(
        "{}::deep_restart_verification_and_verified_undo_are_fd_bounded",
        module_path!()
            .strip_prefix("degu_core::")
            .unwrap_or(module_path!())
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .unwrap();
    assert!(status.success(), "isolated deep recovery FD test failed");
    assert!(
        marker.exists(),
        "isolated deep recovery FD test did not execute"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_deep_streamed_purge_fits_process_fd_budget() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let mut directory = fixture.source_root.clone();
    for _ in 0..96 {
        directory.push("d");
        std::fs::create_dir(&directory).unwrap();
        set_mode(&directory, 0o770);
    }
    std::fs::write(directory.join("deep-data"), b"bounded purge").unwrap();
    let transaction = TransactionId([0xfa; 16]);
    let mut ready = stage_production(&fixture, transaction);

    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = limit.rlim_cur.min(160);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

    let authority = ready
        .request_verified_purge(verified_purge_request(&fixture, transaction, "undo-group"))
        .unwrap();
    let commit = ready.execute_verified_purge(authority).unwrap();
    assert_eq!(commit.removed_entries(), 100);
    assert_eq!(ready.state(transaction), Some(TransactionState::Purged));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn deep_streamed_v3_purge_is_fd_bounded() {
    const CHILD_MARKER_ENV: &str = "DEGU_DEEP_PURGE_FD_CHILD_MARKER";
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        assert_deep_streamed_purge_fits_process_fd_budget();
        std::fs::write(marker, b"observed").unwrap();
        return;
    }
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("completed");
    let test_name = format!(
        "{}::deep_streamed_v3_purge_is_fd_bounded",
        module_path!()
            .strip_prefix("degu_core::")
            .unwrap_or(module_path!())
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .unwrap();
    assert!(status.success(), "isolated deep purge FD test failed");
    assert!(
        marker.exists(),
        "isolated deep purge FD test did not execute"
    );
}

#[test]
fn staged_recovery_descendant_replacement_is_quarantined_without_chmod_replacement() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let transaction = TransactionId([0xf7; 16]);
    let binding = fixture.prepare();
    let (mut engine, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    assert!(report.is_empty());
    drop(engine.stage_prepared_root(transaction, binding).unwrap());
    drop(engine);

    let (mut recovered, report) = SealedStagingEngine::open(&fixture.store).unwrap();
    let candidate = report.into_candidates().pop().unwrap();
    let capability = recovered
        .prepare_startup_recovery(candidate, fixture.anchors())
        .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("applied rename must require staged verification")
    };

    let child = fixture.destination_root.join("child");
    let detached = fixture.destination_root.join("detached-child");
    std::fs::rename(&child, &detached).unwrap();
    std::fs::create_dir(&child).unwrap();
    set_mode(&child, 0o700);
    let outcome = pending.verify_or_quarantine().unwrap();
    assert!(matches!(
        outcome,
        StagedVerificationOutcome::Quarantined(StagedVerificationFailure::Rebind(
            RecoveryRebindError::BindingChanged
        ))
    ));
    assert_eq!(mode(&child), 0o700, "replacement must never be chmoded");
    assert_eq!(mode(&detached), 0o750, "moved original remains sealed");
    assert_eq!(
        recovered.state(transaction),
        Some(TransactionState::Quarantined)
    );
}
