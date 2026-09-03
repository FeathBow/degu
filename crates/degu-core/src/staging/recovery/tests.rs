use super::*;
use crate::authority::PersistentRecoveryEvidence;
use crate::backend::held::ManifestV3StreamError;
use crate::seal::sidecar::TreeSidecarError;
use crate::seal::store::SealWalStore;
use crate::seal::wal::{
    ApplicationStatus, DurableSourceParentStrategy, DurableTreeManifest, ObjectIncarnation,
    PermissionIntent, RecoveryIdentity, RecoveryRequiredReason, decide_recovery,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn open_dir(path: &Path) -> OwnedFd {
    rustix::fs::open(path, OPEN_DIRECTORY, Mode::empty()).unwrap()
}

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    source_anchor: OwnedFd,
    destination_anchor: OwnedFd,
    metadata: StagingTransactionMetadata,
    backend: CertifiedLocalBackend,
    filesystem_id: String,
}

fn fixture(staged: bool) -> Option<Fixture> {
    let temp = crate::secure_test_tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("source");
    let destination = base.join("destination");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&destination).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
    let root = if staged {
        destination.join("staged")
    } else {
        source.join("root")
    };
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let source_anchor = open_dir(&base);
    let destination_anchor = open_dir(&base);
    let backend = match certify_held_fd_backend(&source_anchor) {
        Ok(backend) => backend,
        Err(
            error @ (CertificationError::UnsupportedPlatform
            | CertificationError::UnsupportedFilesystem),
        ) => {
            eprintln!("SKIP staging-recovery fixture: {error:?}");
            return None;
        }
        Err(error) => panic!("staging-recovery fixture certification failed: {error:?}"),
    };
    let filesystem_id = held_filesystem_id(&source_anchor).unwrap();
    let source_identity = strong_identity_fd(&open_dir(&source)).unwrap();
    let destination_identity = strong_identity_fd(&open_dir(&destination)).unwrap();
    let root_identity = strong_identity_fd(&open_dir(&root)).unwrap();
    let metadata = StagingTransactionMetadata::new(
        StagingLocator::new(PathBuf::from("source"), filesystem_id.clone()).unwrap(),
        source_identity,
        OsString::from("root"),
        root_identity,
        StagingLocator::new(PathBuf::from("destination"), filesystem_id.clone()).unwrap(),
        destination_identity,
        OsString::from("staged"),
        backend,
        DurableSourceParentStrategy::PermissionSeal,
    )
    .unwrap();
    Some(Fixture {
        _temp: temp,
        base,
        source_anchor,
        destination_anchor,
        metadata,
        backend,
        filesystem_id,
    })
}

fn anchors(fixture: &Fixture) -> RecoveryAnchors {
    RecoveryAnchors {
        source: RecoveryFilesystemAnchor::certify(
            rustix::io::dup(&fixture.source_anchor).unwrap(),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
        destination: RecoveryFilesystemAnchor::certify(
            rustix::io::dup(&fixture.destination_anchor).unwrap(),
            fixture.filesystem_id.clone(),
        )
        .unwrap(),
    }
}

#[test]
fn inode_reuse_or_changed_incarnation_never_rebinds() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let actual = fixture.metadata.root_identity();
    let wrong = StrongObjectIdentity::new_with_mount(
        actual.device(),
        actual.inode(),
        ObjectIncarnation::new(actual.incarnation().get().wrapping_add(1)),
        actual.mount_id(),
    );
    let metadata = StagingTransactionMetadata::new(
        fixture.metadata.source_parent().clone(),
        fixture.metadata.source_parent_identity(),
        fixture.metadata.source_basename().to_os_string(),
        wrong,
        fixture.metadata.destination_parent().clone(),
        fixture.metadata.destination_parent_identity(),
        fixture.metadata.destination_basename().to_os_string(),
        fixture.backend,
        DurableSourceParentStrategy::PermissionSeal,
    )
    .unwrap();
    let result = rebind_work(
        &metadata,
        None,
        None,
        RecoveryWork::RestoreBeforeRename {
            transaction: TransactionId([1; 16]),
            permissions: vec![],
        },
        &anchors(&fixture),
    );
    assert!(matches!(result, Err(RecoveryRebindError::BindingChanged)));
}

#[test]
fn mount_id_is_part_of_strong_identity_even_when_other_fields_match() {
    let a = StrongObjectIdentity::new_with_mount(7, 9, ObjectIncarnation::new(11), 13);
    let b = StrongObjectIdentity::new_with_mount(7, 9, ObjectIncarnation::new(11), 14);
    assert_ne!(a, b);
}

#[test]
fn staging_metadata_rejects_durable_mount_mismatch() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let destination = fixture.metadata.destination_parent_identity();
    let drifted = StrongObjectIdentity::new_with_mount(
        destination.device(),
        destination.inode(),
        destination.incarnation(),
        destination.mount_id().wrapping_add(1),
    );
    assert!(
        StagingTransactionMetadata::new(
            fixture.metadata.source_parent().clone(),
            fixture.metadata.source_parent_identity(),
            fixture.metadata.source_basename().to_os_string(),
            fixture.metadata.root_identity(),
            fixture.metadata.destination_parent().clone(),
            drifted,
            fixture.metadata.destination_basename().to_os_string(),
            fixture.backend,
            DurableSourceParentStrategy::PermissionSeal,
        )
        .is_none()
    );
}

#[test]
fn exact_name_replacement_is_rejected_even_on_same_backend() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let source = fixture.base.as_path().join("source");
    fs::rename(source.join("root"), source.join("old-root")).unwrap();
    fs::create_dir(source.join("root")).unwrap();
    let result = rebind_work(
        &fixture.metadata,
        None,
        None,
        RecoveryWork::RestoreBeforeRename {
            transaction: TransactionId([2; 16]),
            permissions: vec![],
        },
        &anchors(&fixture),
    );
    assert!(matches!(result, Err(RecoveryRebindError::BindingChanged)));
}

#[test]
fn capability_rechecks_name_immediately_before_use() {
    let Some(fixture) = fixture(true) else {
        return;
    };
    let rebound = rebind_work(
        &fixture.metadata,
        None,
        None,
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: TransactionId([3; 16]),
            permissions: vec![],
        },
        &anchors(&fixture),
    )
    .unwrap();
    let ReboundWork::VerifyStaged(staged) = rebound else {
        panic!("expected staged capability");
    };
    let destination = fixture.base.as_path().join("destination");
    fs::rename(destination.join("staged"), destination.join("old-staged")).unwrap();
    fs::create_dir(destination.join("staged")).unwrap();
    assert!(matches!(
        staged.root.verify_fresh_binding(),
        Err(RecoveryRebindError::BindingChanged)
    ));
}

#[test]
fn recovery_capability_rechecks_final_namespace_controller_exclusivity() {
    let Some(fixture) = fixture(true) else {
        return;
    };
    let rebound = rebind_work(
        &fixture.metadata,
        None,
        None,
        RecoveryWork::VerifyOrQuarantineAfterRename {
            transaction: TransactionId([0xbc; 16]),
            permissions: vec![],
        },
        &anchors(&fixture),
    )
    .unwrap();
    let ReboundWork::VerifyStaged(staged) = rebound else {
        panic!("expected staged capability");
    };
    fs::set_permissions(
        fixture.base.as_path().join("destination"),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    assert!(matches!(
        staged.root.verify_fresh_binding(),
        Err(RecoveryRebindError::LocatorControllerNotExclusive)
    ));
}

#[test]
fn recovery_rebind_rejects_writable_anchor_controller() {
    let Some(fixture) = fixture(true) else {
        return;
    };
    fs::set_permissions(fixture.base.as_path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        rebind_work(
            &fixture.metadata,
            None,
            None,
            RecoveryWork::VerifyOrQuarantineAfterRename {
                transaction: TransactionId([0xbd; 16]),
                permissions: vec![],
            },
            &anchors(&fixture),
        ),
        Err(RecoveryRebindError::LocatorControllerNotExclusive)
    ));
}

#[test]
fn caller_supplied_filesystem_label_cannot_replace_kernel_fsid() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    assert!(matches!(
        RecoveryFilesystemAnchor::certify(
            rustix::io::dup(&fixture.source_anchor).unwrap(),
            "invented-fsid".into(),
        ),
        Err(RecoveryRebindError::FilesystemChanged)
    ));
}

#[test]
fn mount_drift_between_authenticated_anchors_fails_closed() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let mut anchors = anchors(&fixture);
    anchors.destination.mount_key = anchors.destination.mount_key.wrapping_add(1);
    assert!(matches!(
        validate_anchors(&fixture.metadata, &anchors),
        Err(RecoveryRebindError::MountChanged)
    ));
}

fn permission_for_directory(
    fixture: &Fixture,
    path: &Path,
    relative_path: &str,
) -> DurablePermission {
    let identity = strong_identity_fd(&open_dir(path)).unwrap();
    DurablePermission {
        mutation_id: 1,
        phase: TransactionState::TreeSealIntent,
        evidence: PersistentRecoveryEvidence::new(
            PathBuf::from(relative_path),
            Some(fixture.filesystem_id.clone()),
            identity.device(),
            identity.inode(),
            Some(identity.incarnation().get()),
            0o700,
        )
        .unwrap(),
        pre_mode: 0o700,
        expected_mode: 0o700,
        reverses_mutation_id: None,
        application: ApplicationStatus::Applied,
    }
}

#[test]
fn build_permission_plan_rejects_group_writable_intermediate_ancestor_in_three_level_path() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let root = fixture.base.join("source/root");
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    let permission = permission_for_directory(&fixture, &child, "source/root/child");
    let recovery_anchors = anchors(&fixture);

    assert!(matches!(
        build_permission_plan(
            &recovery_anchors.source,
            RecoveryAnchorSide::Source,
            PathBuf::from("source/root/child"),
            permission,
            0o700,
            &fixture.metadata,
        ),
        Err(RecoveryRebindError::LocatorControllerNotExclusive)
    ));
}

#[test]
fn reopen_permission_plan_rejects_group_writable_intermediate_ancestor_in_three_level_path() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let root = fixture.base.join("source/root");
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let permission = permission_for_directory(&fixture, &child, "source/root/child");
    let recovery_anchors = anchors(&fixture);
    let plan = build_permission_plan(
        &recovery_anchors.source,
        RecoveryAnchorSide::Source,
        PathBuf::from("source/root/child"),
        permission,
        0o700,
        &fixture.metadata,
    )
    .unwrap();

    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        reopen_permission_plan(&recovery_anchors.source, &plan, &fixture.metadata),
        Err(RecoveryRebindError::LocatorControllerNotExclusive)
    ));
}

#[test]
fn unknown_rename_outcome_forbids_all_source_destination_lookup() {
    assert!(recovery_lookup_is_forbidden(
        &RecoveryWork::RecoveryRequired {
            transaction: TransactionId([4; 16]),
            reason: RecoveryRequiredReason::RenameOutcomeUnknown,
        }
    ));
    assert!(!recovery_lookup_is_forbidden(
        &RecoveryWork::RestoreBeforeRename {
            transaction: TransactionId([4; 16]),
            permissions: vec![],
        }
    ));
}

#[test]
fn uncertain_staging_intent_resolves_before_after_and_at_fresh_resolution() {
    for physical_outcome in 0_u8..3 {
        let physically_applied = physical_outcome == 1;
        let change_after_certification = physical_outcome == 2;
        let Some(fixture) = fixture(false) else {
            return;
        };
        let source_path = fixture.base.as_path().join("source");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o770)).unwrap();
        let wal_temp = crate::secure_test_tempdir().unwrap();
        let store = SealWalStore::open_or_create(
            &wal_temp.path().canonicalize().unwrap().join("wal-store"),
        )
        .unwrap();
        let transaction = TransactionId([0xb0 + physical_outcome; 16]);
        let mut lease = store.try_lease().unwrap();
        lease.replay_and_repair().unwrap();
        let mut wal = lease.resume().unwrap();
        wal.begin_staging(transaction, fixture.metadata.clone())
            .unwrap();
        wal.transition_staging_for_test(transaction, TransactionState::ParentSealIntent)
            .unwrap();
        let fd = open_dir(&source_path);
        let result = wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 1,
                evidence: PersistentRecoveryEvidence::new(
                    PathBuf::from("source"),
                    Some(fixture.filesystem_id.clone()),
                    fixture.metadata.source_parent_identity().device(),
                    fixture.metadata.source_parent_identity().inode(),
                    Some(
                        fixture
                            .metadata
                            .source_parent_identity()
                            .incarnation()
                            .get(),
                    ),
                    0o750,
                )
                .unwrap(),
                pre_mode: 0o770,
                expected_mode: 0o750,
                reverses_mutation_id: None,
            },
            || {
                if physically_applied {
                    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o750)).map_err(io::Error::from)?;
                }
                Err(io::Error::other("simulated crash before applied record"))
            },
        );
        assert!(matches!(
            result,
            Err(crate::seal::wal::MutationAppendError::Mutation(_))
        ));
        drop(wal);

        let mut lease = store.try_lease().unwrap();
        lease.replay_and_repair().unwrap();
        let mut wal = lease.resume().unwrap();
        if change_after_certification {
            let delayed_fd = open_dir(&source_path);
            BEFORE_PERMISSION_RESOLUTION.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    rustix::fs::fchmod(&delayed_fd, Mode::from_raw_mode(0o750)).unwrap();
                }));
            });
        }
        let sidecars = store.tree_sidecar_store().unwrap();
        let mut startup_blocked = true;
        let capability = prepare_startup_recovery(
            &mut wal,
            &sidecars,
            &mut startup_blocked,
            transaction,
            anchors(&fixture),
        )
        .unwrap();
        let StartupRecoveryCapability::Restore(restore) = capability else {
            panic!("uncertainty must continue into exact restore");
        };
        restore.execute().unwrap();
        let snapshot = wal.recovery_snapshot(transaction).unwrap();
        assert_eq!(snapshot.state, TransactionState::Restored);
        assert_eq!(
            snapshot.permissions[0].application,
            if physically_applied || change_after_certification {
                ApplicationStatus::Applied
            } else {
                ApplicationStatus::ConfirmedNotApplied
            }
        );
        assert_eq!(
            snapshot
                .permissions
                .iter()
                .filter(|permission| permission.reverses_mutation_id.is_some())
                .count(),
            usize::from(physically_applied || change_after_certification)
        );
        assert_eq!(
            fs::metadata(&source_path).unwrap().permissions().mode() & 0o7777,
            0o770
        );
        assert!(!startup_blocked);
    }
}

#[test]
fn uncertain_inverse_intents_resolve_before_and_after_fchmod_in_every_restore_phase() {
    #[derive(Clone, Copy)]
    enum Case {
        RestoreTree,
        SourceParentRestore,
        QuarantinedParent,
        QuarantinedTree,
    }
    for (case_index, case) in [
        Case::RestoreTree,
        Case::SourceParentRestore,
        Case::QuarantinedParent,
        Case::QuarantinedTree,
    ]
    .into_iter()
    .enumerate()
    {
        for physical_outcome in 0_u8..4 {
            if physical_outcome == 2 && !matches!(case, Case::QuarantinedParent) {
                continue;
            }
            if physical_outcome == 3 && !matches!(case, Case::QuarantinedTree) {
                continue;
            }
            let physically_applied = physical_outcome == 1;
            let Some(fixture) = fixture(false) else {
                return;
            };
            let source_path = fixture.base.as_path().join("source");
            let root_path = source_path.join("root");
            let staged_path = fixture.base.as_path().join("destination/staged");
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o770)).unwrap();
            fs::set_permissions(&root_path, fs::Permissions::from_mode(0o770)).unwrap();
            let wal_temp = crate::secure_test_tempdir().unwrap();
            let store = SealWalStore::open_or_create(
                &wal_temp.path().canonicalize().unwrap().join("wal-store"),
            )
            .unwrap();
            let transaction = TransactionId([0xd0 + case_index as u8 * 3 + physical_outcome; 16]);
            let mut lease = store.try_lease().unwrap();
            lease.replay_and_repair().unwrap();
            let mut wal = lease.resume().unwrap();
            wal.begin_staging(transaction, fixture.metadata.clone())
                .unwrap();
            wal.transition_staging_for_test(transaction, TransactionState::ParentSealIntent)
                .unwrap();
            let source_fd = open_dir(&source_path);
            wal.apply_staging_permission_mutation(
                PermissionIntent {
                    transaction,
                    mutation_id: 1,
                    evidence: PersistentRecoveryEvidence::new(
                        PathBuf::from("source"),
                        Some(fixture.filesystem_id.clone()),
                        fixture.metadata.source_parent_identity().device(),
                        fixture.metadata.source_parent_identity().inode(),
                        Some(
                            fixture
                                .metadata
                                .source_parent_identity()
                                .incarnation()
                                .get(),
                        ),
                        0o750,
                    )
                    .unwrap(),
                    pre_mode: 0o770,
                    expected_mode: 0o750,
                    reverses_mutation_id: None,
                },
                || {
                    rustix::fs::fchmod(&source_fd, Mode::from_raw_mode(0o750))
                        .map_err(io::Error::from)
                },
            )
            .unwrap();
            wal.transition_staging_for_test(transaction, TransactionState::ParentSealed)
                .unwrap();
            wal.transition_staging_for_test(transaction, TransactionState::TreeSealIntent)
                .unwrap();
            let needs_tree = matches!(case, Case::RestoreTree | Case::QuarantinedTree);
            if needs_tree {
                let root_fd = open_dir(&root_path);
                wal.apply_staging_permission_mutation(
                    PermissionIntent {
                        transaction,
                        mutation_id: 2,
                        evidence: PersistentRecoveryEvidence::new(
                            PathBuf::from("source/root"),
                            Some(fixture.filesystem_id.clone()),
                            fixture.metadata.root_identity().device(),
                            fixture.metadata.root_identity().inode(),
                            Some(fixture.metadata.root_identity().incarnation().get()),
                            0o750,
                        )
                        .unwrap(),
                        pre_mode: 0o770,
                        expected_mode: 0o750,
                        reverses_mutation_id: None,
                    },
                    || {
                        rustix::fs::fchmod(&root_fd, Mode::from_raw_mode(0o750))
                            .map_err(io::Error::from)
                    },
                )
                .unwrap();
            }
            wal.complete_tree_manifest(
                transaction,
                DurableTreeManifest {
                    schema_version: 3,
                    entry_count: 1,
                    sha256: [case_index as u8; 32],
                },
            )
            .unwrap();
            wal.transition_staging_for_test(transaction, TransactionState::TreeSealed)
                .unwrap();
            let (phase, original_id, inverse_path, inverse_identity) = match case {
                Case::RestoreTree => (
                    TransactionState::RestoreIntent,
                    2,
                    root_path.clone(),
                    fixture.metadata.root_identity(),
                ),
                Case::SourceParentRestore | Case::QuarantinedParent | Case::QuarantinedTree => {
                    wal.record_rename_intent(transaction).unwrap();
                    fs::rename(&root_path, &staged_path).unwrap();
                    wal.record_applied_rename_for_test(transaction).unwrap();
                    wal.transition_staging_for_test(
                        transaction,
                        TransactionState::StagedUnverified,
                    )
                    .unwrap();
                    match case {
                        Case::SourceParentRestore => {
                            wal.transition_staging_for_test(
                                transaction,
                                TransactionState::StagedSealed,
                            )
                            .unwrap();
                            wal.transition_staging_for_test(
                                transaction,
                                TransactionState::SourceParentRestoreIntent,
                            )
                            .unwrap();
                            (
                                TransactionState::SourceParentRestoreIntent,
                                1,
                                source_path.clone(),
                                fixture.metadata.source_parent_identity(),
                            )
                        }
                        Case::QuarantinedParent => {
                            wal.transition_staging_for_test(
                                transaction,
                                TransactionState::Quarantined,
                            )
                            .unwrap();
                            (
                                TransactionState::Quarantined,
                                1,
                                source_path.clone(),
                                fixture.metadata.source_parent_identity(),
                            )
                        }
                        Case::QuarantinedTree => {
                            wal.transition_staging_for_test(
                                transaction,
                                TransactionState::Quarantined,
                            )
                            .unwrap();
                            (
                                TransactionState::Quarantined,
                                2,
                                staged_path.clone(),
                                fixture.metadata.root_identity(),
                            )
                        }
                        Case::RestoreTree => unreachable!(),
                    }
                }
            };
            if phase == TransactionState::RestoreIntent {
                wal.transition_staging_for_test(transaction, phase).unwrap();
            }
            let inverse_relative = if matches!(case, Case::QuarantinedTree) {
                PathBuf::from("destination/staged")
            } else if original_id == 1 {
                PathBuf::from("source")
            } else {
                PathBuf::from("source/root")
            };
            let inverse_fd = open_dir(&inverse_path);
            let result = wal.apply_staging_permission_mutation(
                PermissionIntent {
                    transaction,
                    mutation_id: 3,
                    evidence: PersistentRecoveryEvidence::new(
                        inverse_relative,
                        Some(fixture.filesystem_id.clone()),
                        inverse_identity.device(),
                        inverse_identity.inode(),
                        Some(inverse_identity.incarnation().get()),
                        0o770,
                    )
                    .unwrap(),
                    pre_mode: 0o750,
                    expected_mode: 0o770,
                    reverses_mutation_id: Some(original_id),
                },
                || {
                    if physically_applied {
                        rustix::fs::fchmod(&inverse_fd, Mode::from_raw_mode(0o770))
                            .map_err(io::Error::from)?;
                    }
                    Err(io::Error::other("simulated inverse crash"))
                },
            );
            assert!(matches!(
                result,
                Err(crate::seal::wal::MutationAppendError::Mutation(_))
            ));
            drop(wal);

            let mut lease = store.try_lease().unwrap();
            lease.replay_and_repair().unwrap();
            let mut wal = lease.resume().unwrap();
            if matches!(physical_outcome, 2 | 3) {
                let delayed_fd = open_dir(&inverse_path);
                BEFORE_PERMISSION_RESOLUTION.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        let mode = if physical_outcome == 2 { 0o700 } else { 0o770 };
                        rustix::fs::fchmod(&delayed_fd, Mode::from_raw_mode(mode)).unwrap();
                    }));
                });
            }
            if physical_outcome == 2 {
                let sidecars = store.tree_sidecar_store().unwrap();
                let mut startup_blocked = true;
                assert!(matches!(
                    prepare_startup_recovery(
                        &mut wal,
                        &sidecars,
                        &mut startup_blocked,
                        transaction,
                        anchors(&fixture),
                    ),
                    Err(RecoveryRebindError::Resolution(ResolveError::Recovery(_)))
                ));
                assert_eq!(
                    wal.transaction_state(transaction),
                    Some(TransactionState::RecoveryRequired)
                );
                continue;
            }
            let snapshot = wal.recovery_snapshot(transaction).unwrap();
            let RecoveryWork::ResolveUncertainPermissions { permissions, .. } =
                decide_recovery(&snapshot, |_| RecoveryIdentity::Reestablished)
            else {
                panic!("inverse intent must remain uncertain after crash");
            };
            resolve_uncertain_permissions(
                &mut wal,
                transaction,
                &fixture.metadata,
                &anchors(&fixture),
                permissions,
            )
            .unwrap();
            let resolved = wal
                .recovery_snapshot(transaction)
                .unwrap()
                .permissions
                .into_iter()
                .find(|permission| permission.mutation_id == 3)
                .unwrap();
            assert_eq!(
                resolved.application,
                if physically_applied || physical_outcome == 3 {
                    ApplicationStatus::Applied
                } else {
                    ApplicationStatus::ConfirmedNotApplied
                }
            );
        }
    }
}

#[test]
fn exact_staging_snapshot_restores_all_applied_permissions_and_reaches_restored() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let source_path = fixture.base.as_path().join("source");
    let root_path = source_path.join("root");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o770)).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o770)).unwrap();

    let wal_temp = crate::secure_test_tempdir().unwrap();
    let store_path = wal_temp.path().canonicalize().unwrap().join("wal-store");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let transaction = TransactionId([0xa3; 16]);
    let mut lease = store.try_lease().unwrap();
    lease.replay_and_repair().unwrap();
    let mut wal = lease.resume().unwrap();
    wal.begin_staging(transaction, fixture.metadata.clone())
        .unwrap();

    let apply_original = |wal: &mut SealWal<RecoverySession>,
                          mutation_id,
                          phase,
                          path: &Path,
                          relative_path: &str,
                          identity: StrongObjectIdentity| {
        wal.transition_staging_for_test(transaction, phase).unwrap();
        let fd = open_dir(path);
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id,
                evidence: PersistentRecoveryEvidence::new(
                    PathBuf::from(relative_path),
                    Some(fixture.filesystem_id.clone()),
                    identity.device(),
                    identity.inode(),
                    Some(identity.incarnation().get()),
                    0o750,
                )
                .unwrap(),
                pre_mode: 0o770,
                expected_mode: 0o750,
                reverses_mutation_id: None,
            },
            || rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o750)).map_err(io::Error::from),
        )
        .unwrap();
    };
    apply_original(
        &mut wal,
        1,
        TransactionState::ParentSealIntent,
        &source_path,
        "source",
        fixture.metadata.source_parent_identity(),
    );
    wal.transition_staging_for_test(transaction, TransactionState::ParentSealed)
        .unwrap();
    apply_original(
        &mut wal,
        2,
        TransactionState::TreeSealIntent,
        &root_path,
        "source/root",
        fixture.metadata.root_identity(),
    );
    wal.complete_tree_manifest(
        transaction,
        DurableTreeManifest {
            schema_version: 3,
            entry_count: 1,
            sha256: [0xa3; 32],
        },
    )
    .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealed)
        .unwrap();

    // Simulate process death: discard every live seal token and rebuild the
    // exact transaction only from replay under a newly acquired WAL lease.
    drop(wal);
    let mut lease = store.try_lease().unwrap();
    lease.replay_and_repair().unwrap();
    let mut wal = lease.resume().unwrap();
    let sidecars = store.tree_sidecar_store().unwrap();
    let mut startup_blocked = true;
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::Restore(restore) = capability else {
        panic!("expected exact restore capability");
    };
    restore.execute().unwrap();

    assert_eq!(
        fs::metadata(&root_path).unwrap().permissions().mode() & 0o7777,
        0o770
    );
    assert_eq!(
        fs::metadata(&source_path).unwrap().permissions().mode() & 0o7777,
        0o770
    );
    let snapshot = wal.recovery_snapshot(transaction).unwrap();
    assert_eq!(snapshot.state, TransactionState::Restored);
    assert!(!startup_blocked);
    assert_eq!(snapshot.permissions.len(), 4);
    assert_eq!(
        snapshot
            .permissions
            .iter()
            .filter(|permission| permission.reverses_mutation_id.is_some())
            .count(),
        2
    );
}

#[test]
fn quarantined_active_seals_restore_in_place_and_unblock_without_unquarantining() {
    let Some(fixture) = fixture(true) else {
        return;
    };
    let source_path = fixture.base.as_path().join("source");
    let staged_path = fixture.base.as_path().join("destination/staged");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o770)).unwrap();
    fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o770)).unwrap();
    let wal_temp = crate::secure_test_tempdir().unwrap();
    let store =
        SealWalStore::open_or_create(&wal_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let transaction = TransactionId([0xd4; 16]);
    let mut lease = store.try_lease().unwrap();
    lease.replay_and_repair().unwrap();
    let mut wal = lease.resume().unwrap();
    wal.begin_staging(transaction, fixture.metadata.clone())
        .unwrap();
    for (phase, mutation_id, path, relative, identity) in [
        (
            TransactionState::ParentSealIntent,
            1,
            source_path.as_path(),
            "source",
            fixture.metadata.source_parent_identity(),
        ),
        (
            TransactionState::TreeSealIntent,
            2,
            staged_path.as_path(),
            "source/root",
            fixture.metadata.root_identity(),
        ),
    ] {
        if phase == TransactionState::TreeSealIntent {
            wal.transition_staging_for_test(transaction, TransactionState::ParentSealed)
                .unwrap();
        }
        wal.transition_staging_for_test(transaction, phase).unwrap();
        let fd = open_dir(path);
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id,
                evidence: PersistentRecoveryEvidence::new(
                    PathBuf::from(relative),
                    Some(fixture.filesystem_id.clone()),
                    identity.device(),
                    identity.inode(),
                    Some(identity.incarnation().get()),
                    0o750,
                )
                .unwrap(),
                pre_mode: 0o770,
                expected_mode: 0o750,
                reverses_mutation_id: None,
            },
            || rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o750)).map_err(io::Error::from),
        )
        .unwrap();
    }
    wal.complete_tree_manifest(
        transaction,
        DurableTreeManifest {
            schema_version: 3,
            entry_count: 1,
            sha256: [0xd4; 32],
        },
    )
    .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealed)
        .unwrap();
    wal.record_rename_intent(transaction).unwrap();
    wal.record_applied_rename_for_test(transaction).unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::StagedUnverified)
        .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::Quarantined)
        .unwrap();

    let sidecars = store.tree_sidecar_store().unwrap();
    let mut startup_blocked = true;
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::Restore(restore) = capability else {
        panic!("expected quarantine seal restore");
    };
    restore.execute().unwrap();
    let snapshot = wal.recovery_snapshot(transaction).unwrap();
    assert_eq!(snapshot.state, TransactionState::Quarantined);
    assert!(!crate::seal::wal::quarantined_transaction_retains_active_permission_seals(&snapshot));
    assert!(!startup_blocked);
    assert_eq!(
        fs::metadata(source_path).unwrap().permissions().mode() & 0o7777,
        0o770
    );
    assert_eq!(
        fs::metadata(staged_path).unwrap().permissions().mode() & 0o7777,
        0o770
    );
}

#[test]
fn unknown_rename_is_durably_blocked_without_any_namespace_lookup() {
    let Some(fixture) = fixture(false) else {
        return;
    };
    let wal_temp = crate::secure_test_tempdir().unwrap();
    let store =
        SealWalStore::open_or_create(&wal_temp.path().canonicalize().unwrap().join("wal-store"))
            .unwrap();
    let transaction = TransactionId([0xc3; 16]);
    let mut lease = store.try_lease().unwrap();
    lease.replay_and_repair().unwrap();
    let mut wal = lease.resume().unwrap();
    wal.begin_staging(transaction, fixture.metadata.clone())
        .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    wal.apply_staging_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: PersistentRecoveryEvidence::new(
                PathBuf::from("source"),
                Some(fixture.filesystem_id.clone()),
                fixture.metadata.source_parent_identity().device(),
                fixture.metadata.source_parent_identity().inode(),
                Some(
                    fixture
                        .metadata
                        .source_parent_identity()
                        .incarnation()
                        .get(),
                ),
                0o500,
            )
            .unwrap(),
            pre_mode: 0o700,
            expected_mode: 0o500,
            reverses_mutation_id: None,
        },
        || Ok(()),
    )
    .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::ParentSealed)
        .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealIntent)
        .unwrap();
    wal.complete_tree_manifest(
        transaction,
        DurableTreeManifest {
            schema_version: 3,
            entry_count: 1,
            sha256: [0xc3; 32],
        },
    )
    .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealed)
        .unwrap();
    wal.record_rename_intent(transaction).unwrap();

    RECOVERY_NAME_LOOKUPS.set(0);
    let sidecars = store.tree_sidecar_store().unwrap();
    let mut startup_blocked = true;
    assert!(matches!(
        prepare_startup_recovery(
            &mut wal,
            &sidecars,
            &mut startup_blocked,
            transaction,
            anchors(&fixture),
        ),
        Err(RecoveryRebindError::RenameOutcomeUnknown)
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::RecoveryRequired)
    );
    assert!(matches!(
        prepare_startup_recovery(
            &mut wal,
            &sidecars,
            &mut startup_blocked,
            transaction,
            anchors(&fixture),
        ),
        Err(RecoveryRebindError::RecordedRecoveryRequired)
    ));
    assert_eq!(RECOVERY_NAME_LOOKUPS.get(), 0);
    assert!(startup_blocked);
}

fn staged_pending(
    include_tree_seal: bool,
    manifest_matches: bool,
) -> Option<(
    Fixture,
    TreeSidecarStore,
    SealWal<RecoverySession>,
    bool,
    TransactionId,
)> {
    let fixture = fixture(true)?;
    let transaction = TransactionId([0xa3; 16]);
    let store_path = fixture.base.as_path().join("verifier-wal");
    let store = SealWalStore::open_or_create(&store_path).unwrap();
    let sidecars = store.tree_sidecar_store().unwrap();
    let mut wal = store.try_lease().unwrap().into_new_wal().unwrap();
    wal.begin_staging(transaction, fixture.metadata.clone())
        .unwrap();

    let source = fixture.base.as_path().join("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o770)).unwrap();
    let source_identity = fixture.metadata.source_parent_identity();
    let source_fd = open_dir(&source);
    wal.transition_staging_for_test(transaction, TransactionState::ParentSealIntent)
        .unwrap();
    wal.apply_staging_permission_mutation(
        PermissionIntent {
            transaction,
            mutation_id: 1,
            evidence: PersistentRecoveryEvidence::new(
                PathBuf::from("source"),
                Some(fixture.filesystem_id.clone()),
                source_identity.device(),
                source_identity.inode(),
                Some(source_identity.incarnation().get()),
                0o750,
            )
            .unwrap(),
            pre_mode: 0o770,
            expected_mode: 0o750,
            reverses_mutation_id: None,
        },
        || rustix::fs::fchmod(&source_fd, Mode::from_raw_mode(0o750)).map_err(io::Error::from),
    )
    .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::ParentSealed)
        .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealIntent)
        .unwrap();

    let destination = fixture.base.as_path().join("destination");
    let staged = destination.join("staged");
    let child = staged.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let child_identity = strong_identity_fd(&open_dir(&child)).unwrap();
    let root_identity = fixture.metadata.root_identity();
    if include_tree_seal {
        let root_fd = open_dir(&staged);
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 2,
                evidence: PersistentRecoveryEvidence::new(
                    PathBuf::from("source/root"),
                    Some(fixture.filesystem_id.clone()),
                    root_identity.device(),
                    root_identity.inode(),
                    Some(root_identity.incarnation().get()),
                    0o500,
                )
                .unwrap(),
                pre_mode: 0o700,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || rustix::fs::fchmod(&root_fd, Mode::from_raw_mode(0o500)).map_err(io::Error::from),
        )
        .unwrap();
        let child_fd = open_dir(&child);
        wal.apply_staging_permission_mutation(
            PermissionIntent {
                transaction,
                mutation_id: 3,
                evidence: PersistentRecoveryEvidence::new(
                    PathBuf::from("source/root/child"),
                    Some(fixture.filesystem_id.clone()),
                    child_identity.device(),
                    child_identity.inode(),
                    Some(child_identity.incarnation().get()),
                    0o500,
                )
                .unwrap(),
                pre_mode: 0o700,
                expected_mode: 0o500,
                reverses_mutation_id: None,
            },
            || rustix::fs::fchmod(&child_fd, Mode::from_raw_mode(0o500)).map_err(io::Error::from),
        )
        .unwrap();
    }
    let inventory = HeldTreeInventory::collect_for_schema(
        certify_held_fd(open_dir(&destination)).unwrap(),
        OsStr::new("staged"),
        crate::safety::PROTECTED_DESCENDANT_DIR_NAMES
            .iter()
            .map(OsString::from)
            .collect(),
        HeldTreeLimits::default(),
        3,
    )
    .unwrap();
    let fingerprint = inventory.fingerprint_for_schema(3).unwrap();
    let manifest = DurableTreeManifest {
        schema_version: 3,
        entry_count: fingerprint.entry_count,
        sha256: if manifest_matches {
            fingerprint.sha256
        } else {
            [0x55; 32]
        },
    };
    let commitment = sidecars
        .publish_stream(&mut wal, transaction, |emit| {
            inventory
                .stream_manifest_v3_segments(|record_count, payload| emit(record_count, payload))
                .map_err(|error| match error {
                    ManifestV3StreamError::Codec(_) => {
                        TreeSidecarError::InvalidSegment("test manifest segmentation failed")
                    }
                    ManifestV3StreamError::Emit(error) => error,
                })
        })
        .unwrap();
    wal.complete_tree_manifest_with_sidecar(transaction, manifest, commitment)
        .unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::TreeSealed)
        .unwrap();
    wal.record_rename_intent(transaction).unwrap();
    wal.record_applied_rename_for_test(transaction).unwrap();
    wal.transition_staging_for_test(transaction, TransactionState::StagedUnverified)
        .unwrap();
    Some((fixture, sidecars, wal, true, transaction))
}

#[test]
fn v3_staged_verification_honors_injected_entry_limit() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    let outcome = pending
        .verify_or_quarantine_with_limits(HeldTreeLimits {
            max_entries: 1,
            ..HeldTreeLimits::default()
        })
        .unwrap();
    assert!(matches!(outcome, StagedVerificationOutcome::Quarantined(_)));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // adversarially creates residue and corrupts published proof
fn initial_sidecar_authentication_failure_cleans_prior_recovery_scratch() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    let store = fixture.base.join("verifier-wal");
    let scratch = store.join(format!(
        ".tree-scratch-v1-{}-{}-999999.tmp",
        "a3".repeat(16),
        std::process::id()
    ));
    fs::write(&scratch, b"prior unpublished recovery scratch").unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o600)).unwrap();
    let published = fs::read_dir(&store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("sidecar")))
        .expect("published sidecar must exist");
    let file = fs::OpenOptions::new().write(true).open(published).unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();

    let outcome = pending.verify_or_quarantine().unwrap();
    assert!(matches!(
        outcome,
        StagedVerificationOutcome::Quarantined(StagedVerificationFailure::Rebind(
            RecoveryRebindError::Sidecar(_)
        ))
    ));
    assert!(
        !scratch.exists(),
        "initial auth failure leaked prior scratch"
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // adversarially corrupts private scratch and published proof
fn published_sidecar_integrity_precedes_recovery_scratch_failure_and_cleans_runs() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    let store = fixture.base.join("verifier-wal");
    let hook_store = store.clone();
    stream_v3::install_after_manifest_scratch_build_test_hook(move || {
        let mut scratch = None;
        let mut published = None;
        for entry in fs::read_dir(&hook_store).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with(".tree-scratch-v1-") {
                scratch = Some(path);
            } else if path.extension() == Some(OsStr::new("sidecar")) {
                published = Some(path);
            }
        }
        for path in [
            scratch.expect("manifest scratch must exist at the test hook"),
            published.expect("published sidecar must exist at the test hook"),
        ] {
            let file = fs::OpenOptions::new().write(true).open(path).unwrap();
            file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        }
    });
    let outcome = pending.verify_or_quarantine().unwrap();
    assert!(matches!(
        outcome,
        StagedVerificationOutcome::Quarantined(StagedVerificationFailure::Rebind(
            RecoveryRebindError::Sidecar(_)
        ))
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
    assert!(
        fs::read_dir(store)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .all(|name| !name.to_string_lossy().starts_with(".tree-scratch-v1-")),
        "failed recovery verification must not leak unpublished scratch runs"
    );
}

#[test]
fn pending_verification_consumes_exact_tree_and_stops_at_staged_sealed() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    let StagedVerificationOutcome::StagedSealed(verified) = pending.verify_or_quarantine().unwrap()
    else {
        panic!("matching staged tree must verify");
    };
    assert_eq!(verified.transaction(), transaction);
    assert_eq!(verified.wal_state(), Some(TransactionState::StagedSealed));
    assert!(verified.startup_is_blocked());
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::StagedSealed)
    );
    assert!(startup_blocked);
}

#[test]
fn dropping_pending_before_transition_replays_staged_unverified() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    assert!(matches!(
        capability,
        StartupRecoveryCapability::PendingVerification(_)
    ));
    drop(capability);
    drop(wal);

    let store = SealWalStore::open_or_create(&fixture.base.as_path().join("verifier-wal")).unwrap();
    let (reopened, report) = crate::staging::SealedStagingEngine::open(&store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(
        reopened.state(transaction),
        Some(TransactionState::StagedUnverified)
    );
}

#[test]
fn durable_staged_sealed_replays_without_commit_promotion() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    let outcome = pending.verify_or_quarantine().unwrap();
    assert!(matches!(
        outcome,
        StagedVerificationOutcome::StagedSealed(_)
    ));
    drop(wal);

    let store = SealWalStore::open_or_create(&fixture.base.as_path().join("verifier-wal")).unwrap();
    let (reopened, report) = crate::staging::SealedStagingEngine::open(&store).unwrap();
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(
        reopened.state(transaction),
        Some(TransactionState::StagedSealed)
    );
    assert_ne!(
        reopened.state(transaction),
        Some(TransactionState::VerifiedCommitted)
    );
}

#[test]
fn manifest_mismatch_is_durably_quarantined_without_mode_restore() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, false)
    else {
        return;
    };
    let staged = fixture.base.as_path().join("destination/staged");
    let mode_before = fs::metadata(&staged).unwrap().permissions().mode() & 0o7777;
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    assert!(matches!(
        pending.verify_or_quarantine().unwrap(),
        StagedVerificationOutcome::Quarantined(_)
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
    assert_eq!(
        fs::metadata(staged).unwrap().permissions().mode() & 0o7777,
        mode_before
    );
    assert!(startup_blocked);
}

#[test]
fn mode_drift_after_capability_creation_is_durably_quarantined() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    fs::set_permissions(
        fixture.base.as_path().join("destination/staged/child"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(matches!(
        pending.verify_or_quarantine().unwrap(),
        StagedVerificationOutcome::Quarantined(_)
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
}

#[test]
fn added_entry_after_manifest_is_durably_quarantined() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(true, true)
    else {
        return;
    };
    let staged = fixture.base.as_path().join("destination/staged");
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(staged.join("added"), b"late").unwrap();
    // Re-seal so the extra entry is the only divergence from the manifest.
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o500)).unwrap();
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    assert!(matches!(
        pending.verify_or_quarantine().unwrap(),
        StagedVerificationOutcome::Quarantined(_)
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
}

#[test]
fn missing_tree_seal_coverage_is_durably_quarantined() {
    let Some((fixture, sidecars, mut wal, mut startup_blocked, transaction)) =
        staged_pending(false, true)
    else {
        return;
    };
    let capability = prepare_startup_recovery(
        &mut wal,
        &sidecars,
        &mut startup_blocked,
        transaction,
        anchors(&fixture),
    )
    .unwrap();
    let StartupRecoveryCapability::PendingVerification(pending) = capability else {
        panic!("expected pending verification");
    };
    assert!(matches!(
        pending.verify_or_quarantine().unwrap(),
        StagedVerificationOutcome::Quarantined(_)
    ));
    assert_eq!(
        wal.transaction_state(transaction),
        Some(TransactionState::Quarantined)
    );
}

fn permission(id: u64, path: &str) -> DurablePermission {
    DurablePermission {
        mutation_id: id,
        phase: TransactionState::TreeSealIntent,
        evidence: PersistentRecoveryEvidence::new(
            PathBuf::from(path),
            Some("test-fs".into()),
            1,
            id + 10,
            Some(id + 100),
            0o500,
        )
        .unwrap(),
        pre_mode: 0o770,
        expected_mode: 0o500,
        reverses_mutation_id: None,
        application: ApplicationStatus::Applied,
    }
}

#[test]
fn restore_order_is_deepest_first_with_exact_source_parent_last() {
    let mut entries = vec![
        (permission(1, "source/root"), ()),
        (permission(2, "source"), ()),
        (permission(3, "source/root/deep/child"), ()),
        (permission(4, "source/root/deep"), ()),
    ];
    sort_restore_entries(&mut entries, Path::new("source"));
    assert_eq!(
        entries
            .iter()
            .map(|(permission, _)| permission.evidence.relative_path())
            .collect::<Vec<_>>(),
        vec![
            Path::new("source/root/deep/child"),
            Path::new("source/root/deep"),
            Path::new("source/root"),
            Path::new("source"),
        ]
    );
}

#[test]
fn unsupported_or_missing_strong_incarnation_is_not_a_weak_match() {
    assert!(matches!(
        timestamp_incarnation(-1, 0),
        Err(RecoveryRebindError::StrongIdentityUnavailable)
    ));
}

#[test]
fn v11_empty_parent_locator_rebinds_the_authenticated_mount_anchor_itself() {
    let temp = crate::secure_test_tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    let fd = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let filesystem_id = held_filesystem_id(&fd).unwrap();
    let identity = strong_identity_fd(&fd).unwrap();
    let anchor = RecoveryFilesystemAnchor::certify(fd, filesystem_id.clone()).unwrap();
    let locator = StagingLocator::new(PathBuf::new(), filesystem_id).unwrap();
    let rebound = rebind_locator(&anchor, &locator, identity).unwrap();
    assert_eq!(strong_identity_fd(&rebound).unwrap(), identity);
}
