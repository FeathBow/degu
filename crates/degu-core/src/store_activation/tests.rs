use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = crate::secure_test_tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let state = home.join("state/degu");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(home.join("state"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = state.join("sealed-staging");
        Self {
            _temp: temp,
            home,
            store,
        }
    }

    fn authority(&self) -> PathBuf {
        self.home.join(AUTHORITY_DIRECTORY_NAME)
    }
}

#[test]
fn never_activated_support_probe_does_not_create_a_store_or_authority() {
    let fixture = Fixture::new();
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::NeverActivated
    );
    assert!(!fixture.authority().exists());
    assert!(!fixture.store.exists());
}

#[test]
fn absent_authority_reaches_injected_unsupported_support_classification() {
    for reason in [
        CertificationError::UnsupportedPlatform,
        CertificationError::UnsupportedFilesystem,
    ] {
        let fixture = Fixture::new();
        let mut probes = 0;
        let state = discover_store_activation_with_probe(&fixture.home, &fixture.store, |_| {
            probes += 1;
            Err(StoreActivationError::Backend(reason.clone()))
        })
        .unwrap();
        assert_eq!(state.kind(), StoreActivationKind::UnsupportedNeverActivated);
        assert_eq!(probes, 1);
        assert!(!fixture.authority().exists());
        assert!(!fixture.store.exists());
    }
}

#[test]
fn existing_authority_never_consults_unsupported_absence_probe() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let state = discover_store_activation_with_probe(&fixture.home, &fixture.store, |_| {
        panic!("support probe must not run for an existing authority")
    })
    .unwrap();
    assert_eq!(state.kind(), StoreActivationKind::Activated);
}

#[test]
fn authority_publication_during_support_probe_blocks_unsupported_escape() {
    let fixture = Fixture::new();
    let authority = fixture.authority();
    let result = discover_store_activation_with_probe(&fixture.home, &fixture.store, |_| {
        std::fs::create_dir(&authority).unwrap();
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o755)).unwrap();
        Err(StoreActivationError::Backend(
            CertificationError::UnsupportedFilesystem,
        ))
    });
    assert!(matches!(result, Err(StoreActivationError::UnsafeHome(_))));
}

#[cfg(target_os = "linux")]
#[test]
fn real_tmpfs_absence_is_explicitly_unsupported_when_available() {
    let Ok(temp) = tempfile::Builder::new()
        .prefix("degu-activation-unsupported-")
        .tempdir_in("/dev/shm")
    else {
        return;
    };
    let home = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = home.join("state/degu");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(home.join("state"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = state.join("sealed-staging");

    assert_eq!(
        discover_store_activation(&home, &store).unwrap().kind(),
        StoreActivationKind::UnsupportedNeverActivated
    );
    let authority = home.join(AUTHORITY_DIRECTORY_NAME);
    assert!(!authority.exists());
    assert!(!store.exists());

    // Presence flips discovery back onto the strict authority path even though
    // the real filesystem remains unsupported.
    std::fs::create_dir(&authority).unwrap();
    std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(discover_store_activation(&home, &store).is_err());
}

#[test]
fn activation_publishes_private_bidirectional_records() {
    let fixture = Fixture::new();
    let activated = activate_or_resume_store(&fixture.home, &fixture.store).unwrap();
    assert_eq!(activated.locator(), fixture.store);
    drop(activated);

    let authority = fixture.authority();
    let prepare = authority.join(PREPARING_RECORD_NAME);
    let active = authority.join(ACTIVE_RECORD_NAME);
    let binding = fixture.store.join(STORE_BINDING_NAME);
    assert_eq!(
        std::fs::metadata(&authority).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    for record in [&prepare, &active, &binding] {
        let metadata = std::fs::metadata(record).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    assert_eq!(
        std::fs::read(&active).unwrap(),
        std::fs::read(binding).unwrap()
    );
    assert_ne!(
        std::fs::read(&active).unwrap(),
        std::fs::read(&prepare).unwrap()
    );
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}

#[test]
fn durable_prepare_is_distinct_and_resume_ignores_changed_xdg() {
    let fixture = Fixture::new();
    // New authority syncs are 0/1, prepare file is 2, and publication directory
    // sync is 3. The rename has happened when boundary 3 reports uncertainty.
    inject_sync_failure(Some(3));
    assert!(matches!(
        activate_or_resume_store(&fixture.home, &fixture.store),
        Err(StoreActivationError::SyncUncertain("preparing record"))
    ));
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );

    let changed = fixture.home.join("state/degu/changed-store");
    let activated = activate_or_resume_store(&fixture.home, &changed).unwrap();
    assert_eq!(activated.locator(), fixture.store);
    assert!(fixture.store.is_dir());
    assert!(!changed.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss after durable prepare publication
fn store_loss_while_preparing_is_lost_not_recreated() {
    let fixture = Fixture::new();
    inject_sync_failure(Some(3));
    assert!(activate_or_resume_store(&fixture.home, &fixture.store).is_err());
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );
    std::fs::remove_dir_all(&fixture.store).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(matches!(
        activate_or_resume_store(&fixture.home, &fixture.store),
        Err(StoreActivationError::NotResumable)
    ));
    assert!(!fixture.store.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol whole-store loss
fn whole_store_loss_is_never_reinitialized() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_dir_all(&fixture.store).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(!fixture.store.exists());
    assert!(matches!(
        activate_or_resume_store(&fixture.home, &fixture.store),
        Err(StoreActivationError::NotResumable)
    ));
    assert!(!fixture.store.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss of the locator ancestor
fn missing_store_ancestor_is_structured_lost() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_dir_all(fixture.home.join("state/degu")).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss plus environment drift
fn xdg_drift_cannot_rediscover_a_new_empty_store() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_dir_all(&fixture.store).unwrap();
    let changed = fixture.home.join("state/degu/new-xdg-store");
    drop(SealWalStore::open_or_create(&changed).unwrap());

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(changed.join(crate::seal_store::WAL_FILE_NAME).is_file());
}

#[test]
fn exact_store_replacement_is_corrupt_or_replaced() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let old = fixture.home.join("state/degu/old-store");
    std::fs::rename(&fixture.store, &old).unwrap();
    drop(SealWalStore::open_or_create(&fixture.store).unwrap());

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn missing_or_changed_reciprocal_binding_is_corrupt() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::write(fixture.store.join(STORE_BINDING_NAME), b"wrong").unwrap();
    std::fs::set_permissions(
        fixture.store.join(STORE_BINDING_NAME),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn active_record_symlink_is_never_followed() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let active = fixture.authority().join(ACTIVE_RECORD_NAME);
    let saved = fixture.authority().join("saved-active");
    std::fs::rename(&active, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &active).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn unsafe_home_and_authority_modes_fail_closed() {
    let fixture = Fixture::new();
    std::fs::set_permissions(&fixture.home, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        discover_store_activation(&fixture.home, &fixture.store),
        Err(StoreActivationError::UnsafeHome(_))
    ));

    std::fs::set_permissions(&fixture.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::set_permissions(fixture.authority(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(discover_store_activation(&fixture.home, &fixture.store).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn authority_acl_drift_fails_closed() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(fixture.authority())
        .status()
        .unwrap();
    assert!(status.success());

    assert!(discover_store_activation(&fixture.home, &fixture.store).is_err());
}

#[test]
fn home_is_fsynced_on_every_authority_open_and_retry() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());

    // For an existing authority, HOME validation is the first activation-owned
    // sync. A failed attempt must not let retry skip that same boundary.
    inject_sync_failure(Some(0));
    assert!(matches!(
        discover_store_activation(&fixture.home, &fixture.store),
        Err(StoreActivationError::SyncUncertain(
            "HOME after authority validation"
        ))
    ));
    inject_sync_failure(Some(0));
    assert!(discover_store_activation(&fixture.home, &fixture.store).is_err());
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}

#[test]
fn every_activation_sync_boundary_fail_before_and_after_converges() {
    let baseline = Fixture::new();
    inject_sync_failure(None);
    drop(activate_or_resume_store(&baseline.home, &baseline.store).unwrap());
    let boundaries = SYNC_COUNT.with(std::cell::Cell::get);
    assert!(
        boundaries >= 8,
        "unexpectedly weak sync protocol: {boundaries}"
    );

    for after in [false, true] {
        for boundary in 0..boundaries {
            let fixture = Fixture::new();
            if after {
                inject_sync_failure_after(boundary);
            } else {
                inject_sync_failure(Some(boundary));
            }
            let first = activate_or_resume_store(&fixture.home, &fixture.store);
            assert!(
                first.is_err(),
                "boundary {boundary}, after={after} did not inject"
            );
            inject_sync_failure(None);
            let state = discover_store_activation(&fixture.home, &fixture.store).unwrap();
            assert_ne!(state.kind(), StoreActivationKind::Lost);
            assert_ne!(state.kind(), StoreActivationKind::CorruptOrReplaced);
            drop(state);
            let activated = activate_or_resume_store(&fixture.home, &fixture.store).unwrap();
            assert_eq!(activated.locator(), fixture.store);
            drop(activated);
            assert_eq!(
                discover_store_activation(&fixture.home, &fixture.store)
                    .unwrap()
                    .kind(),
                StoreActivationKind::Activated,
                "boundary {boundary}, after={after} did not converge"
            );
        }
    }
    inject_sync_failure(None);
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss of one redundant record
fn missing_active_recovers_from_permanent_prepare_without_xdg_recreation() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_file(fixture.authority().join(ACTIVE_RECORD_NAME)).unwrap();

    let changed = fixture.home.join("state/degu/changed-after-active-loss");
    assert_eq!(
        discover_store_activation(&fixture.home, &changed)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );
    let recovered = activate_or_resume_store(&fixture.home, &changed).unwrap();
    assert_eq!(recovered.locator(), fixture.store);
    assert!(!changed.exists());
    assert!(fixture.authority().join(PREPARING_RECORD_NAME).is_file());
    assert!(fixture.authority().join(ACTIVE_RECORD_NAME).is_file());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol record tampering
fn authority_record_hardlink_mode_and_directory_tampering_are_corrupt() {
    for tamper in 0..3 {
        let fixture = Fixture::new();
        drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
        let active = fixture.authority().join(ACTIVE_RECORD_NAME);
        match tamper {
            0 => {
                std::fs::hard_link(&active, fixture.authority().join("active-hardlink")).unwrap();
            }
            1 => {
                std::fs::set_permissions(&active, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
            2 => {
                std::fs::remove_file(&active).unwrap();
                std::fs::create_dir(&active).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            discover_store_activation(&fixture.home, &fixture.store)
                .unwrap()
                .kind(),
            StoreActivationKind::CorruptOrReplaced,
            "tamper case {tamper}"
        );
    }
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol record loss
fn missing_reciprocal_record_is_corrupt() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_file(fixture.store.join(STORE_BINDING_NAME)).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol record loss
fn missing_permanent_prepare_is_corrupt_not_activated() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    std::fs::remove_file(fixture.authority().join(PREPARING_RECORD_NAME)).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn record_fstat_and_statat_io_are_errors_not_corruption() {
    for step in [RecordValidationStep::Fstat, RecordValidationStep::Statat] {
        let fixture = Fixture::new();
        drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
        set_record_validation_failure(Some(step));
        let result = discover_store_activation(&fixture.home, &fixture.store);
        set_record_validation_failure(None);
        assert!(matches!(
            result,
            Err(StoreActivationError::Io { source, .. })
                if source.raw_os_error() == Some(libc::EIO)
        ));
    }
}

#[test]
fn record_acl_probe_unknown_is_inspection_error_not_corruption() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    set_record_acl_unknown(true);
    let result = discover_store_activation(&fixture.home, &fixture.store);
    set_record_acl_unknown(false);
    assert!(matches!(
        result,
        Err(StoreActivationError::RecordInspection {
            reason: CertificationError::AclProbeUnknown,
            ..
        })
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn real_record_acl_tamper_is_corrupt() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(fixture.authority().join(ACTIVE_RECORD_NAME))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn busy_store_parent_is_returned_as_error_not_corrupt_state() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let parent = std::fs::File::open(fixture.store.parent().unwrap()).unwrap();
    parent.try_lock().unwrap();
    assert!(matches!(
        discover_store_activation(&fixture.home, &fixture.store),
        Err(StoreActivationError::Store(StoreError::Lease(
            crate::seal_wal::RecoveryLockError::Busy
        )))
    ));
    drop(parent);
}

#[test]
fn authority_guard_drop_unlocks_an_inherited_open_file_description() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let held = open_authority_root(&fixture.home, false).unwrap().unwrap();
    let inherited = held._lock.as_file().try_clone().unwrap();

    drop(held);
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );

    drop(inherited);
}

#[test]
fn concurrent_authority_user_is_a_blocking_error_not_a_state() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.home, &fixture.store).unwrap());
    let held = open_authority_root(&fixture.home, false).unwrap().unwrap();
    let home = fixture.home.clone();
    let store = fixture.store.clone();
    let result = std::thread::spawn(move || discover_store_activation(&home, &store))
        .join()
        .unwrap();
    assert!(matches!(result, Err(StoreActivationError::Io { .. })));
    drop(held);
    assert_eq!(
        discover_store_activation(&fixture.home, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}
