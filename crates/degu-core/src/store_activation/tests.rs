use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    anchor: ActivationAnchorLocator,
    store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_provisioned_anchor(true)
    }

    fn without_anchor() -> Self {
        Self::with_provisioned_anchor(false)
    }

    fn with_provisioned_anchor(provision: bool) -> Self {
        let temp = crate::secure_test_tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let anchor_path = home.join("system-anchor");
        if provision {
            std::fs::create_dir(&anchor_path).unwrap();
            std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let state = home.join("state/degu");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(home.join("state"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = state.join("sealed-staging");
        Self {
            _temp: temp,
            home,
            anchor: ActivationAnchorLocator { path: anchor_path },
            store,
        }
    }

    fn authority(&self) -> PathBuf {
        self.anchor.as_path().to_path_buf()
    }
}

#[test]
fn record_empty_anchor_support_probe_does_not_create_a_store() {
    let fixture = Fixture::new();
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::NeverActivated
    );
    assert!(fixture.authority().is_dir());
    assert!(!fixture.store.exists());
}

#[test]
fn missing_anchor_blocks_without_creating_anchor_or_store() {
    let fixture = Fixture::without_anchor();
    assert!(matches!(
        discover_store_activation(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::AnchorNotProvisioned { path })
            if path == fixture.authority()
    ));
    assert!(!fixture.authority().exists());
    assert!(!fixture.store.exists());
    assert!(matches!(
        activate_or_resume_store(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::AnchorNotProvisioned { .. })
    ));
    assert!(!fixture.authority().exists());
    assert!(!fixture.store.exists());
}

#[test]
fn record_empty_anchor_reaches_injected_unsupported_support_classification() {
    for reason in [
        CertificationError::UnsupportedPlatform,
        CertificationError::UnsupportedFilesystem,
    ] {
        let fixture = Fixture::new();
        let mut probes = 0;
        let state = discover_store_activation_with_probe(&fixture.anchor, &fixture.store, |_| {
            probes += 1;
            Err(StoreActivationError::Backend(reason.clone()))
        })
        .unwrap();
        assert_eq!(state.kind(), StoreActivationKind::UnsupportedNeverActivated);
        assert_eq!(probes, 1);
        assert!(fixture.authority().is_dir());
        assert!(!fixture.store.exists());
    }
}

#[test]
fn activation_records_bypass_the_desired_store_support_probe() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let state = discover_store_activation_with_probe(&fixture.anchor, &fixture.store, |_| {
        panic!("support probe must not run when activation evidence exists")
    })
    .unwrap();
    assert_eq!(state.kind(), StoreActivationKind::Activated);
}

#[test]
fn platform_anchor_is_derived_only_from_platform_and_euid() {
    let anchor = ActivationAnchorLocator::for_current_euid().unwrap();
    let expected =
        Path::new(SYSTEM_ANCHOR_ROOT).join(rustix::process::geteuid().as_raw().to_string());
    assert_eq!(anchor.as_path(), expected);
}

#[test]
fn a_home_relative_authority_trap_is_ignored() {
    let fixture = Fixture::new();
    let trap = fixture.home.join(".degu-store-authority");
    std::fs::create_dir(&trap).unwrap();
    std::fs::set_permissions(&trap, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::NeverActivated
    );
    assert!(!fixture.store.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn real_tmpfs_desired_store_is_explicitly_unsupported_when_available() {
    let fixture = Fixture::new();
    let Ok(temp) = tempfile::Builder::new()
        .prefix("degu-activation-unsupported-")
        .tempdir_in("/dev/shm")
    else {
        return;
    };
    let parent = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = parent.join("sealed-staging");

    assert_eq!(
        discover_store_activation(&fixture.anchor, &store)
            .unwrap()
            .kind(),
        StoreActivationKind::UnsupportedNeverActivated
    );
    assert!(fixture.authority().is_dir());
    assert!(!store.exists());
    assert!(matches!(
        activate_or_resume_store(&fixture.anchor, &store),
        Err(StoreActivationError::Backend(
            CertificationError::UnsupportedFilesystem | CertificationError::UnsupportedPlatform
        ))
    ));
    assert!(!store.exists());
}

#[test]
fn v1_record_codecs_round_trip_without_a_policy_format_change() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let prepare_bytes = std::fs::read(fixture.authority().join(PREPARING_RECORD_NAME)).unwrap();
    let active_bytes = std::fs::read(fixture.authority().join(ACTIVE_RECORD_NAME)).unwrap();
    assert!(prepare_bytes.starts_with(MAGIC_PREPARE));
    assert!(active_bytes.starts_with(MAGIC_ACTIVE));
    assert_eq!(
        encode_prepare(&decode_prepare(&prepare_bytes).unwrap()).unwrap(),
        prepare_bytes
    );
    assert_eq!(
        encode_active(&decode_active(&active_bytes).unwrap()).unwrap(),
        active_bytes
    );
}

#[test]
fn activation_publishes_private_bidirectional_records() {
    let fixture = Fixture::new();
    let activated = activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap();
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
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}

#[test]
fn durable_prepare_is_distinct_and_resume_ignores_changed_xdg() {
    let fixture = Fixture::new();
    // Anchor/parent validation syncs are 0/1, prepare file is 2, and its
    // publication-directory sync is 3. The rename is visible at boundary 3.
    inject_sync_failure(Some(3));
    assert!(matches!(
        activate_or_resume_store(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::SyncUncertain("preparing record"))
    ));
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );

    let changed = fixture.home.join("state/degu/changed-store");
    let activated = activate_or_resume_store(&fixture.anchor, &changed).unwrap();
    assert_eq!(activated.locator(), fixture.store);
    assert!(fixture.store.is_dir());
    assert!(!changed.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss after durable prepare publication
fn store_loss_while_preparing_is_lost_not_recreated() {
    let fixture = Fixture::new();
    inject_sync_failure(Some(3));
    assert!(activate_or_resume_store(&fixture.anchor, &fixture.store).is_err());
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );
    std::fs::remove_dir_all(&fixture.store).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(matches!(
        activate_or_resume_store(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::NotResumable)
    ));
    assert!(!fixture.store.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol whole-store loss
fn whole_store_loss_is_never_reinitialized() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_dir_all(&fixture.store).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(!fixture.store.exists());
    assert!(matches!(
        activate_or_resume_store(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::NotResumable)
    ));
    assert!(!fixture.store.exists());
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss of the locator ancestor
fn missing_store_ancestor_is_structured_lost() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_dir_all(fixture.home.join("state/degu")).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates loss plus environment drift
fn xdg_drift_cannot_rediscover_a_new_empty_store() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_dir_all(&fixture.store).unwrap();
    let changed = fixture.home.join("state/degu/new-xdg-store");
    drop(SealWalStore::open_or_create(&changed).unwrap());

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Lost
    );
    assert!(changed.join(crate::seal_store::WAL_FILE_NAME).is_file());
}

#[test]
fn exact_store_replacement_is_corrupt_or_replaced() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let old = fixture.home.join("state/degu/old-store");
    std::fs::rename(&fixture.store, &old).unwrap();
    drop(SealWalStore::open_or_create(&fixture.store).unwrap());

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn missing_or_changed_reciprocal_binding_is_corrupt() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::write(fixture.store.join(STORE_BINDING_NAME), b"wrong").unwrap();
    std::fs::set_permissions(
        fixture.store.join(STORE_BINDING_NAME),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn active_record_symlink_is_never_followed() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let active = fixture.authority().join(ACTIVE_RECORD_NAME);
    let saved = fixture.authority().join("saved-active");
    std::fs::rename(&active, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &active).unwrap();

    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn foreign_writable_parent_and_unsafe_anchor_mode_fail_closed() {
    let fixture = Fixture::new();
    std::fs::set_permissions(&fixture.home, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        discover_store_activation(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::UnsafeAnchor(_))
    ));

    std::fs::set_permissions(&fixture.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::set_permissions(fixture.authority(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        discover_store_activation(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::UnsafeAnchor(_))
    ));
}

#[test]
fn anchor_symlink_and_regular_file_are_unsafe_and_never_followed() {
    for regular_file in [false, true] {
        let fixture = Fixture::without_anchor();
        if regular_file {
            std::fs::write(fixture.anchor.as_path(), b"not an anchor").unwrap();
        } else {
            let target = fixture.home.join("anchor-target");
            std::fs::create_dir(&target).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::symlink(&target, fixture.anchor.as_path()).unwrap();
        }
        assert!(matches!(
            discover_store_activation(&fixture.anchor, &fixture.store),
            Err(StoreActivationError::UnsafeAnchor(_))
        ));
        assert!(!fixture.store.exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn authority_acl_drift_fails_closed() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(fixture.authority())
        .status()
        .unwrap();
    assert!(status.success());

    assert!(discover_store_activation(&fixture.anchor, &fixture.store).is_err());
}

#[test]
fn anchor_is_fsynced_on_every_open_and_retry() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());

    // Anchor validation is the first activation-owned sync. A failed attempt
    // must not let retry skip that same boundary.
    inject_sync_failure(Some(0));
    assert!(matches!(
        discover_store_activation(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::SyncUncertain(
            "activation anchor directory after validation"
        ))
    ));
    inject_sync_failure(Some(0));
    assert!(discover_store_activation(&fixture.anchor, &fixture.store).is_err());
    inject_sync_failure(None);
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}

#[test]
fn every_activation_sync_boundary_fail_before_and_after_converges() {
    let baseline = Fixture::new();
    inject_sync_failure(None);
    drop(activate_or_resume_store(&baseline.anchor, &baseline.store).unwrap());
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
            let first = activate_or_resume_store(&fixture.anchor, &fixture.store);
            assert!(
                first.is_err(),
                "boundary {boundary}, after={after} did not inject"
            );
            inject_sync_failure(None);
            let state = discover_store_activation(&fixture.anchor, &fixture.store).unwrap();
            assert_ne!(state.kind(), StoreActivationKind::Lost);
            assert_ne!(state.kind(), StoreActivationKind::CorruptOrReplaced);
            drop(state);
            let activated = activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap();
            assert_eq!(activated.locator(), fixture.store);
            drop(activated);
            assert_eq!(
                discover_store_activation(&fixture.anchor, &fixture.store)
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
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_file(fixture.authority().join(ACTIVE_RECORD_NAME)).unwrap();

    let changed = fixture.home.join("state/degu/changed-after-active-loss");
    assert_eq!(
        discover_store_activation(&fixture.anchor, &changed)
            .unwrap()
            .kind(),
        StoreActivationKind::Preparing
    );
    let recovered = activate_or_resume_store(&fixture.anchor, &changed).unwrap();
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
        drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
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
            discover_store_activation(&fixture.anchor, &fixture.store)
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
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_file(fixture.store.join(STORE_BINDING_NAME)).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
#[allow(clippy::disallowed_methods)] // simulates out-of-protocol record loss
fn missing_permanent_prepare_is_corrupt_not_activated() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    std::fs::remove_file(fixture.authority().join(PREPARING_RECORD_NAME)).unwrap();
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn record_fstat_and_statat_io_are_errors_not_corruption() {
    for step in [RecordValidationStep::Fstat, RecordValidationStep::Statat] {
        let fixture = Fixture::new();
        drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
        set_record_validation_failure(Some(step));
        let result = discover_store_activation(&fixture.anchor, &fixture.store);
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
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    set_record_acl_unknown(true);
    let result = discover_store_activation(&fixture.anchor, &fixture.store);
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
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(fixture.authority().join(ACTIVE_RECORD_NAME))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::CorruptOrReplaced
    );
}

#[test]
fn busy_store_parent_is_returned_as_error_not_corrupt_state() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let parent = std::fs::File::open(fixture.store.parent().unwrap()).unwrap();
    parent.try_lock().unwrap();
    assert!(matches!(
        discover_store_activation(&fixture.anchor, &fixture.store),
        Err(StoreActivationError::Store(StoreError::Lease(
            crate::seal_wal::RecoveryLockError::Busy
        )))
    ));
    drop(parent);
}

#[test]
fn authority_guard_drop_unlocks_an_inherited_open_file_description() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let held = open_activation_anchor(&fixture.anchor).unwrap();
    let inherited = held._lock.as_file().try_clone().unwrap();

    drop(held);
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );

    drop(inherited);
}

#[test]
fn concurrent_authority_user_is_a_blocking_error_not_a_state() {
    let fixture = Fixture::new();
    drop(activate_or_resume_store(&fixture.anchor, &fixture.store).unwrap());
    let held = open_activation_anchor(&fixture.anchor).unwrap();
    let anchor = fixture.anchor.clone();
    let store = fixture.store.clone();
    let result = std::thread::spawn(move || discover_store_activation(&anchor, &store))
        .join()
        .unwrap();
    assert!(matches!(result, Err(StoreActivationError::Io { .. })));
    drop(held);
    assert_eq!(
        discover_store_activation(&fixture.anchor, &fixture.store)
            .unwrap()
            .kind(),
        StoreActivationKind::Activated
    );
}
