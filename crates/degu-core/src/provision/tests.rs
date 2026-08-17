use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Barrier};

fn test_credentials() -> Credentials {
    Credentials {
        controller_uid: rustix::process::geteuid().as_raw(),
        enforce_root: false,
    }
}

fn test_uid() -> u32 {
    42424
}

fn fixture() -> tempfile::TempDir {
    let root = crate::secure_test_tempdir().unwrap();
    let mut base = root.path().to_path_buf();
    for component in BASE_COMPONENTS {
        base.push(component);
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    root
}

fn provision_test(
    root: &Path,
    uid: u32,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    provision(
        root,
        uid,
        true,
        test_credentials(),
        BackendProbe::Fixed(CertifiedLocalBackend::Ext4),
    )
}

#[test]
fn fixed_path_contains_only_platform_and_decimal_uid() {
    let path = fixed_path(ProvisioningFlavor::System(Path::new("/")), 12345);
    #[cfg(target_os = "linux")]
    assert_eq!(path, Path::new("/var/lib/degu/store-activation/12345"));
    #[cfg(target_os = "macos")]
    assert_eq!(
        path,
        Path::new("/private/var/db/degu/store-activation/12345")
    );
}

#[test]
fn create_then_validate_without_repair_and_runtime_can_open_public_parents() {
    let root = fixture();
    let created = provision_test(root.path(), test_uid()).unwrap();
    assert_eq!(created.status, ActivationAnchorProvisioningStatus::Created);
    assert_eq!(
        std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
        LEAF_MODE
    );
    for parent in [
        created.path.parent().unwrap(),
        created.path.parent().unwrap().parent().unwrap(),
    ] {
        let metadata = std::fs::symlink_metadata(parent).unwrap();
        assert_eq!(metadata.mode() & 0o7777, PUBLIC_MODE);
        assert_eq!(
            metadata.mode() & 0o005,
            0o005,
            "runtime needs read and search"
        );
    }
    let lock = created
        .path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(PROVISIONING_LOCK_NAME);
    assert_eq!(
        std::fs::symlink_metadata(lock).unwrap().mode() & 0o7777,
        PRIVATE_LOCK_MODE
    );
    let again = provision_test(root.path(), test_uid()).unwrap();
    assert_eq!(
        again.status,
        ActivationAnchorProvisioningStatus::AlreadyProvisioned
    );
    assert!(!again.mutated());
}

#[test]
fn existing_wrong_mode_is_rejected_and_unchanged() {
    let root = fixture();
    let created = provision_test(root.path(), test_uid()).unwrap();
    std::fs::set_permissions(&created.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = provision_test(root.path(), test_uid()).unwrap_err();
    assert!(error.to_string().contains("mode is not exactly 0700"));
    assert_eq!(
        std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
        0o755
    );
}

#[test]
fn existing_file_and_symlink_are_never_replaced() {
    for symlink in [false, true] {
        let root = fixture();
        let leaf = fixed_path(ProvisioningFlavor::System(root.path()), test_uid());
        std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            leaf.parent().unwrap().parent().unwrap(),
            std::fs::Permissions::from_mode(PUBLIC_MODE),
        )
        .unwrap();
        std::fs::set_permissions(
            leaf.parent().unwrap(),
            std::fs::Permissions::from_mode(PUBLIC_MODE),
        )
        .unwrap();
        if symlink {
            std::os::unix::fs::symlink(root.path(), &leaf).unwrap();
        } else {
            std::fs::write(&leaf, b"keep").unwrap();
        }
        let error = provision_test(root.path(), test_uid()).unwrap_err();
        assert!(error.to_string().contains("not a no-follow directory"));
        if symlink {
            assert!(
                std::fs::symlink_metadata(&leaf)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        } else {
            assert_eq!(std::fs::read(&leaf).unwrap(), b"keep");
        }
    }
}

#[test]
fn failure_rolls_back_only_this_attempts_published_components() {
    let root = fixture();
    let error = provision(
        root.path(),
        test_uid(),
        true,
        test_credentials(),
        BackendProbe::FailAt("store-activation"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("inspection is uncertain"));
    let mut base = root.path().to_path_buf();
    for component in BASE_COMPONENTS {
        base.push(component);
    }
    // The empty, authenticated degu-owned serialization scaffold is a
    // committed idempotent prerequisite, not per-UID authority.
    assert!(base.join("degu").is_dir());
    assert!(!base.join("degu/store-activation").exists());
}

#[test]
fn cooperative_concurrency_never_removes_a_successful_anchor() {
    let root = fixture();
    let path = root.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            provision_test(&path, test_uid())
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(results.iter().any(Result::is_ok));
    assert!(fixed_path(ProvisioningFlavor::System(root.path()), test_uid()).is_dir());
    assert!(provision_test(root.path(), test_uid()).is_ok());
}

#[test]
fn missing_initial_and_reserved_uids_are_rejected_before_mutation() {
    let root = fixture();
    assert!(
        provision(
            root.path(),
            test_uid(),
            false,
            test_credentials(),
            BackendProbe::Fixed(CertifiedLocalBackend::Ext4)
        )
        .is_err()
    );
    for uid in [0, u32::MAX] {
        assert!(matches!(
            provision(
                root.path(),
                uid,
                true,
                test_credentials(),
                BackendProbe::Fixed(CertifiedLocalBackend::Ext4)
            ),
            Err(ActivationAnchorProvisioningError::InvalidUid { uid: rejected }) if rejected == uid
        ));
    }
}

fn provision_self_test(
    account_home: &Path,
) -> Result<ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningError> {
    let euid = rustix::process::geteuid().as_raw();
    let home = account_home.to_path_buf();
    let mut lookup = || Ok(home.clone());
    provision_flavor(
        ProvisioningFlavor::SelfManaged(account_home),
        euid,
        Credentials {
            controller_uid: euid,
            enforce_root: false,
        },
        BackendProbe::Real,
        Some(&mut lookup),
    )
}

#[test]
fn self_flavor_uses_trusted_account_base_and_real_backend_certification() {
    let home = crate::secure_test_tempdir().unwrap();
    let canonical_home = home.path().canonicalize().unwrap();
    let euid = rustix::process::geteuid().as_raw();
    let created = provision_self_test(&canonical_home).unwrap();
    assert_eq!(created.uid, euid);
    assert_eq!(created.status, ActivationAnchorProvisioningStatus::Created);
    assert_eq!(
        created.path,
        canonical_home
            .join(".local/state/degu/store-activation")
            .join(euid.to_string())
    );
    assert_eq!(
        std::fs::symlink_metadata(canonical_home.join(".local"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&created.path).unwrap().uid(),
        euid
    );
    assert_eq!(
        std::fs::symlink_metadata(&created.path).unwrap().mode() & 0o7777,
        LEAF_MODE
    );
    let again = provision_self_test(&canonical_home).unwrap();
    assert_eq!(
        again.status,
        ActivationAnchorProvisioningStatus::AlreadyProvisioned
    );
    assert_eq!(again.backend, created.backend);
}

#[test]
fn self_flavor_rejects_untrusted_home_ancestry_before_creation() {
    let outer = crate::secure_test_tempdir().unwrap();
    let home = outer.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let error = provision_self_test(&home).unwrap_err();
    assert!(matches!(
        error,
        ActivationAnchorProvisioningError::Io { .. }
    ));
    assert!(!home.join(".local").exists());
}

#[test]
fn self_flavor_never_repairs_an_existing_scaffold() {
    let home = crate::secure_test_tempdir().unwrap();
    let canonical_home = home.path().canonicalize().unwrap();
    let local = canonical_home.join(".local");
    std::fs::create_dir(&local).unwrap();
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o770)).unwrap();
    let error = provision_self_test(&canonical_home).unwrap_err();
    assert!(error.to_string().contains("grants group or other write"));
    assert_eq!(
        std::fs::symlink_metadata(&local).unwrap().mode() & 0o7777,
        0o770
    );
    assert!(!local.join("state").exists());
}

#[test]
fn self_flavor_concurrency_keeps_one_valid_current_euid_anchor() {
    let home = crate::secure_test_tempdir().unwrap();
    let path = home.path().canonicalize().unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            provision_self_test(&path)
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(results.iter().any(Result::is_ok));
    let final_result = provision_self_test(&path).unwrap();
    assert_eq!(
        final_result.status,
        ActivationAnchorProvisioningStatus::AlreadyProvisioned
    );
}

#[test]
fn noreplace_loser_reports_unremoved_initializer_as_residue() {
    let home = crate::secure_test_tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let euid = rustix::process::geteuid().as_raw();
    let lookup_home = home.clone();
    let mut lookup = || Ok(lookup_home.clone());
    let error = provision_flavor(
        ProvisioningFlavor::SelfManaged(&home),
        euid,
        Credentials {
            controller_uid: euid,
            enforce_root: false,
        },
        BackendProbe::LoseNoreplaceRaceAndBlockCleanupAt(SELF_STATE_COMPONENTS[0]),
        Some(&mut lookup),
    )
    .unwrap_err();

    let (failure, residue) = match error {
        ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
            (failure, residue)
        }
        other => panic!("expected machine-readable initializer residue, got {other:?}"),
    };
    assert!(!failure.is_empty());
    assert_eq!(residue.len(), 1);
    let initializer = &residue[0];
    assert_eq!(initializer.parent(), Some(home.as_path()));
    assert!(
        initializer
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(PRIVATE_TEMP_PREFIX))
    );
    assert!(initializer.join(TEST_CLEANUP_BLOCKER_NAME).is_dir());
    let remaining_initializers = std::fs::read_dir(&home)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(PRIVATE_TEMP_PREFIX))
        })
        .collect::<Vec<_>>();
    assert_eq!(remaining_initializers, residue);
    assert!(home.join(SELF_STATE_COMPONENTS[0]).is_dir());
    assert!(!home.join(".local/state").exists());
}

#[test]
fn all_scaffold_wrappers_preserve_original_failure_and_every_residue_path() {
    let home = PathBuf::from("/account-home");
    let local = home.join(".local");
    let state = local.join("state");
    let degu = state.join("degu");
    let lock = degu.join(PROVISIONING_LOCK_NAME);
    let initializer = degu.join(".degu-anchor-initializing-test");
    let merged = report_all_scaffold_failure(
        ActivationAnchorProvisioningError::RollbackResidue {
            failure: "original failure".into(),
            residue: vec![initializer.clone()],
        },
        ProvisioningFlavor::SelfManaged(&home),
        &[state.clone(), local.clone()],
        true,
        true,
    );
    match merged {
        ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
            let mut expected = vec![local, state, degu, lock, initializer];
            expected.sort();
            assert_eq!(failure, "original failure");
            assert_eq!(residue, expected);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

fn assert_self_scaffold_residue(error: ActivationAnchorProvisioningError, home: &Path) -> String {
    let local = home.join(".local");
    let state = local.join("state");
    let degu = state.join("degu");
    let lock = degu.join(PROVISIONING_LOCK_NAME);
    let mut expected = vec![local, state, degu, lock];
    expected.sort();
    match error {
        ActivationAnchorProvisioningError::RollbackResidue { failure, residue } => {
            assert_eq!(residue, expected);
            failure
        }
        other => panic!("expected machine-readable scaffold residue, got {other:?}"),
    }
}

#[cfg(target_os = "linux")]
fn plant_ineffective_access_acl(path: &Path) {
    use std::os::fd::AsRawFd;

    let file = File::open(path).unwrap();
    let euid = rustix::process::geteuid().as_raw();
    let named_uid = if euid < u32::MAX - 1 { euid + 1 } else { 1 };
    let mut acl = Vec::new();
    acl.extend_from_slice(&2_u32.to_le_bytes());
    for (tag, permissions, qualifier) in [
        (1_u16, 7_u16, u32::MAX),
        (2_u16, 4_u16, named_uid),
        (4_u16, 0_u16, u32::MAX),
        (0x10_u16, 0_u16, u32::MAX),
        (0x20_u16, 0_u16, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&qualifier.to_le_bytes());
    }
    // SAFETY: the held directory FD, xattr name, and ACL bytes remain live
    // for the syscall. The zero mask makes the named entry ineffective, so
    // mode-only trusted ancestry still accepts the directory.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
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
        io::Error::last_os_error()
    );
    assert_eq!(
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777,
        0o700
    );
}

#[cfg(target_os = "macos")]
fn plant_ineffective_access_acl(path: &Path) {
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "failed to plant test ACL");
    assert_eq!(
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777,
        0o700
    );
}

#[test]
fn trusted_symlink_is_rejected_by_runtime_preflight_before_leaf_publication() {
    let outer = crate::secure_test_tempdir().unwrap();
    let outer = outer.path().canonicalize().unwrap();
    let real_home = outer.join("real-home");
    let alias_home = outer.join("alias-home");
    std::fs::create_dir(&real_home).unwrap();
    std::fs::set_permissions(&real_home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real_home, &alias_home).unwrap();

    let error = provision_self_test(&alias_home).unwrap_err();
    assert!(matches!(
        error,
        ActivationAnchorProvisioningError::RuntimeIncompatible { .. }
    ));
    assert!(
        !real_home.join(".local").exists(),
        "runtime-incompatible account path created a scaffold"
    );
    let leaf = real_home
        .join(".local/state/degu/store-activation")
        .join(rustix::process::geteuid().as_raw().to_string());
    assert!(
        !leaf.exists(),
        "runtime-incompatible ancestry published a leaf"
    );
}

#[test]
fn account_acl_is_rejected_by_the_shared_runtime_contract() {
    let home = crate::secure_test_tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    plant_ineffective_access_acl(&home);

    let error = provision_self_test(&home).unwrap_err();
    assert!(error.to_string().contains("runtime contract"));
    assert!(error.to_string().contains("ACL"));
    assert!(
        !home.join(".local").exists(),
        "ACL-incompatible account path created a scaffold"
    );
    let leaf = home
        .join(".local/state/degu/store-activation")
        .join(rustix::process::geteuid().as_raw().to_string());
    assert!(!leaf.exists(), "ACL-incompatible ancestry published a leaf");
}

#[test]
fn account_home_a_to_b_drift_blocks_commit_and_rolls_back_leaf() {
    let a = crate::secure_test_tempdir().unwrap();
    let b = crate::secure_test_tempdir().unwrap();
    let a = a.path().canonicalize().unwrap();
    let b = b.path().canonicalize().unwrap();
    let mut answers = std::collections::VecDeque::from([a.clone(), a.clone(), a.clone(), b]);
    let euid = rustix::process::geteuid().as_raw();
    let error = provision_current_euid_self_with_lookup(euid, || {
        Ok(answers
            .pop_front()
            .expect("bounded account lookup sequence"))
    })
    .unwrap_err();
    let failure = assert_self_scaffold_residue(error, &a);
    assert!(failure.contains("account database home changed"));
    let leaf = a
        .join(".local/state/degu/store-activation")
        .join(euid.to_string());
    assert!(
        !leaf.exists(),
        "account drift left a published authority leaf"
    );
    assert!(
        answers.is_empty(),
        "final commit gate did not re-read account facts"
    );
}

#[test]
fn public_self_entry_is_zero_argument_and_rejects_root() {
    if rustix::process::geteuid().is_root() {
        assert!(matches!(
            provision_current_euid_self_activation_anchor(),
            Err(ActivationAnchorProvisioningError::RootCannotSelfProvision)
        ));
    }
    let entry: fn() -> Result<_, _> = provision_current_euid_self_activation_anchor;
    let _ = entry;
}

#[test]
fn production_entry_requires_real_root() {
    if !rustix::process::geteuid().is_root() {
        assert!(matches!(
            provision_activation_anchor(test_uid(), true),
            Err(ActivationAnchorProvisioningError::NotRoot)
        ));
    }
}

#[test]
fn system_initialization_refuses_an_existing_self_candidate() {
    let temp = crate::secure_test_tempdir().unwrap();
    let candidate = temp.path().join("self-candidate");
    assert!(refuse_existing_self_candidate_path(candidate.clone()).is_ok());
    std::fs::create_dir(&candidate).unwrap();
    assert!(matches!(
        refuse_existing_self_candidate_path(candidate.clone()),
        Err(ActivationAnchorProvisioningError::Unsafe { path, .. }) if path == candidate
    ));

    let dangling = temp.path().join("self-candidate-symlink");
    std::os::unix::fs::symlink(temp.path().join("missing-target"), &dangling).unwrap();
    assert!(matches!(
        refuse_existing_self_candidate_path(dangling.clone()),
        Err(ActivationAnchorProvisioningError::Unsafe { path, .. }) if path == dangling
    ));
}

#[test]
fn system_argument_validation_rejects_reserved_uids_and_missing_assertion() {
    let root = Path::new("/fixed-root");
    assert!(matches!(
        validate_provision_arguments(root, 0, true),
        Err(ActivationAnchorProvisioningError::InvalidUid { uid: 0 })
    ));
    assert!(matches!(
        validate_provision_arguments(root, u32::MAX, true),
        Err(ActivationAnchorProvisioningError::InvalidUid { uid }) if uid == u32::MAX
    ));
    assert!(matches!(
        validate_provision_arguments(root, test_uid(), false),
        Err(ActivationAnchorProvisioningError::Unsafe { reason, .. })
            if reason.contains("must assert --initial")
    ));
}
