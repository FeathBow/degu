use super::*;
use crate::backend::certify_held_fd;
use std::fs::Permissions;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

fn open_directory(path: &Path) -> rustix::fd::OwnedFd {
    rustix::fs::open(path, OPEN_DIRECTORY, Mode::empty()).unwrap()
}

fn setup_tree() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::create_dir(root.join("a/b")).unwrap();
    std::fs::write(root.join("a/file"), b"one").unwrap();
    std::os::unix::fs::symlink("/", root.join("link")).unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    (temp, root)
}

fn collect(
    temp: &tempfile::TempDir,
    policy: Vec<OsString>,
    limits: HeldTreeLimits,
) -> Result<HeldTreeInventory, HeldTreeError> {
    HeldTreeInventory::collect(
        certify_held_fd(open_directory(temp.path())).unwrap(),
        OsStr::new("root"),
        policy,
        limits,
    )
}

fn assess(
    temp: &tempfile::TempDir,
    policy: Vec<OsString>,
    limits: HeldTreeLimits,
) -> Result<HeldTreeAdmissionAssessment, HeldTreeError> {
    assess_tree_admission(
        certify_held_fd(open_directory(temp.path())).unwrap(),
        OsStr::new("root"),
        policy,
        limits,
    )
}

fn assess_named(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    policy: Vec<OsString>,
    limits: HeldTreeLimits,
) -> Result<HeldTreeAdmissionAssessment, HeldTreeError> {
    assess_tree_admission(parent, root_name, policy, limits)
}

fn unwrap_tree_assessment(
    assessment: HeldTreeAdmissionAssessment,
) -> (HeldTreePolicyAssessment, SourceParentSealProjection) {
    match assessment {
        HeldTreeAdmissionAssessment::TreePolicyAssessed {
            tree,
            source_parent_seal,
        } => (tree, source_parent_seal),
        HeldTreeAdmissionAssessment::TreePolicyDeferredUntilSourceParentSeal { reason, .. } => {
            panic!("tree policy assessment unexpectedly deferred: {reason:?}")
        }
    }
}

fn assert_same_admission_error(
    prove: Result<HeldTreeInventory, HeldTreeError>,
    assessed: Result<HeldTreeAdmissionAssessment, HeldTreeError>,
) {
    let (prove, assessed) = (prove.unwrap_err(), assessed.unwrap_err());
    match (prove, assessed) {
        (
            HeldTreeError::Limit { kind: a, limit: x },
            HeldTreeError::Limit { kind: b, limit: y },
        ) => assert_eq!((a, x), (b, y)),
        (HeldTreeError::ExternalHardLink(a), HeldTreeError::ExternalHardLink(b))
        | (
            HeldTreeError::NonDirectoryExtendedMetadata(a),
            HeldTreeError::NonDirectoryExtendedMetadata(b),
        )
        | (HeldTreeError::UnsupportedContentProof(a), HeldTreeError::UnsupportedContentProof(b))
        | (HeldTreeError::ProtectedName(a), HeldTreeError::ProtectedName(b))
        | (HeldTreeError::ForeignOwner(a), HeldTreeError::ForeignOwner(b))
        | (HeldTreeError::BackendBoundary(a), HeldTreeError::BackendBoundary(b)) => {
            assert_eq!(a, b)
        }
        (a, b) => panic!("different admission errors: {a:?} vs {b:?}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_test_xattr(path: &Path) {
    let file = std::fs::File::open(path).unwrap();
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    // SAFETY: the file, name, and one-byte value remain live for the call.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"user.degu-content-admission".as_ptr(),
            b"x".as_ptr().cast(),
            1,
            0,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: the file, name, and one-byte value remain live for the call.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"com.degu.content-admission".as_ptr(),
            b"x".as_ptr().cast(),
            1,
            0,
            0,
        )
    };
    assert_eq!(
        result,
        0,
        "failed to set test xattr: {}",
        io::Error::last_os_error()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_symlink_test_xattr(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    #[cfg(target_os = "linux")]
    // SAFETY: path, name, and value remain live; lsetxattr does not follow path.
    let result = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            c"user.degu-content-admission".as_ptr(),
            b"x".as_ptr().cast(),
            1,
            0,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: path, name, and value remain live; XATTR_NOFOLLOW selects the link.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"com.degu.content-admission".as_ptr(),
            b"x".as_ptr().cast(),
            1,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[test]
fn production_directory_budget_fits_the_recovery_permission_envelope() {
    let limits = HeldTreeLimits::default();
    assert_eq!(limits.max_directories, MAX_TREE_DIRECTORIES);
    assert_eq!(MAX_TREE_DIRECTORIES + 1, HARD_DIRECTORY_CAP);
    assert_eq!(
        HARD_DIRECTORY_CAP,
        crate::seal::wal::RECOVERY_MAX_ACTIVE_PERMISSIONS as u64
    );
    assert_eq!(limits.max_entries, 100_000);
    assert_eq!(limits.max_depth, 128);
    assert_eq!(limits.max_path_bytes, 16 * 1024 * 1024);
    assert_eq!(limits.max_manifest_bytes, 64 * 1024 * 1024);
    assert_eq!(limits.max_content_bytes, 1024 * 1024 * 1024);
}

#[test]
fn every_traversal_rejects_an_explicit_1024_directory_request() {
    let (temp, _) = setup_tree();
    let limits = HeldTreeLimits {
        max_directories: HARD_DIRECTORY_CAP,
        ..HeldTreeLimits::default()
    };
    let v2 = collect(&temp, vec![], limits).unwrap_err();
    let assessment = assess(&temp, vec![], limits).unwrap_err();
    let legacy = HeldTreeInventory::collect_for_schema(
        certify_held_fd(open_directory(temp.path())).unwrap(),
        OsStr::new("root"),
        vec![],
        limits,
        1,
    )
    .unwrap_err();

    for error in [v2, assessment, legacy] {
        assert!(matches!(error, HeldTreeError::InvalidDirectoryLimit));
        assert_eq!(
            error.to_string(),
            "requested tree directory limit exceeds 1023 total directories (including the root)"
        );
    }
}

#[test]
fn production_boundary_accepts_1023_total_directories_and_rejects_1024() {
    let (temp, root) = setup_tree();
    // setup_tree contains root, a, and a/b. Add 1,020 siblings for 1,023 total.
    for index in 0..(MAX_TREE_DIRECTORIES - 3) {
        std::fs::create_dir(root.join(format!("boundary-{index:04}"))).unwrap();
    }
    let inventory = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    assert_eq!(inventory.directories.len() as u64, MAX_TREE_DIRECTORIES);
    let (assessment, _) =
        unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(assessment.directories, MAX_TREE_DIRECTORIES);
    let legacy = HeldTreeInventory::collect_for_schema(
        certify_held_fd(open_directory(temp.path())).unwrap(),
        OsStr::new("root"),
        vec![],
        HeldTreeLimits::default(),
        1,
    )
    .unwrap();
    assert_eq!(legacy.directories.len() as u64, MAX_TREE_DIRECTORIES);

    std::fs::create_dir(root.join("boundary-over-limit")).unwrap();
    for error in [
        collect(&temp, vec![], HeldTreeLimits::default()).unwrap_err(),
        assess(&temp, vec![], HeldTreeLimits::default()).unwrap_err(),
    ] {
        assert!(matches!(
            error,
            HeldTreeError::Limit {
                kind: HeldTreeLimit::Directories,
                limit: MAX_TREE_DIRECTORIES,
            }
        ));
    }
}

#[test]
fn metadata_only_tree_policy_matches_clean_v2_admission_without_claiming_seal_readiness() {
    fn assert_data_traits<T: Clone + Send + Sync + Eq + std::fmt::Debug>() {}
    assert_data_traits::<HeldTreeAdmissionAssessment>();

    let (temp, _) = setup_tree();
    let prove = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let (tree, seal) =
        unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(tree.entries, prove.entry_count());
    assert_eq!(tree.directories, prove.directories.len() as u64);
    assert_eq!(seal.original_mode, 0o700);
    assert_eq!(seal.projected_mode, 0o700);
    assert_eq!(
        seal.validation,
        SourceParentSealValidation::RequiresExecutionValidation
    );
    assert!(tree.path_bytes > 0);
    assert!(tree.manifest_bytes > tree.path_bytes);
    assert_eq!(tree.content_bytes, 4); // "one" plus the one-byte symlink target.
}

#[test]
fn assessment_regular_files_remain_metadata_only_while_proving_reads_content() {
    let (temp, _) = setup_tree();
    REGULAR_CONTENT_BYTES_READ.with(|bytes| bytes.set(0));
    unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(REGULAR_CONTENT_BYTES_READ.with(std::cell::Cell::get), 0);

    let proved = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    assert_eq!(REGULAR_CONTENT_BYTES_READ.with(std::cell::Cell::get), 3);
    assert_eq!(proved.entry_count(), 5);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_assessment_fd_peak_is_independent_of_directory_count() {
    use std::cell::Cell;
    use std::rc::Rc;

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    for index in 0..240 {
        std::fs::create_dir(root.join(format!("sibling-{index:03}"))).unwrap();
    }

    let baseline = observed_process_fd_count();
    let peak = Rc::new(Cell::new(baseline));
    let fired = Rc::new(Cell::new(0_u64));
    let observed_peak = Rc::clone(&peak);
    let observed_fired = Rc::clone(&fired);
    let _hook = install_reopener_test_hook(move |_, path| {
        if !path.as_os_str().is_empty() {
            observed_fired.set(observed_fired.get() + 1);
            observed_peak.set(observed_peak.get().max(observed_process_fd_count()));
        }
    });
    let (tree, _) =
        unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(tree.directories, 241);
    assert!(fired.get() >= 240, "descendant reopener hook did not fire");
    assert!(
        peak.get().saturating_sub(baseline) <= 4,
        "assessment retained directory descriptors: baseline={baseline}, peak={}",
        peak.get()
    );
    assert_eq!(observed_process_fd_count(), baseline);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn assessment_fd_peak_is_bounded_across_240_sibling_directories() {
    const CHILD_MARKER_ENV: &str = "DEGU_ASSESSMENT_FD_OBSERVATION_CHILD_MARKER";
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        assert_assessment_fd_peak_is_independent_of_directory_count();
        std::fs::write(marker, b"observed").unwrap();
        return;
    }

    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("completed");
    let test_name = format!(
        "{}::assessment_fd_peak_is_bounded_across_240_sibling_directories",
        module_path!()
            .strip_prefix("degu_core::")
            .unwrap_or(module_path!())
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .unwrap();
    assert!(status.success(), "isolated assessment FD test failed");
    assert!(
        marker.exists(),
        "isolated assessment FD test did not execute"
    );
}

#[test]
#[allow(clippy::disallowed_methods)]
fn assessment_reopener_fails_closed_on_descendant_replacement() {
    use std::cell::Cell;
    use std::rc::Rc;

    let (temp, root) = setup_tree();
    let moved = temp.path().join("moved-assessment-a");
    let fired = Rc::new(Cell::new(false));
    let hook_fired = Rc::clone(&fired);
    let hook_root = root.clone();
    let _hook = install_reopener_test_hook(move |phase, path| {
        if phase == ReopenerTestPhase::AfterOpenBeforeValidation
            && path == Path::new("a")
            && !hook_fired.replace(true)
        {
            std::fs::rename(hook_root.join("a"), &moved).unwrap();
            std::fs::create_dir(hook_root.join("a")).unwrap();
        }
    });
    let error = assess(&temp, vec![], HeldTreeLimits::default()).unwrap_err();
    assert!(
        fired.get(),
        "assessment did not use the root-relative reopener"
    );
    assert!(
        matches!(error, HeldTreeError::IdentityChanged(ref path) if path == Path::new("a")),
        "replacement returned {error:?}"
    );
}

#[test]
fn proving_manifest_is_stable_across_bounded_assessment() {
    let (temp, _) = setup_tree();
    let baseline = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let baseline_fingerprint = baseline.fingerprint();
    drop(baseline);

    unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    let proved = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    assert_eq!(proved.fingerprint(), baseline_fingerprint);
    assert_eq!(proved.directories.len(), 3);
}

#[test]
fn writable_parent_allows_tree_policy_assessment_but_seal_remains_unvalidated() {
    let (temp, _) = setup_tree();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o770)).unwrap();
    let (_, seal) =
        unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(seal.original_mode, 0o770);
    assert_eq!(seal.projected_mode, 0o750);
    assert_eq!(
        seal.validation,
        SourceParentSealValidation::RequiresExecutionValidation
    );
    assert_eq!(
        std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o7777,
        0o770
    );
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::ParentNotExclusive)
    ));
}

#[test]
fn unsearchable_source_parent_defers_the_entire_tree_policy_assessment() {
    let (temp, _) = setup_tree();
    let seal_fd = open_directory(temp.path());
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o400)).unwrap();
    let assessment = assess(&temp, vec![], HeldTreeLimits::default()).unwrap();
    match assessment {
        HeldTreeAdmissionAssessment::TreePolicyDeferredUntilSourceParentSeal {
            reason,
            source_parent_seal,
        } => {
            assert_eq!(
                reason,
                TreePolicyDeferralReason::SourceParentSearchRequiresExecutionSeal
            );
            assert_eq!(source_parent_seal.original_mode, 0o400);
            assert_eq!(source_parent_seal.projected_mode, 0o700);
            assert_eq!(
                source_parent_seal.validation,
                SourceParentSealValidation::RequiresExecutionValidation
            );
        }
        other => panic!("0400 parent was not deferred: {other:?}"),
    }

    rustix::fs::fchmod(&seal_fd, Mode::from_raw_mode(0o700)).unwrap();
    collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
}

#[test]
fn syntactic_root_policy_and_tree_request_cap_errors_precede_tree_policy_deferral() {
    let (temp, _) = setup_tree();
    let invalid_root = certify_held_fd(open_directory(temp.path())).unwrap();
    let protected_root = certify_held_fd(open_directory(temp.path())).unwrap();
    let excessive_cap = certify_held_fd(open_directory(temp.path())).unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o400)).unwrap();

    assert!(matches!(
        assess_named(
            invalid_root,
            OsStr::new("not/one-component"),
            vec![],
            HeldTreeLimits::default(),
        ),
        Err(HeldTreeError::InvalidRoot)
    ));
    assert!(matches!(
        assess_named(
            protected_root,
            OsStr::new("root"),
            vec![OsString::from("root")],
            HeldTreeLimits::default(),
        ),
        Err(HeldTreeError::ProtectedName(path)) if path.as_os_str().is_empty()
    ));
    assert!(matches!(
        assess_named(
            excessive_cap,
            OsStr::new("root"),
            vec![],
            HeldTreeLimits {
                max_directories: HARD_DIRECTORY_CAP,
                ..HeldTreeLimits::default()
            },
        ),
        Err(HeldTreeError::InvalidDirectoryLimit)
    ));
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn unsearchable_parent_does_not_claim_non_directory_or_special_content_was_checked() {
    fn assert_tree_policy_deferred(assessment: HeldTreeAdmissionAssessment) {
        assert!(matches!(
            assessment,
            HeldTreeAdmissionAssessment::TreePolicyDeferredUntilSourceParentSeal {
                reason: TreePolicyDeferralReason::SourceParentSearchRequiresExecutionSeal,
                source_parent_seal: SourceParentSealProjection {
                    validation: SourceParentSealValidation::RequiresExecutionValidation,
                    ..
                },
            }
        ));
    }

    // A regular file at the root name would be a known RootNotDirectory only
    // after search has actually been acquired on the source parent.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::write(&root, b"not a directory").unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o400)).unwrap();
    let held = certify_held_fd(open_directory(temp.path())).unwrap();
    assert_tree_policy_deferred(
        assess_named(held, OsStr::new("root"), vec![], HeldTreeLimits::default()).unwrap(),
    );
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::RootNotDirectory)
    ));

    // Likewise, a FIFO inside the tree remains deliberately unknown before the
    // source-parent execution seal makes traversal possible.
    let (temp, root) = setup_tree();
    let fifo = CString::new(root.join("a/fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is a fresh NUL-terminated fixture path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o400)).unwrap();
    let held = certify_held_fd(open_directory(temp.path())).unwrap();
    assert_tree_policy_deferred(
        assess_named(held, OsStr::new("root"), vec![], HeldTreeLimits::default()).unwrap(),
    );
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::UnsupportedContentProof(path)) if path == Path::new("a/fifo")
    ));
}

#[test]
fn assessment_and_prove_share_hardlink_protected_special_and_directory_cap_rejections() {
    let (temp, root) = setup_tree();
    std::fs::hard_link(root.join("a/file"), root.join("a/other")).unwrap();
    assert_same_admission_error(
        collect(&temp, vec![], HeldTreeLimits::default()),
        assess(&temp, vec![], HeldTreeLimits::default()),
    );

    let (temp, _) = setup_tree();
    assert_same_admission_error(
        collect(
            &temp,
            vec![OsString::from("file")],
            HeldTreeLimits::default(),
        ),
        assess(
            &temp,
            vec![OsString::from("file")],
            HeldTreeLimits::default(),
        ),
    );

    let (temp, root) = setup_tree();
    let fifo = CString::new(root.join("a/fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is a fresh NUL-terminated fixture path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_same_admission_error(
        collect(&temp, vec![], HeldTreeLimits::default()),
        assess(&temp, vec![], HeldTreeLimits::default()),
    );

    let (temp, root) = setup_tree();
    for index in 0..MAX_TREE_DIRECTORIES {
        std::fs::create_dir(root.join(format!("d{index:04}"))).unwrap();
    }
    assert_same_admission_error(
        collect(&temp, vec![], HeldTreeLimits::default()),
        assess(&temp, vec![], HeldTreeLimits::default()),
    );
}

#[test]
fn assessment_and_prove_have_entry_depth_path_manifest_and_content_limit_parity() {
    fn assert_limit(temp: &tempfile::TempDir, limits: HeldTreeLimits, expected: HeldTreeLimit) {
        let prove = collect(temp, vec![], limits).unwrap_err();
        let assessed = assess(temp, vec![], limits).unwrap_err();
        for error in [prove, assessed] {
            assert!(matches!(
                error,
                HeldTreeError::Limit { kind, .. } if kind == expected
            ));
        }
    }

    let (temp, _) = setup_tree();
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_entries: 4,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::Entries,
    );
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_depth: 1,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::Depth,
    );
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_path_bytes: 1,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::PathBytes,
    );
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_manifest_bytes: 0,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::ManifestBytes,
    );
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_content_bytes: 3,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::ContentBytes,
    );

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink("/", root.join("link")).unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    assert_limit(
        &temp,
        HeldTreeLimits {
            max_content_bytes: 0,
            ..HeldTreeLimits::default()
        },
        HeldTreeLimit::ContentBytes,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn immutable_parent_demonstrates_that_tree_assessment_is_not_seal_readiness() {
    use std::os::fd::AsRawFd;

    struct ClearImmutable(rustix::fd::OwnedFd);
    impl Drop for ClearImmutable {
        fn drop(&mut self) {
            // SAFETY: the descriptor remains live and names the test directory.
            let result = unsafe { libc::fchflags(self.0.as_raw_fd(), 0) };
            assert_eq!(result, 0, "failed to clear UF_IMMUTABLE during cleanup");
        }
    }

    let (temp, _) = setup_tree();
    let flag_fd = open_directory(temp.path());
    let chmod_fd = open_directory(temp.path());
    // SAFETY: the descriptor remains live and names a fresh owned APFS fixture.
    let result = unsafe { libc::fchflags(flag_fd.as_raw_fd(), libc::UF_IMMUTABLE) };
    assert_eq!(
        result,
        0,
        "UF_IMMUTABLE fixture unavailable; this must be diagnosed, not silently skipped: {}",
        io::Error::last_os_error()
    );
    let _clear = ClearImmutable(flag_fd);

    let (_, seal) =
        unwrap_tree_assessment(assess(&temp, vec![], HeldTreeLimits::default()).unwrap());
    assert_eq!(seal.original_mode, 0o700);
    assert_eq!(seal.projected_mode, 0o700);
    assert_eq!(
        seal.validation,
        SourceParentSealValidation::RequiresExecutionValidation
    );

    let error = rustix::fs::fchmod(&chmod_fd, Mode::from_raw_mode(0o700)).unwrap_err();
    assert_eq!(error, rustix::io::Errno::PERM);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn assessment_and_prove_share_xattr_rejection() {
    let (temp, root) = setup_tree();
    set_test_xattr(&root.join("a/file"));
    assert_same_admission_error(
        collect(&temp, vec![], HeldTreeLimits::default()),
        assess(&temp, vec![], HeldTreeLimits::default()),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn assessment_and_prove_share_regular_acl_rejection_when_supported() {
    use std::os::fd::AsRawFd;

    let (temp, root) = setup_tree();
    let file = std::fs::File::open(root.join("a/file")).unwrap();
    let acl: [u8; 44] = [
        2, 0, 0, 0, // version
        1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ
        2, 0, 4, 0, 0, 0, 0, 0, // ACL_USER uid 0
        4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ
        0x10, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_MASK
        0x20, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER
    ];
    // SAFETY: the FD and ACL buffer remain live for the syscall.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error().is_some_and(|code| {
            code == libc::ENOTSUP || code == libc::EOPNOTSUPP || code == libc::EPERM
        }) {
            eprintln!(
                "SKIP assessment_and_prove_share_regular_acl_rejection_when_supported: \
                 filesystem rejected POSIX ACL fixture: {error}"
            );
            return;
        }
        panic!("unexpected ACL fixture failure: {error}");
    }
    assert_same_admission_error(
        collect(&temp, vec![], HeldTreeLimits::default()),
        assess(&temp, vec![], HeldTreeLimits::default()),
    );
}

#[test]
fn synthetic_owner_and_mount_reasons_remain_the_shared_traversal_errors() {
    let (temp, _) = setup_tree();
    let held = certify_held_fd(open_directory(temp.path())).unwrap();
    let mut inspected = inspect_held(&held, Path::new("fixture")).unwrap();
    inspected.uid = inspected.uid.saturating_add(1);
    assert!(matches!(
        require_owner(Path::new("fixture"), inspected.uid, held.effective_uid()),
        Err(HeldTreeError::ForeignOwner(path)) if path == Path::new("fixture")
    ));
    inspected.uid = held.effective_uid();
    inspected.mount_id = inspected.mount_id.saturating_add(1);
    assert!(matches!(
        require_boundary(Path::new("fixture"), held.backend(), held.mount_id(), &inspected),
        Err(HeldTreeError::BackendBoundary(path)) if path == Path::new("fixture")
    ));
}

#[test]
fn bounded_collect_records_every_directory_and_exact_rewalks() {
    let (temp, _) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    assert_eq!(tree.entry_count(), 5);
    let order = tree.directories_deepest_first().collect::<Vec<_>>();
    assert_eq!(
        order
            .iter()
            .map(|entry| entry.relative_path.as_path())
            .collect::<Vec<_>>(),
        [Path::new("a/b"), Path::new("a"), Path::new("")]
    );
    assert_eq!(
        order.iter().map(|entry| entry.depth).collect::<Vec<_>>(),
        [2, 1, 0]
    );
    tree.rewalk_exact().unwrap();
}

#[test]
fn directory_evidence_is_descriptor_free_data_and_clean_rewalk_succeeds() {
    fn assert_data_only<T: Clone + Send + Sync + Eq + std::fmt::Debug>() {}
    assert_data_only::<DirectoryEvidence>();

    let (temp, _) = setup_tree();
    collect(&temp, vec![], HeldTreeLimits::default())
        .unwrap()
        .rewalk_exact()
        .unwrap();
}

#[test]
fn directory_evidence_index_rejects_duplicate_paths() {
    let (temp, _) = setup_tree();
    let mut tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let a = tree
        .directories
        .iter()
        .position(|directory| directory.relative_path == Path::new("a"))
        .unwrap();
    let ab = tree
        .directories
        .iter()
        .position(|directory| directory.relative_path == Path::new("a/b"))
        .unwrap();
    tree.directories[ab].relative_path = PathBuf::from("a");
    tree.directories[ab].depth = tree.directories[a].depth;
    assert!(matches!(
        build_directory_index(&tree.directories),
        Err(HeldTreeError::IdentityChanged(path)) if path == Path::new("a")
    ));
}

#[test]
fn confined_reopener_rejects_every_non_normal_relative_form() {
    let (temp, _) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    for invalid in ["../a", "/a", "./a", "a/../b", "a/./b", "a//b", "a/"] {
        assert!(matches!(
            tree.reopen_directory(Path::new(invalid)),
            Err(HeldTreeError::InvalidDirectoryPath(path)) if path == Path::new(invalid)
        ));
    }
    assert!(tree.reopen_directory(Path::new("")).is_ok());
    assert!(tree.reopen_directory(Path::new("a/b")).is_ok());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observed_process_fd_count() -> usize {
    #[cfg(target_os = "linux")]
    let directory = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    let directory = "/dev/fd";
    std::fs::read_dir(directory).unwrap().count()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_confined_reopener_process_fd_bound() {
    use std::cell::Cell;
    use std::rc::Rc;

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    for sibling in 0..239 {
        std::fs::create_dir(root.join(format!("s{sibling}"))).unwrap();
    }
    let mut path = root.join("s0");
    for depth in 1..=16 {
        path.push(format!("d{depth}"));
        std::fs::create_dir(&path).unwrap();
    }

    let before_inventory = observed_process_fd_count();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let baseline = observed_process_fd_count();
    assert_eq!(tree.directories.len(), 256);
    assert_eq!(
        baseline.checked_sub(before_inventory),
        Some(2),
        "production proving retains exactly the source parent and tree root FDs"
    );

    for target in [
        PathBuf::from("s0"),
        path.strip_prefix(temp.path().join("root"))
            .unwrap()
            .to_path_buf(),
    ] {
        let peak = Rc::new(Cell::new(baseline));
        let fired = Rc::new(Cell::new(0_u64));
        let observed_peak = Rc::clone(&peak);
        let observed_fired = Rc::clone(&fired);
        let _hook = install_reopener_test_hook(move |_, _| {
            observed_fired.set(observed_fired.get() + 1);
            observed_peak.set(observed_peak.get().max(observed_process_fd_count()));
        });
        REOPENER_MAX_NON_ROOT_FDS.with(|maximum| maximum.set(0));
        drop(tree.reopen_directory(&target).unwrap());
        assert!(
            fired.get() > 0,
            "the in-reopener observation hook did not fire"
        );
        let transient = peak
            .get()
            .checked_sub(baseline)
            .expect("process FD count fell below the post-inventory baseline");
        assert!(
            transient <= 2,
            "reopening depth {} used {transient} transient process FDs",
            normal_relative_components(&target).unwrap().len()
        );
        let depth = normal_relative_components(&target).unwrap().len();
        assert_eq!(transient, depth.min(2));
        assert_eq!(
            REOPENER_MAX_NON_ROOT_FDS.with(std::cell::Cell::get),
            depth.min(2),
            "the internal rolling-FD counter is only a secondary invariant"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn confined_reopener_process_fd_delta_is_bounded_independent_of_depth() {
    const CHILD_MARKER_ENV: &str = "DEGU_REOPENER_FD_OBSERVATION_CHILD_MARKER";
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        assert_confined_reopener_process_fd_bound();
        std::fs::write(marker, b"observed").unwrap();
        return;
    }

    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("completed");
    let test_name = format!(
        "{}::confined_reopener_process_fd_delta_is_bounded_independent_of_depth",
        module_path!()
            .strip_prefix("degu_core::")
            .unwrap_or(module_path!())
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated FD observation subprocess failed"
    );
    assert!(
        marker.exists(),
        "isolated FD observation test did not execute"
    );
}

#[test]
#[allow(clippy::disallowed_methods)]
fn in_reopener_namespace_replacement_move_and_detach_fail_closed() {
    use std::cell::Cell;
    use std::rc::Rc;

    for phase in [
        ReopenerTestPhase::AfterOpenBeforeValidation,
        ReopenerTestPhase::AfterValidatedHopBeforeNextOperation,
    ] {
        let (temp, root) = setup_tree();
        let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
        let moved = temp.path().join("moved");
        let fired = Rc::new(Cell::new(false));
        let hook_fired = Rc::clone(&fired);
        let hook_root = root.clone();
        let _hook = install_reopener_test_hook(move |observed_phase, path| {
            if observed_phase == phase && path == Path::new("a") && !hook_fired.replace(true) {
                std::fs::rename(hook_root.join("a"), &moved).unwrap();
                if phase == ReopenerTestPhase::AfterOpenBeforeValidation {
                    std::fs::create_dir(hook_root.join("a")).unwrap();
                }
            }
        });
        let error = tree.reopen_directory(Path::new("a/b")).unwrap_err();
        assert!(fired.get(), "the requested in-reopener phase did not fire");
        match phase {
            ReopenerTestPhase::AfterOpenBeforeValidation => assert!(
                matches!(error, HeldTreeError::IdentityChanged(ref path) if path == Path::new("a")),
                "in-window replacement returned {error:?}"
            ),
            ReopenerTestPhase::AfterValidatedHopBeforeNextOperation => assert!(
                matches!(error, HeldTreeError::Io { ref path, .. } if path == Path::new("a")),
                "in-window move returned {error:?}"
            ),
        }
    }

    let (temp, root) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let detached = temp.path().join("detached-root");
    let fired = Rc::new(Cell::new(false));
    let hook_fired = Rc::clone(&fired);
    let _hook = install_reopener_test_hook(move |phase, path| {
        if phase == ReopenerTestPhase::AfterValidatedHopBeforeNextOperation
            && path.as_os_str().is_empty()
            && !hook_fired.replace(true)
        {
            std::fs::rename(&root, &detached).unwrap();
        }
    });
    let error = tree.rewalk_exact().unwrap_err();
    assert!(fired.get(), "the root-detach in-reopener hook did not fire");
    assert!(
        matches!(error, HeldTreeError::RootBindingChanged),
        "in-window root detach returned {error:?}"
    );
}

#[test]
fn confined_reopener_compares_the_recorded_strong_incarnation() {
    let (temp, _) = setup_tree();
    let mut tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let directory = tree
        .directories
        .iter_mut()
        .find(|directory| directory.relative_path == Path::new("a"))
        .unwrap();
    directory.identity.incarnation ^= 1;
    assert!(matches!(
        tree.reopen_directory(Path::new("a")),
        Err(HeldTreeError::IdentityChanged(path)) if path == Path::new("a")
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regular_xattrs_remain_rejected_but_directory_xattrs_remain_out_of_scope() {
    let (temp, root) = setup_tree();
    set_test_xattr(&root.join("a/file"));
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::NonDirectoryExtendedMetadata(path)) if path == Path::new("a/file")
    ));

    let (temp, root) = setup_tree();
    set_test_xattr(&root.join("a"));
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    tree.rewalk_exact().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn special_files_remain_unsupported() {
    let (temp, root) = setup_tree();
    let fifo = root.join("a/fifo");
    let fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is NUL-terminated and names a fresh path in the fixture.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::UnsupportedContentProof(path)) if path == Path::new("a/fifo")
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum XattrStep {
    Count(usize),
    Bytes(&'static [u8]),
    Error(i32),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collect_script(steps: &[XattrStep]) -> CollectedXattrs {
    let mut steps = steps.iter().copied();
    let collected = collect_xattr_names(|buffer, size| match steps.next().unwrap() {
        XattrStep::Count(count) => Ok(count),
        XattrStep::Error(errno) => Err(io::Error::from_raw_os_error(errno)),
        XattrStep::Bytes(bytes) => {
            assert!(!buffer.is_null());
            assert!(bytes.len() <= size);
            // SAFETY: collect_xattr_names supplied a writable allocation of `size` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast(), bytes.len()) };
            Ok(bytes.len())
        }
    });
    assert!(
        steps.next().is_none(),
        "script contained unused xattr steps"
    );
    collected
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn xattr_enumeration_retries_are_deterministic_and_fail_closed() {
    let names = CollectedXattrs::Names(vec![b"user.z".to_vec(), b"security.a".to_vec()]);
    let list = b"user.z\0security.a\0";
    for (label, steps, expected) in [
        (
            "stable zero",
            vec![XattrStep::Count(0)],
            CollectedXattrs::Names(vec![]),
        ),
        (
            "stable list",
            vec![XattrStep::Count(list.len()), XattrStep::Bytes(list)],
            names,
        ),
        (
            "sizing EINTR then list",
            vec![
                XattrStep::Error(libc::EINTR),
                XattrStep::Count(list.len()),
                XattrStep::Bytes(list),
            ],
            CollectedXattrs::Names(vec![b"user.z".to_vec(), b"security.a".to_vec()]),
        ),
        (
            "sizing EINTR then zero",
            vec![XattrStep::Error(libc::EINTR), XattrStep::Count(0)],
            CollectedXattrs::Unknown,
        ),
        (
            "data EINTR then list",
            vec![
                XattrStep::Count(list.len()),
                XattrStep::Error(libc::EINTR),
                XattrStep::Count(list.len()),
                XattrStep::Bytes(list),
            ],
            CollectedXattrs::Names(vec![b"user.z".to_vec(), b"security.a".to_vec()]),
        ),
        (
            "data ERANGE then list",
            vec![
                XattrStep::Count(list.len()),
                XattrStep::Error(libc::ERANGE),
                XattrStep::Count(list.len()),
                XattrStep::Bytes(list),
            ],
            CollectedXattrs::Names(vec![b"user.z".to_vec(), b"security.a".to_vec()]),
        ),
        (
            "sizing retry exhaustion",
            vec![
                XattrStep::Error(libc::EINTR),
                XattrStep::Error(libc::EINTR),
                XattrStep::Error(libc::EINTR),
            ],
            CollectedXattrs::Unknown,
        ),
        (
            "data retry exhaustion",
            vec![
                XattrStep::Count(2),
                XattrStep::Error(libc::ERANGE),
                XattrStep::Count(2),
                XattrStep::Error(libc::ERANGE),
                XattrStep::Count(2),
                XattrStep::Error(libc::ERANGE),
            ],
            CollectedXattrs::Unknown,
        ),
        (
            "sizing ERANGE",
            vec![XattrStep::Error(libc::ERANGE)],
            CollectedXattrs::Unknown,
        ),
        (
            "sizing nonretryable error",
            vec![XattrStep::Error(libc::EIO)],
            CollectedXattrs::Unknown,
        ),
        (
            "data nonretryable error",
            vec![XattrStep::Count(2), XattrStep::Error(libc::EIO)],
            CollectedXattrs::Unknown,
        ),
        (
            "oversized list",
            vec![XattrStep::Count(MAX_XATTR_NAME_LIST_BYTES + 1)],
            CollectedXattrs::Unknown,
        ),
        (
            "read exceeds allocation",
            vec![XattrStep::Count(1), XattrStep::Count(2)],
            CollectedXattrs::Unknown,
        ),
        (
            "missing trailing NUL",
            vec![XattrStep::Count(3), XattrStep::Bytes(b"abc")],
            CollectedXattrs::Unknown,
        ),
        (
            "empty name",
            vec![XattrStep::Count(3), XattrStep::Bytes(b"a\0\0")],
            CollectedXattrs::Unknown,
        ),
        (
            "positive then retry then zero",
            vec![
                XattrStep::Count(2),
                XattrStep::Error(libc::ERANGE),
                XattrStep::Count(0),
            ],
            CollectedXattrs::Unknown,
        ),
    ] {
        assert_eq!(collect_script(&steps), expected, "{label}");
    }

    let too_many = vec![b'a', 0]
        .into_iter()
        .cycle()
        .take((MAX_XATTR_NAMES + 1) * 2)
        .collect::<Vec<_>>();
    let mut sizing = true;
    let collected = collect_xattr_names(|buffer, size| {
        if sizing {
            sizing = false;
            return Ok(too_many.len());
        }
        assert_eq!(size, too_many.len());
        // SAFETY: collect_xattr_names supplied a writable allocation of `size` bytes.
        unsafe { std::ptr::copy_nonoverlapping(too_many.as_ptr(), buffer.cast(), size) };
        Ok(size)
    });
    assert_eq!(collected, CollectedXattrs::Unknown);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[allow(clippy::disallowed_methods)]
fn symlink_xattrs_are_no_follow_and_link_metadata_stays_fail_closed() {
    let (temp, root) = setup_tree();
    let target = temp.path().join("outside-target");
    std::fs::write(&target, b"outside").unwrap();
    set_test_xattr(&target);
    std::fs::remove_file(root.join("link")).unwrap();
    std::os::unix::fs::symlink(&target, root.join("link")).unwrap();

    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    tree.rewalk_exact().unwrap();
    drop(tree);

    match set_symlink_test_xattr(&root.join("link")) {
        Ok(()) => assert!(matches!(
            collect(&temp, vec![], HeldTreeLimits::default()),
            Err(HeldTreeError::NonDirectoryExtendedMetadata(path)) if path == Path::new("link")
        )),
        Err(error) if link_self_xattr_is_unsupported(&error) => {
            eprintln!("platform refused link-self xattr fixture: {error}");
        }
        Err(error) => panic!("unexpected link-self xattr fixture failure: {error}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn link_self_xattr_is_unsupported(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|code| code == libc::EPERM || code == libc::EACCES || code == libc::ENOTSUP)
}

#[test]
fn schema_one_inventory_preserves_legacy_hardlink_semantics() {
    let (temp, root) = setup_tree();
    std::fs::hard_link(root.join("a/file"), root.join("a/hardlink")).unwrap();
    let held_parent = certify_held_fd(open_directory(temp.path())).unwrap();
    let legacy = HeldTreeInventory::collect_for_schema(
        held_parent,
        OsStr::new("root"),
        vec![],
        HeldTreeLimits::default(),
        1,
    )
    .unwrap();
    assert_eq!(legacy.fingerprint_for_schema(1).unwrap().schema_version, 1);
    legacy.rewalk_exact().unwrap();

    let held_parent = certify_held_fd(open_directory(temp.path())).unwrap();
    assert!(matches!(
        HeldTreeInventory::collect_for_schema(
            held_parent,
            OsStr::new("root"),
            vec![],
            HeldTreeLimits::default(),
            CONTENT_PROOF_VERSION,
        ),
        Err(HeldTreeError::ExternalHardLink(path)) if path == Path::new("a/file") || path == Path::new("a/hardlink")
    ));
}

#[test]
fn fingerprint_codec_is_domain_separated_raw_and_field_complete() {
    let base = ManifestEntry {
        path: PathBuf::from(OsString::from_vec(vec![b'a', 0xff])),
        identity: NodeIdentity {
            kind: NodeKind::Regular,
            device: 7,
            inode: 11,
            incarnation: 14,
        },
        uid: 12,
        gid: 13,
        mode: 0o640,
        content: ContentProof::Regular {
            size: 3,
            nlink: 1,
            mtime_sec: 17,
            mtime_nsec: 18,
            ctime_sec: 19,
            ctime_nsec: 20,
            sha256: [0x42; 32],
        },
    };
    let fingerprint = fingerprint_manifest_v1(std::slice::from_ref(&base));
    assert_eq!(fingerprint.entry_count, 1);
    assert_eq!(
        fingerprint.sha256,
        [
            0xfa, 0xe6, 0x37, 0xba, 0x3e, 0x80, 0xbb, 0x23, 0x91, 0xa9, 0x87, 0xf6, 0x50, 0xdf,
            0x16, 0x97, 0x6a, 0x03, 0x29, 0x3c, 0xda, 0x77, 0xaa, 0x38, 0xe4, 0x46, 0x1e, 0xe1,
            0x11, 0xc1, 0xc4, 0xd1,
        ]
    );
    let v2 = fingerprint_manifest_v2(std::slice::from_ref(&base));
    assert_eq!(v2.schema_version, CONTENT_PROOF_VERSION);
    assert_eq!(
        v2.sha256,
        [
            0x58, 0x90, 0x03, 0xec, 0x4f, 0x17, 0x6d, 0xb1, 0x1c, 0x87, 0x64, 0x53, 0x51, 0x40,
            0xe2, 0x4f, 0x44, 0x9d, 0xb3, 0x68, 0x1b, 0x8f, 0xe9, 0x19, 0xd1, 0x7e, 0x38, 0x1d,
            0x08, 0x2f, 0x33, 0xfc,
        ]
    );

    let mut variants = Vec::new();
    let mut value = base.clone();
    value.path = PathBuf::from("b");
    variants.push(value);
    let mut value = base.clone();
    value.identity.kind = NodeKind::Symlink;
    variants.push(value);
    let mut value = base.clone();
    value.identity.device += 1;
    variants.push(value);
    let mut value = base.clone();
    value.identity.inode += 1;
    variants.push(value);
    let mut value = base.clone();
    value.identity.incarnation += 1;
    variants.push(value);
    let mut value = base.clone();
    value.uid += 1;
    variants.push(value);
    let mut value = base.clone();
    value.gid += 1;
    variants.push(value);
    let mut value = base;
    value.mode ^= 1;
    variants.push(value);
    for variant in variants {
        assert_ne!(
            fingerprint_manifest_v1(&[variant]).sha256,
            fingerprint.sha256
        );
    }
}

#[test]
fn reused_device_and_inode_with_a_new_incarnation_is_changed() {
    let expected = NodeIdentity {
        kind: NodeKind::Regular,
        device: 7,
        inode: 11,
        incarnation: 14,
    };
    let actual = NodeIdentity {
        incarnation: 15,
        ..expected
    };
    assert!(matches!(
        require_same_identity(Path::new("victim"), expected, actual),
        Err(HeldTreeError::IdentityChanged(path)) if path == Path::new("victim")
    ));
}

#[test]
#[allow(clippy::disallowed_methods)]
fn content_proof_rejects_same_size_overwrite_and_symlink_target_change() {
    let (temp, root) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    std::fs::write(root.join("a/file"), b"two").unwrap();
    assert!(tree.rewalk_exact().is_err());

    let (temp, root) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    std::fs::remove_file(root.join("link")).unwrap();
    std::os::unix::fs::symlink("/tmp", root.join("link")).unwrap();
    assert!(tree.rewalk_exact().is_err());
}

#[test]
fn collection_rejects_external_regular_file_hardlinks() {
    let (temp, root) = setup_tree();
    std::fs::hard_link(root.join("a/file"), root.join("a/alias")).unwrap();
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::ExternalHardLink(_))
    ));
}

#[test]
fn content_hashing_is_aggregate_bounded() {
    let (temp, _) = setup_tree();
    assert!(matches!(
        collect(
            &temp,
            vec![],
            HeldTreeLimits {
                max_content_bytes: 2,
                ..HeldTreeLimits::default()
            },
        ),
        Err(HeldTreeError::Limit {
            kind: HeldTreeLimit::ContentBytes,
            ..
        })
    ));
}

#[test]
fn protected_policy_is_accepted_once_and_reused_by_rewalk() {
    let (temp, root) = setup_tree();
    let tree = collect(
        &temp,
        vec![OsString::from(".secret")],
        HeldTreeLimits::default(),
    )
    .unwrap();
    std::fs::create_dir(root.join(".secret")).unwrap();
    assert!(matches!(
        tree.rewalk_exact(),
        Err(HeldTreeError::ProtectedName(path)) if path == Path::new(".secret")
    ));

    let protected_root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(protected_root.path(), Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(protected_root.path().join(".ssh")).unwrap();
    assert!(matches!(
        HeldTreeInventory::collect(
            certify_held_fd(open_directory(protected_root.path())).unwrap(),
            OsStr::new(".ssh"),
            vec![OsString::from(".ssh")],
            HeldTreeLimits::default(),
        ),
        Err(HeldTreeError::ProtectedName(path)) if path.as_os_str().is_empty()
    ));
}

#[test]
fn both_walks_share_the_entry_bound() {
    let (temp, root) = setup_tree();
    let limits = HeldTreeLimits {
        max_entries: 5,
        ..HeldTreeLimits::default()
    };
    let tree = collect(&temp, vec![], limits).unwrap();
    std::fs::write(root.join("a/b/added"), b"attack").unwrap();
    assert!(matches!(
        tree.rewalk_exact(),
        Err(HeldTreeError::Limit {
            kind: HeldTreeLimit::Entries,
            ..
        })
    ));
}

#[test]
fn collect_enforces_directory_depth_path_and_manifest_bounds() {
    for (limits, expected) in [
        (
            HeldTreeLimits {
                max_directories: 1,
                ..HeldTreeLimits::default()
            },
            HeldTreeLimit::Directories,
        ),
        (
            HeldTreeLimits {
                max_depth: 0,
                ..HeldTreeLimits::default()
            },
            HeldTreeLimit::Depth,
        ),
        (
            HeldTreeLimits {
                max_path_bytes: 1,
                ..HeldTreeLimits::default()
            },
            HeldTreeLimit::PathBytes,
        ),
        (
            HeldTreeLimits {
                max_manifest_bytes: std::mem::size_of::<ManifestEntry>() as u64,
                ..HeldTreeLimits::default()
            },
            HeldTreeLimit::ManifestBytes,
        ),
    ] {
        let (temp, _) = setup_tree();
        assert!(matches!(
            collect(&temp, vec![], limits),
            Err(HeldTreeError::Limit { kind, .. }) if kind == expected
        ));
    }
}

#[test]
#[allow(clippy::disallowed_methods)]
fn rewalk_rejects_add_remove_replace_and_mode_change() {
    enum Attack {
        Add,
        Remove,
        Replace,
        Mode,
    }
    for attack in [Attack::Add, Attack::Remove, Attack::Replace, Attack::Mode] {
        let (temp, root) = setup_tree();
        let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
        match attack {
            Attack::Add => std::fs::write(root.join("added"), b"new").unwrap(),
            Attack::Remove => std::fs::remove_file(root.join("a/file")).unwrap(),
            Attack::Replace => {
                std::fs::rename(root.join("a/file"), root.join("a/old")).unwrap();
                std::fs::write(root.join("a/file"), b"two").unwrap();
            }
            Attack::Mode => {
                std::fs::set_permissions(root.join("a/b"), Permissions::from_mode(0o700)).unwrap()
            }
        }
        assert!(tree.rewalk_exact().is_err());
    }
}

#[test]
#[allow(clippy::disallowed_methods)]
fn final_root_binding_rejects_namespace_replacement() {
    let (temp, root) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let moved = temp.path().join("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &root).unwrap();
    assert!(matches!(
        tree.rewalk_exact(),
        Err(HeldTreeError::RootBindingChanged)
    ));
}

#[test]
fn root_binding_comparison_includes_mount_and_backend() {
    let identity = NodeIdentity {
        kind: NodeKind::Directory,
        device: 7,
        inode: 11,
        incarnation: 14,
    };
    let actual = Inspection {
        identity,
        uid: 1,
        gid: 1,
        mode: 0o700,
        size: 0,
        nlink: 1,
        mtime_sec: 0,
        mtime_nsec: 0,
        ctime_sec: 0,
        ctime_nsec: 0,
        content_fields_available: true,
        mount_id: 42,
        backend: CertifiedLocalBackend::Ext4,
    };
    assert!(root_binding_matches(
        identity,
        42,
        CertifiedLocalBackend::Ext4,
        &actual
    ));
    assert!(!root_binding_matches(
        identity,
        43,
        CertifiedLocalBackend::Ext4,
        &actual
    ));
    assert!(!root_binding_matches(
        identity,
        42,
        CertifiedLocalBackend::Xfs,
        &actual
    ));
    assert!(!root_binding_matches(
        NodeIdentity {
            device: 8,
            ..identity
        },
        42,
        CertifiedLocalBackend::Ext4,
        &actual
    ));
}

#[test]
fn source_parent_is_revalidated_as_exclusive() {
    let (temp, _) = setup_tree();
    std::fs::set_permissions(temp.path(), Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        collect(&temp, vec![], HeldTreeLimits::default()),
        Err(HeldTreeError::ParentNotExclusive)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn rewalk_rejects_acl_planted_after_collect() {
    use std::os::fd::AsRawFd;

    let (temp, _) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    // A named user entry plus a mask makes this a non-trivial ACL; the kernel
    // folds a bare user/group/other ACL back into the mode bits and stores no
    // xattr, which the probe would then correctly report as absent.
    let acl: [u8; 44] = [
        2, 0, 0, 0, // version
        1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ
        2, 0, 4, 0, 0, 0, 0, 0, // ACL_USER uid 0
        4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ
        0x10, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_MASK
        0x20, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER
    ];
    let result = with_fd(&tree.root.held, |fd| {
        // SAFETY: the FD and ACL buffer remain live for this syscall.
        unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        }
    });
    assert_eq!(
        result,
        0,
        "failed to plant test ACL: {}",
        io::Error::last_os_error()
    );
    assert!(matches!(
        tree.rewalk_exact(),
        Err(HeldTreeError::Certification {
            reason: CertificationError::AclPresent,
            ..
        })
    ));
}
