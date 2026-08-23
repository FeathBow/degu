use degu_core::backend::{
    CertificationError, HeldLocalBackendEvidence, HeldTreeAssessmentFailureCategory,
    HeldTreeAssessmentFailureKind, HeldTreePolicyAssessmentOutcome, HeldTreePolicyDeferralReason,
    SourceParentSealAssessmentStatus, assess_held_tree_policy_metadata, certify_held_fd,
};
use rustix::fs::{Mode, OFlags};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"data").unwrap();
    (temp, root)
}

fn certified(path: &std::path::Path) -> Option<HeldLocalBackendEvidence> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    match certify_held_fd(fd) {
        Ok(evidence) => Some(evidence),
        Err(CertificationError::UnsupportedFilesystem) => {
            eprintln!("SKIP held-tree facade fixture: UnsupportedFilesystem");
            None
        }
        Err(CertificationError::UnsupportedPlatform) => {
            eprintln!("SKIP held-tree facade fixture: UnsupportedPlatform");
            None
        }
        Err(error) => panic!("unexpected certification failure: {error:?}"),
    }
}

#[test]
fn public_clean_tree_is_assessed_but_never_claims_seal_validation() {
    let (temp, _) = setup();
    let Some(parent) = certified(temp.path()) else {
        return;
    };
    match assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap() {
        HeldTreePolicyAssessmentOutcome::TreePolicyAssessed {
            tree,
            source_parent_seal,
        } => {
            assert_eq!(tree.entries, 2);
            assert_eq!(tree.directories, 1);
            assert_eq!(
                source_parent_seal.validation,
                SourceParentSealAssessmentStatus::RequiresExecutionValidation
            );
        }
        other => panic!("clean tree was not assessed: {other:?}"),
    }

    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
    let parent = certified(temp.path()).expect("certified backend changed within fixture");
    let outcome = assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap();
    assert!(matches!(
        outcome,
        HeldTreePolicyAssessmentOutcome::TreePolicyDeferredUntilSourceParentSeal {
            reason: HeldTreePolicyDeferralReason::SourceParentSearchRequiresExecutionSeal,
            source_parent_seal: degu_core::backend::SourceParentSealAssessment {
                validation: SourceParentSealAssessmentStatus::RequiresExecutionValidation,
                ..
            },
        }
    ));
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn public_default_directory_boundary_and_hardlink_are_structured() {
    const MAX_TREE_DIRECTORIES: usize = 1_023;

    let (temp, root) = setup();
    // The root is included, so 1,022 children are exactly the production bound.
    for index in 0..(MAX_TREE_DIRECTORIES - 1) {
        std::fs::create_dir(root.join(format!("d{index:04}"))).unwrap();
    }
    let Some(parent) = certified(temp.path()) else {
        return;
    };
    let outcome = assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap();
    let HeldTreePolicyAssessmentOutcome::TreePolicyAssessed { tree, .. } = outcome else {
        panic!("searchable boundary tree assessment unexpectedly deferred")
    };
    assert_eq!(tree.directories, MAX_TREE_DIRECTORIES as u64);

    // One more child makes 1,024 total tree directories. Recovery also needs
    // one source-parent permission, so policy must reject this boundary.
    std::fs::create_dir(root.join("over-limit")).unwrap();
    let Some(parent) = certified(temp.path()) else {
        return;
    };
    let error = assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap_err();
    assert_eq!(
        error.kind(),
        HeldTreeAssessmentFailureKind::DirectoryLimitExceeded
    );
    assert_eq!(
        error.category(),
        HeldTreeAssessmentFailureCategory::ResourceLimit
    );
    assert!(error.relative_path().is_none());
    assert_eq!(
        error.to_string(),
        "held-tree assessment failed: directory limit exceeded"
    );

    let (temp, root) = setup();
    std::fs::hard_link(root.join("file"), root.join("other")).unwrap();
    let Some(parent) = certified(temp.path()) else {
        return;
    };
    let error = assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap_err();
    assert_eq!(
        error.kind(),
        HeldTreeAssessmentFailureKind::ExternalHardLink
    );
    assert!(
        matches!(error.relative_path(), Some(path) if path == std::path::Path::new("file") || path == std::path::Path::new("other"))
    );
}

#[test]
fn public_facade_always_applies_the_production_protected_name_policy() {
    let (temp, root) = setup();
    let protected = degu_core::safety::PROTECTED_DESCENDANT_DIR_NAMES[0];
    std::fs::create_dir(root.join(protected)).unwrap();
    let Some(parent) = certified(temp.path()) else {
        return;
    };

    let error = assess_held_tree_policy_metadata(parent, OsStr::new("root")).unwrap_err();
    assert_eq!(error.kind(), HeldTreeAssessmentFailureKind::ProtectedName);
    assert_eq!(error.relative_path(), Some(std::path::Path::new(protected)));
}
