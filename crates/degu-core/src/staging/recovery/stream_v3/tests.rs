use super::*;
use crate::authority::PersistentRecoveryEvidence;

fn plan(path: &str, pre_mode: u32) -> RecoveryPermissionPlan {
    RecoveryPermissionPlan {
        permission: DurablePermission {
            mutation_id: 1,
            phase: TransactionState::TreeSealIntent,
            evidence: PersistentRecoveryEvidence::new(
                PathBuf::from(path),
                Some("test-fs".into()),
                1,
                2,
                Some(3),
                0o500,
            )
            .unwrap(),
            pre_mode,
            expected_mode: 0o500,
            reverses_mutation_id: None,
            application: ApplicationStatus::Applied,
        },
        side: RecoveryAnchorSide::Destination,
        relative_path: PathBuf::from(path),
        chain: Vec::new(),
    }
}

/// A directory's modes come back for its own path, as restored or as sealed.
/// A path two plans name, a path no plan names, and every path once a plan
/// lies outside the destination root are refused, as the scan the index
/// replaced refused them.
#[test]
fn modes_by_path() {
    let root = Path::new("trash/entry/pip");
    let plans = [
        plan("trash/entry/pip", 0o755),
        plan("trash/entry/pip/a", 0o700),
        plan("trash/entry/pip/b", 0o750),
        plan("trash/entry/pip/b", 0o750),
    ];

    let sealed = DirectoryModes::new(&plans[..3], root, false);
    assert_eq!(sealed.get(Path::new("")).unwrap(), (0o500, 0o500));
    assert_eq!(sealed.get(Path::new("a")).unwrap(), (0o500, 0o500));
    let restored = DirectoryModes::new(&plans[..3], root, true);
    assert_eq!(restored.get(Path::new("")).unwrap(), (0o755, 0o500));
    assert_eq!(restored.get(Path::new("a")).unwrap(), (0o700, 0o500));
    assert!(matches!(
        restored.get(Path::new("c")),
        Err(RecoveryRebindError::UndoManifestChanged)
    ));

    let duplicated = DirectoryModes::new(&plans, root, true);
    assert_eq!(duplicated.get(Path::new("a")).unwrap(), (0o700, 0o500));
    assert!(matches!(
        duplicated.get(Path::new("b")),
        Err(RecoveryRebindError::UndoManifestChanged)
    ));

    let outside = [plan("trash/entry/pip/a", 0o700), plan("trash/other", 0o700)];
    let misplaced = DirectoryModes::new(&outside, root, true);
    assert!(matches!(
        misplaced.get(Path::new("a")),
        Err(RecoveryRebindError::InvalidLocator)
    ));
}

fn io_failure(code: i32) -> TreeSidecarError {
    TreeSidecarError::Io {
        path: PathBuf::from("/store/run"),
        source: io::Error::from_raw_os_error(code),
    }
}

/// What the hardlink records showed decides when only a full disk stopped the
/// fold tidying up. Any other failure keeps its place ahead of them.
#[test]
fn hardlinks_outrank_removal() {
    for code in [libc::ENOSPC, libc::EDQUOT] {
        assert!(matches!(
            hardlink_fold_failure(io_failure(code), HardlinkTopologyFold::miscounted()),
            RecoveryRebindError::UndoManifestChanged
        ));
        assert!(
            hardlink_fold_failure(io_failure(code), HardlinkTopologyFold::new()).is_disk_full()
        );
    }
    assert!(matches!(
        hardlink_fold_failure(io_failure(libc::EIO), HardlinkTopologyFold::miscounted()),
        RecoveryRebindError::Sidecar(_)
    ));
}

/// A full disk never replaces what a check found, and anything else still does.
#[test]
fn outrank_keeps_findings() {
    let disk = || sidecar_error(io_failure(libc::EDQUOT));
    let damage = || sidecar_error(TreeSidecarError::InvalidScratch("damaged"));
    assert!(matches!(
        outrank_primary(Err(disk()), Err(disk()), manifest_changed()),
        RecoveryRebindError::UndoManifestChanged
    ));
    assert!(matches!(
        outrank_primary(Ok(()), Err(damage()), manifest_changed()),
        RecoveryRebindError::Sidecar(TreeSidecarError::InvalidScratch(_))
    ));
    assert!(matches!(
        outrank_primary(Err(disk()), Err(damage()), manifest_changed()),
        RecoveryRebindError::Sidecar(TreeSidecarError::InvalidScratch(_))
    ));
    assert!(outrank_primary(Ok(()), Ok(()), disk()).is_disk_full());
}
