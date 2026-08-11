use super::*;
use crate::local_backend::certify_held_fd;
use std::fs::Permissions;
#[cfg(target_os = "linux")]
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

#[test]
fn bounded_collect_retains_every_directory_and_exact_rewalks() {
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
    };
    let fingerprint = fingerprint_manifest(std::slice::from_ref(&base));
    assert_eq!(fingerprint.entry_count, 1);
    assert_eq!(
        fingerprint.sha256,
        [
            0xfa, 0xe6, 0x37, 0xba, 0x3e, 0x80, 0xbb, 0x23, 0x91, 0xa9, 0x87, 0xf6, 0x50, 0xdf,
            0x16, 0x97, 0x6a, 0x03, 0x29, 0x3c, 0xda, 0x77, 0xaa, 0x38, 0xe4, 0x46, 0x1e, 0xe1,
            0x11, 0xc1, 0xc4, 0xd1,
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
        assert_ne!(fingerprint_manifest(&[variant]).sha256, fingerprint.sha256);
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
fn fingerprint_is_stable_after_inventory_sorting() {
    let (temp, _) = setup_tree();
    let tree = collect(&temp, vec![], HeldTreeLimits::default()).unwrap();
    let first = tree.fingerprint();
    let second = tree.fingerprint();
    assert_eq!(first, second);
    assert_eq!(first.entry_count, tree.entry_count());
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
    let result = with_fd(&tree.directories[0].held, |fd| {
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
