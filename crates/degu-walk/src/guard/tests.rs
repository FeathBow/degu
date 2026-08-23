use super::*;

const ROOT_MOUNT: u8 = 1;
const OTHER_MOUNT: u8 = 2;
const TEST_UID: u32 = 1000;
const FOREIGN_UID: u32 = 2000;

#[derive(Clone, Copy)]
enum FixtureKind {
    Directory,
    Other,
}

struct FixtureNode {
    path: &'static str,
    kind: FixtureKind,
    mount: u8,
    children: &'static [&'static str],
}

struct FakeDirectory {
    path: PathBuf,
    next_child: usize,
}

struct FakeTree<'a> {
    nodes: &'a [FixtureNode],
    parent_mount: u8,
    inspect_error: Option<&'static str>,
    read_error: Option<&'static str>,
    foreign_uid_path: Option<&'static str>,
    shared_writable_path: Option<&'static str>,
    missing_uid_path: Option<&'static str>,
    missing_mode_path: Option<&'static str>,
}

impl<'a> FakeTree<'a> {
    fn clean(nodes: &'a [FixtureNode]) -> Self {
        Self {
            nodes,
            parent_mount: ROOT_MOUNT,
            inspect_error: None,
            read_error: None,
            foreign_uid_path: None,
            shared_writable_path: None,
            missing_uid_path: None,
            missing_mode_path: None,
        }
    }

    fn node(&self, path: &Path) -> &FixtureNode {
        self.nodes
            .iter()
            .find(|node| path == Path::new(node.path))
            .expect("fixture path")
    }

    fn open_node(&self, path: &Path) -> io::Result<TreeNode<FakeDirectory>> {
        if self
            .inspect_error
            .is_some_and(|failed| path == Path::new(failed))
        {
            let error = io::Error::new(io::ErrorKind::PermissionDenied, "probe denied");
            return Err(contextual_error("inspect", path, error));
        }
        let node = self.node(path);
        let directory = matches!(node.kind, FixtureKind::Directory).then(|| FakeDirectory {
            path: path.to_path_buf(),
            next_child: 0,
        });
        let uid = if self
            .foreign_uid_path
            .is_some_and(|foreign| path == Path::new(foreign))
        {
            FOREIGN_UID
        } else {
            TEST_UID
        };
        let mode = if self
            .shared_writable_path
            .is_some_and(|shared| path == Path::new(shared))
        {
            0o770
        } else {
            0o700
        };
        let uid = self
            .missing_uid_path
            .is_none_or(|missing| path != Path::new(missing))
            .then_some(uid);
        let mode = self
            .missing_mode_path
            .is_none_or(|missing| path != Path::new(missing))
            .then_some(mode);
        Ok(TreeNode {
            path: path.to_path_buf(),
            mount: MountIdentity::fake(node.mount),
            uid,
            mode,
            directory,
        })
    }
}

impl TreeAccess for FakeTree<'_> {
    type Directory = FakeDirectory;

    fn open_root(&self, path: &Path) -> io::Result<Root<Self::Directory>> {
        Ok(Root {
            node: self.open_node(path)?,
            parent_mount: Some(MountIdentity::fake(self.parent_mount)),
        })
    }

    fn next_child(
        &self,
        directory: &mut Self::Directory,
    ) -> io::Result<Option<TreeNode<Self::Directory>>> {
        if self
            .read_error
            .is_some_and(|failed| directory.path == Path::new(failed))
        {
            let error = io::Error::new(io::ErrorKind::PermissionDenied, "read denied");
            return Err(contextual_error("read", &directory.path, error));
        }
        let node = self.node(&directory.path);
        let Some(child) = node.children.get(directory.next_child) else {
            return Ok(None);
        };
        directory.next_child += 1;
        self.open_node(Path::new(child)).map(Some)
    }
}

#[test]
fn rejects_a_root_that_is_itself_a_mount_boundary() {
    for kind in [FixtureKind::Directory, FixtureKind::Other] {
        let nodes = [FixtureNode {
            path: "/root",
            kind,
            mount: OTHER_MOUNT,
            children: &[],
        }];

        let error = validate_with(&FakeTree::clean(&nodes), Path::new("/root")).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("root /root is a mount boundary"));
    }
}

#[test]
fn accepts_a_root_beneath_a_symlinked_parent_on_its_containing_mount() {
    let temp = tempfile::tempdir().unwrap();
    let actual_parent = temp.path().join("actual-parent");
    let root = actual_parent.join("root");
    let alias = temp.path().join("alias");
    std::fs::create_dir(&actual_parent).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(&actual_parent, &alias).unwrap();

    validate_single_mount_tree(&alias.join("root")).unwrap();
}

#[test]
fn does_not_follow_a_root_symlink_with_trailing_components() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    let alias = temp.path().join("alias");
    std::fs::create_dir(&outside).unwrap();
    std::fs::create_dir(outside.join(".codex")).unwrap();
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    let names = [OsString::from(".codex")];

    for suffix in ["/", "/."] {
        let root = PathBuf::from(format!("{}{suffix}", alias.display()));
        let found = find_named_entry_single_mount(&root, &names).unwrap();
        assert_eq!(found, None);
    }
}

#[test]
fn rejects_a_descendant_on_another_mount_without_descending() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/mounted"],
        },
        FixtureNode {
            path: "/root/mounted",
            kind: FixtureKind::Directory,
            mount: OTHER_MOUNT,
            children: &["/must-not-be-read"],
        },
    ];

    let error = validate_with(&FakeTree::clean(&nodes), Path::new("/root")).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("/root/mounted"));
}

#[test]
fn fails_closed_when_a_descendant_cannot_be_inspected() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/unknown"],
        },
        FixtureNode {
            path: "/root/unknown",
            kind: FixtureKind::Other,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let tree = FakeTree {
        inspect_error: Some("/root/unknown"),
        ..FakeTree::clean(&nodes)
    };

    let error = validate_with(&tree, Path::new("/root")).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains("failed to inspect /root/unknown")
    );
}

#[test]
fn fails_closed_when_a_directory_cannot_be_read() {
    let nodes = [FixtureNode {
        path: "/root",
        kind: FixtureKind::Directory,
        mount: ROOT_MOUNT,
        children: &[],
    }];
    let tree = FakeTree {
        read_error: Some("/root"),
        ..FakeTree::clean(&nodes)
    };

    let error = validate_with(&tree, Path::new("/root")).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("failed to read /root"));
}

#[test]
fn owned_validation_rejects_a_foreign_root() {
    let nodes = [FixtureNode {
        path: "/root",
        kind: FixtureKind::Directory,
        mount: ROOT_MOUNT,
        children: &[],
    }];
    let tree = FakeTree {
        foreign_uid_path: Some("/root"),
        ..FakeTree::clean(&nodes)
    };

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID, &[]).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("UID 2000 at /root"));
    assert!(error.to_string().contains("required UID 1000"));
}

#[test]
fn owned_validation_rejects_a_foreign_descendant() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/owned", "/root/foreign"],
        },
        FixtureNode {
            path: "/root/owned",
            kind: FixtureKind::Other,
            mount: ROOT_MOUNT,
            children: &[],
        },
        FixtureNode {
            path: "/root/foreign",
            kind: FixtureKind::Other,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let tree = FakeTree {
        foreign_uid_path: Some("/root/foreign"),
        ..FakeTree::clean(&nodes)
    };

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID, &[]).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("/root/foreign"));
}

#[test]
fn owned_validation_rejects_a_shared_writable_directory() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/shared"],
        },
        FixtureNode {
            path: "/root/shared",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let tree = FakeTree {
        shared_writable_path: Some("/root/shared"),
        ..FakeTree::clean(&nodes)
    };

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID, &[]).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("group- or world-writable"));
    assert!(error.to_string().contains("/root/shared"));
}

#[test]
fn owned_validation_finds_a_protected_descendant_name_in_the_ownership_pass() {
    // The combined final gate spots a protected directory name (e.g. `.aws`)
    // planted inside the tree in the SAME traversal that enforces ownership and
    // mount -- no separate recheck pass is consulted. Every node here is
    // EUID-owned and private, so the returned match comes ONLY from the name
    // check riding the ownership traversal.
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/nested"],
        },
        FixtureNode {
            path: "/root/nested",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/nested/.aws"],
        },
        FixtureNode {
            path: "/root/nested/.aws",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let protected = [OsString::from(".aws"), OsString::from(".ssh")];

    let found = validate_owned_with(
        &FakeTree::clean(&nodes),
        Path::new("/root"),
        TEST_UID,
        &protected,
    )
    .unwrap()
    .expect("protected descendant found");
    assert_eq!(found, Path::new("/root/nested/.aws"));

    // With no protected names the same clean tree passes: the match above was
    // the name check, not ownership or mount.
    assert_eq!(
        validate_owned_with(&FakeTree::clean(&nodes), Path::new("/root"), TEST_UID, &[]).unwrap(),
        None
    );
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn combined_owned_validator_refuses_a_real_protected_descendant() {
    use std::os::unix::fs::PermissionsExt;

    // The public FS-backed combined entry point turns a protected descendant
    // name into a fail-closed PermissionDenied error in a single traversal.
    let euid = rustix::process::geteuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cache");
    let nested = root.join("nested");
    let protected_dir = nested.join(".aws");
    std::fs::create_dir_all(&protected_dir).unwrap();
    // Keep the ambient umask from triggering the mode guard before the name guard.
    for path in [&root, &nested, &protected_dir] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let protected = [OsString::from(".aws"), OsString::from(".ssh")];

    let error = reject_protected_in_owned_single_mount_tree(&root, euid, &protected).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains(".aws"), "{error}");
    assert!(
        error.to_string().contains("protected directory name"),
        "{error}"
    );

    // A sibling tree with the same shape but no protected descendant passes: the
    // refusal above is the name check, not ownership or mount.
    let clean_root = dir.path().join("clean");
    let clean_nested = clean_root.join("nested");
    let safe = clean_nested.join("safe");
    std::fs::create_dir_all(&safe).unwrap();
    for path in [&clean_root, &clean_nested, &safe] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    reject_protected_in_owned_single_mount_tree(&clean_root, euid, &protected).unwrap();
}

#[test]
fn owned_validation_fails_closed_when_uid_or_mode_metadata_is_unavailable() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/child"],
        },
        FixtureNode {
            path: "/root/child",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    for tree in [
        FakeTree {
            missing_uid_path: Some("/root/child"),
            ..FakeTree::clean(&nodes)
        },
        FakeTree {
            missing_mode_path: Some("/root/child"),
            ..FakeTree::clean(&nodes)
        },
    ] {
        let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID, &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("metadata unavailable"));
    }
}

#[test]
fn mount_only_validation_accepts_unavailable_uid_and_mode_metadata() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/child"],
        },
        FixtureNode {
            path: "/root/child",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let tree = FakeTree {
        missing_uid_path: Some("/root/child"),
        missing_mode_path: Some("/root/child"),
        ..FakeTree::clean(&nodes)
    };

    validate_with(&tree, Path::new("/root")).unwrap();
}

#[test]
fn mount_only_validation_does_not_reinterpret_existing_tree_ownership() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/foreign"],
        },
        FixtureNode {
            path: "/root/foreign",
            kind: FixtureKind::Other,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];
    let tree = FakeTree {
        foreign_uid_path: Some("/root/foreign"),
        ..FakeTree::clean(&nodes)
    };

    validate_with(&tree, Path::new("/root")).unwrap();
}

#[test]
fn accepts_a_single_mount_tree() {
    let nodes = [
        FixtureNode {
            path: "/root",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &["/root/dir", "/root/file"],
        },
        FixtureNode {
            path: "/root/dir",
            kind: FixtureKind::Directory,
            mount: ROOT_MOUNT,
            children: &[],
        },
        FixtureNode {
            path: "/root/file",
            kind: FixtureKind::Other,
            mount: ROOT_MOUNT,
            children: &[],
        },
    ];

    validate_with(&FakeTree::clean(&nodes), Path::new("/root")).unwrap();
}

#[test]
fn foreign_mutation_predicate_is_sticky_and_owner_aware() {
    use super::directory_grants_foreign_mutation;

    const EUID: u32 = TEST_UID;

    // Owned by the invoking EUID: group- or world-writable without sticky grants
    // foreign mutation.
    assert!(directory_grants_foreign_mutation(EUID, 0o777, EUID));
    assert!(directory_grants_foreign_mutation(EUID, 0o770, EUID));
    assert!(directory_grants_foreign_mutation(EUID, 0o707, EUID));
    // Owned by the invoking EUID: private modes never do.
    assert!(!directory_grants_foreign_mutation(EUID, 0o700, EUID));
    assert!(!directory_grants_foreign_mutation(EUID, 0o755, EUID));
    // Owned by the invoking EUID: sticky confines rename/delete to each entry's
    // owner, so it is safe even when group/world-writable.
    assert!(!directory_grants_foreign_mutation(EUID, 0o1777, EUID));
    assert!(!directory_grants_foreign_mutation(EUID, 0o1770, EUID));
    // A non-root foreign owner is never trusted regardless of mode: the owner can
    // chmod to 0777 at will and, as the directory owner, sticky does not confine
    // it.
    assert!(directory_grants_foreign_mutation(FOREIGN_UID, 0o700, EUID));
    assert!(directory_grants_foreign_mutation(FOREIGN_UID, 0o755, EUID));
    assert!(directory_grants_foreign_mutation(FOREIGN_UID, 0o1777, EUID));
}

#[test]
fn foreign_mutation_predicate_exempts_root_owner_from_the_owner_clause() {
    use super::directory_grants_foreign_mutation;

    const EUID: u32 = TEST_UID;
    const ROOT_UID: u32 = 0;

    // Root ownership is out of the unprivileged threat model, so the OWNER clause
    // never demotes a root-owned parent: a private or sticky-world-writable
    // root-owned dir (`/tmp`, container roots, HPC scratch) stays trusted.
    assert!(!directory_grants_foreign_mutation(ROOT_UID, 0o755, EUID));
    assert!(!directory_grants_foreign_mutation(ROOT_UID, 0o1777, EUID));
    // The MODE clause still fires for a root-owned dir that is world-writable
    // without sticky: a non-root principal could swap its entries.
    assert!(directory_grants_foreign_mutation(ROOT_UID, 0o777, EUID));
    // The euid-owner cases are unaffected by the exemption.
    assert!(!directory_grants_foreign_mutation(EUID, 0o755, EUID));
    assert!(!directory_grants_foreign_mutation(EUID, 0o1777, EUID));
    assert!(directory_grants_foreign_mutation(EUID, 0o777, EUID));
    // A NON-root foreign owner is still distrusted by the owner clause, even when
    // sticky -- the owner can rename or delete any entry.
    assert!(directory_grants_foreign_mutation(FOREIGN_UID, 0o755, EUID));
    assert!(directory_grants_foreign_mutation(FOREIGN_UID, 0o1777, EUID));
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn trusted_parent_namespace_fails_closed_on_missing_and_untrusted() {
    use super::validate_trusted_parent_namespace;
    use std::os::unix::fs::PermissionsExt;

    let euid = rustix::process::geteuid().as_raw();
    let dir = tempfile::tempdir().unwrap();

    // Missing path fails closed.
    let missing = dir.path().join("absent");
    assert!(validate_trusted_parent_namespace(&missing, euid).is_err());

    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = validate_trusted_parent_namespace(&parent, euid).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains("group- or world-writable without the sticky bit")
    );

    // Even sticky no longer whitelists a FOREIGN owner: a same-owner sticky
    // parent is trusted, but claiming a different EUID must refuse it.
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777)).unwrap();
    validate_trusted_parent_namespace(&parent, euid).unwrap();
    let foreign_error =
        validate_trusted_parent_namespace(&parent, euid.wrapping_add(1)).unwrap_err();
    assert_eq!(foreign_error.kind(), io::ErrorKind::PermissionDenied);
    assert!(foreign_error.to_string().contains("owned by UID"));

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    validate_trusted_parent_namespace(&parent, euid).unwrap();
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn trusted_parent_namespace_follows_a_symlinked_parent() {
    use super::validate_trusted_parent_namespace;
    use std::os::unix::fs::PermissionsExt;

    let euid = rustix::process::geteuid().as_raw();
    let dir = tempfile::tempdir().unwrap();

    // A symlink to a private 0700 directory resolves to a trusted namespace: the
    // resolved directory's mode is authoritative, not the symlink's own mode
    // (which is 0o777 on Linux, where the old no-follow read wrongly refused).
    let trusted_target = dir.path().join("trusted-target");
    std::fs::create_dir(&trusted_target).unwrap();
    std::fs::set_permissions(&trusted_target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let trusted_link = dir.path().join("trusted-link");
    std::os::unix::fs::symlink(&trusted_target, &trusted_link).unwrap();
    validate_trusted_parent_namespace(&trusted_link, euid).unwrap();

    // A symlink to a world-writable, non-sticky directory is refused: following
    // resolves to the untrusted target.
    let untrusted_target = dir.path().join("untrusted-target");
    std::fs::create_dir(&untrusted_target).unwrap();
    std::fs::set_permissions(&untrusted_target, std::fs::Permissions::from_mode(0o777)).unwrap();
    let untrusted_link = dir.path().join("untrusted-link");
    std::os::unix::fs::symlink(&untrusted_target, &untrusted_link).unwrap();
    let error = validate_trusted_parent_namespace(&untrusted_link, euid).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains("group- or world-writable without the sticky bit")
    );
}
