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

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID).unwrap_err();

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

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID).unwrap_err();

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

    let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("group- or world-writable"));
    assert!(error.to_string().contains("/root/shared"));
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
        let error = validate_owned_with(&tree, Path::new("/root"), TEST_UID).unwrap_err();
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
fn foreign_mutation_predicate_is_sticky_aware() {
    use super::directory_grants_foreign_mutation;

    // Group- or world-writable without sticky grants foreign mutation.
    assert!(directory_grants_foreign_mutation(0o777));
    assert!(directory_grants_foreign_mutation(0o770));
    assert!(directory_grants_foreign_mutation(0o707));
    // Private modes never do.
    assert!(!directory_grants_foreign_mutation(0o700));
    assert!(!directory_grants_foreign_mutation(0o755));
    // Sticky confines rename/delete to each entry's owner, so it is safe even
    // when group/world-writable.
    assert!(!directory_grants_foreign_mutation(0o1777));
    assert!(!directory_grants_foreign_mutation(0o1770));
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn trusted_parent_namespace_fails_closed_on_missing_and_untrusted() {
    use super::validate_trusted_parent_namespace;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();

    // Missing path fails closed.
    let missing = dir.path().join("absent");
    assert!(validate_trusted_parent_namespace(&missing).is_err());

    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = validate_trusted_parent_namespace(&parent).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains("group- or world-writable without the sticky bit")
    );

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777)).unwrap();
    validate_trusted_parent_namespace(&parent).unwrap();

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    validate_trusted_parent_namespace(&parent).unwrap();
}
