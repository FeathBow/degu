use super::*;

const ROOT_MOUNT: u8 = 1;
const OTHER_MOUNT: u8 = 2;

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
}

impl<'a> FakeTree<'a> {
    fn clean(nodes: &'a [FixtureNode]) -> Self {
        Self {
            nodes,
            parent_mount: ROOT_MOUNT,
            inspect_error: None,
            read_error: None,
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
        Ok(TreeNode {
            path: path.to_path_buf(),
            mount: MountIdentity::fake(node.mount),
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
