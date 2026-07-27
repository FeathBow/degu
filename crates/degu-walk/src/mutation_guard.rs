use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

mod platform;
use crate::mount::MountIdentity;

struct Root<Directory> {
    node: TreeNode<Directory>,
    parent_mount: Option<MountIdentity>,
}

struct TreeNode<Directory> {
    path: PathBuf,
    mount: MountIdentity,
    directory: Option<Directory>,
}

trait TreeAccess {
    type Directory;

    fn open_root(&self, path: &Path) -> io::Result<Root<Self::Directory>>;
    fn next_child(
        &self,
        directory: &mut Self::Directory,
    ) -> io::Result<Option<TreeNode<Self::Directory>>>;
}

/// Verifies that `root` and its no-follow descendants share the parent mount.
pub fn validate_single_mount_tree(root: &Path) -> io::Result<()> {
    validate_with(&platform::FileSystem, root)
}

fn validate_with(access: &impl TreeAccess, root: &Path) -> io::Result<()> {
    find_named_with(access, root, &[]).map(|_| ())
}

/// Finds a named descendant while enforcing [`validate_single_mount_tree`].
pub fn find_named_entry_single_mount(
    root: &Path,
    names: &[OsString],
) -> io::Result<Option<PathBuf>> {
    find_named_with(&platform::FileSystem, root, names)
}

fn find_named_with<Access: TreeAccess>(
    access: &Access,
    root: &Path,
    names: &[OsString],
) -> io::Result<Option<PathBuf>> {
    require_absolute(root)?;
    let opened = access.open_root(root)?;
    if opened
        .parent_mount
        .as_ref()
        .is_some_and(|parent| parent != &opened.node.mount)
    {
        return Err(root_mount_boundary(root));
    }
    let root_mount = opened.node.mount;
    let Some(directory) = opened.node.directory else {
        return Ok(None);
    };
    let validation = Validation {
        access,
        root,
        root_mount: &root_mount,
        names,
    };
    validation.find(directory)
}

fn require_absolute(root: &Path) -> io::Result<()> {
    if root.is_absolute() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tree mutation root must be absolute: {}", root.display()),
        ))
    }
}

struct Validation<'a, Access> {
    access: &'a Access,
    root: &'a Path,
    root_mount: &'a MountIdentity,
    names: &'a [OsString],
}

impl<Access: TreeAccess> Validation<'_, Access> {
    fn find(&self, root: Access::Directory) -> io::Result<Option<PathBuf>> {
        let mut pending = vec![root];
        while let Some(directory) = pending.last_mut() {
            let Some(node) = self.access.next_child(directory)? else {
                pending.pop();
                continue;
            };
            if node.mount != *self.root_mount {
                return Err(mount_boundary(self.root, &node.path));
            }
            if self.matches(&node.path) {
                return Ok(Some(node.path));
            }
            if let Some(directory) = node.directory {
                pending.push(directory);
            }
        }
        Ok(None)
    }

    fn matches(&self, path: &Path) -> bool {
        self.names
            .iter()
            .any(|name| path.file_name() == Some(name.as_os_str()))
    }
}

fn mount_boundary(root: &Path, path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "refusing tree mutation: mount boundary at {} differs from root {}",
            path.display(),
            root.display()
        ),
    )
}

fn root_mount_boundary(root: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "refusing tree mutation: root {} is a mount boundary relative to its parent",
            root.display()
        ),
    )
}

fn contextual_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "failed to {operation} {} while validating mount boundaries: {error}",
            path.display()
        ),
    )
}

#[cfg(test)]
#[path = "mutation_guard/tests.rs"]
mod tests;
