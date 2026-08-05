use std::ffi::OsString;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

mod platform;
use crate::mount::MountIdentity;

/// Group/other write bits: either grants a non-owner the authority to add or
/// remove names in a directory.
const SHARED_WRITE_MASK: u32 = 0o022;
/// Restricted-deletion ("sticky") bit: when set on a directory, only an entry's
/// owner may rename or delete it, so a shared-writable directory is safe.
const STICKY_BIT: u32 = 0o1000;

/// True when a directory of `mode` owned by `uid` grants namespace-mutation
/// authority to a principal other than the invoking `euid`: the owner is foreign
/// (a foreign owner can always chmod the directory to `0777` and can, being the
/// directory owner, rename or delete any entry even when the sticky bit is set),
/// OR it is group/world-writable AND not sticky. This is the companion to the
/// tree-internal [`require_private_directory`] predicate (which refuses any
/// shared-writable directory), used for the finding root's PARENT: a foreign
/// owner is never trusted, and a same-owner shared parent is safe only when the
/// sticky bit confines rename/delete to each entry's owner.
pub fn directory_grants_foreign_mutation(uid: u32, mode: u32, euid: u32) -> bool {
    uid != euid || (mode & SHARED_WRITE_MASK != 0 && mode & STICKY_BIT == 0)
}

/// Reads the resolved parent directory's live owner and mode (follows symlinks,
/// matching the stage-side `open_directory_following`) and fails closed unless it
/// is a trusted namespace: an untrusted writer must not be able to swap
/// `parent`'s entries. A foreign owner is untrusted regardless of mode (it can
/// chmod to `0777` at will and, as the directory owner, sticky does not confine
/// it), so trust requires ownership by `euid` AND a mode that is not
/// shared-writable-without-sticky. The directory whose write-permissions matter
/// is the real directory the entries live in, not a symlink pointing at it. Any
/// error reading the resolved metadata (broken symlink, EACCES, ...) is a
/// refusal, never a pass; the authoritative anti-swap gate remains the held-FD
/// rename.
pub fn validate_trusted_parent_namespace(parent: &Path, euid: u32) -> io::Result<()> {
    let metadata = std::fs::metadata(parent).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "refusing tree mutation: could not read parent directory metadata at {}: {error}",
                parent.display()
            ),
        )
    })?;
    if metadata.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing tree mutation: parent directory {} is owned by UID {} not the invoking UID {euid}",
                parent.display(),
                metadata.uid()
            ),
        ));
    }
    if directory_grants_foreign_mutation(metadata.uid(), metadata.mode(), euid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing tree mutation: parent directory {} is group- or world-writable without the sticky bit",
                parent.display()
            ),
        ));
    }
    Ok(())
}

struct Root<Directory> {
    node: TreeNode<Directory>,
    parent_mount: Option<MountIdentity>,
}

struct TreeNode<Directory> {
    path: PathBuf,
    mount: MountIdentity,
    uid: Option<u32>,
    mode: Option<u32>,
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

/// Verifies the single-mount boundary, invoking-user ownership, and absence of
/// group/world-writable directories for the complete no-follow tree. Intended
/// for staging live findings; trash purge and undo validate mount/identity
/// separately and must not reinterpret old data.
pub fn validate_owned_single_mount_tree(root: &Path, required_uid: u32) -> io::Result<()> {
    validate_owned_with(&platform::FileSystem, root, required_uid, &[]).map(|_| ())
}

/// The staging-boundary gate: one no-follow descriptor traversal that enforces
/// ALL of the invariants the rename-into-trash depends on -- single-mount
/// boundary, invoking-user ownership, absence of group/world-writable
/// directories, AND the absence of any descendant whose name matches
/// `protected_names` (the built-in credential / mixed-state AI-tool directory
/// names). Folding the protected-name check into the same pass as ownership
/// closes the window a same-UID process had to plant a protected directory
/// (`.ssh`, `.aws`, `.codex`, ...) inside the tree DURING an earlier,
/// non-constant-time ownership traversal. A descendant name match is a refusal,
/// not a returned path. Config-`protect` PATH overlaps and the root's own name
/// are outside this descriptor walk and stay in the path-based protection check.
pub fn reject_protected_in_owned_single_mount_tree(
    root: &Path,
    required_uid: u32,
    protected_names: &[OsString],
) -> io::Result<()> {
    match validate_owned_with(&platform::FileSystem, root, required_uid, protected_names)? {
        None => Ok(()),
        Some(protected) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing tree mutation: protected directory name at {} inside {}",
                protected.display(),
                root.display()
            ),
        )),
    }
}

fn validate_with(access: &impl TreeAccess, root: &Path) -> io::Result<()> {
    find_named_with(access, root, &[], None).map(|_| ())
}

fn validate_owned_with(
    access: &impl TreeAccess,
    root: &Path,
    required_uid: u32,
    names: &[OsString],
) -> io::Result<Option<PathBuf>> {
    find_named_with(access, root, names, Some(required_uid))
}

/// Finds a named descendant while enforcing [`validate_single_mount_tree`].
pub fn find_named_entry_single_mount(
    root: &Path,
    names: &[OsString],
) -> io::Result<Option<PathBuf>> {
    find_named_with(&platform::FileSystem, root, names, None)
}

fn find_named_with<Access: TreeAccess>(
    access: &Access,
    root: &Path,
    names: &[OsString],
    required_uid: Option<u32>,
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
    require_uid(&opened.node.path, opened.node.uid, required_uid)?;
    require_private_directory(
        &opened.node.path,
        opened.node.mode,
        opened.node.directory.is_some(),
        required_uid,
    )?;
    let root_mount = opened.node.mount;
    let Some(directory) = opened.node.directory else {
        return Ok(None);
    };
    let validation = Validation {
        access,
        root,
        root_mount: &root_mount,
        names,
        required_uid,
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
    required_uid: Option<u32>,
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
            require_uid(&node.path, node.uid, self.required_uid)?;
            require_private_directory(
                &node.path,
                node.mode,
                node.directory.is_some(),
                self.required_uid,
            )?;
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

fn require_uid(path: &Path, actual: Option<u32>, required: Option<u32>) -> io::Result<()> {
    let Some(required) = required else {
        return Ok(());
    };
    let actual = actual.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing tree mutation: UID metadata unavailable at {}",
                path.display()
            ),
        )
    })?;
    if actual == required {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing tree mutation: UID {actual} at {} differs from required UID {required}",
            path.display()
        ),
    ))
}

fn require_private_directory(
    path: &Path,
    mode: Option<u32>,
    is_directory: bool,
    required_uid: Option<u32>,
) -> io::Result<()> {
    if required_uid.is_none() || !is_directory {
        return Ok(());
    }
    let mode = mode.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing tree mutation: mode metadata unavailable at {}",
                path.display()
            ),
        )
    })?;
    if mode & 0o022 == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing tree mutation: group- or world-writable directory at {}",
            path.display()
        ),
    ))
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
