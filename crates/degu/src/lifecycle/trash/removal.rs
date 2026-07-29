use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use degu_core::oplog::ObjectIdentity;
use degu_walk::mount::MountIdentity;
use rustix::fd::OwnedFd;
use rustix::fs::Stat;

mod entry;
mod error;
mod identity;
use entry::{NamedEntry, open_directory_at};
use error::{contextual_error, require_same_mount};
use identity::{IdentityExpectation, kind_from_mode, object_identity_from_stat};

pub(in crate::lifecycle) use identity::{
    IdentityExpectation as ParentIdentityExpectation, object_identity_from_stat as parent_identity,
};

pub(super) fn remove(root: &Path, expected: ObjectIdentity) -> io::Result<()> {
    degu_walk::validate_single_mount_tree(root)?;
    let target = Target::open(root, expected)?;
    target.remove(expected)
}

struct Target {
    parent: OwnedFd,
    name: CString,
    path: PathBuf,
    mount: MountIdentity,
    directory: Option<OwnedFd>,
}

impl Target {
    fn open(path: &Path, expected: ObjectIdentity) -> io::Result<Self> {
        let (parent_path, name) = split_path(path)?;
        let parent = open_directory_at(rustix::fs::CWD, parent_path, parent_path)?;
        let parent_mount = degu_walk::mount::identity_for_fd(&parent, parent_path)?;
        let entry = NamedEntry::new(&parent, &name, path);
        IdentityExpectation::Exact(expected)
            .require(path, object_identity_from_stat(&entry.stat()?))?;
        let directory = entry.open_if_directory(expected)?;
        let mount = entry.mount(directory.as_ref(), &parent_mount)?;
        require_same_mount(path, &parent_mount, &mount)?;
        Ok(Self {
            parent,
            name,
            path: path.to_path_buf(),
            mount,
            directory,
        })
    }

    fn remove(self, expected: ObjectIdentity) -> io::Result<()> {
        let entry = NamedEntry::new(&self.parent, &self.name, &self.path);
        if let Some(directory) = self.directory {
            remove_directory_contents(&directory, &self.path, &self.mount)?;
            entry.unlink_directory(expected, &self.mount)
        } else {
            entry.unlink_file(expected, &self.mount)
        }
    }
}

fn remove_directory_contents(
    directory: &OwnedFd,
    path: &Path,
    root_mount: &MountIdentity,
) -> io::Result<()> {
    for name in directory_entries(directory, path)? {
        let child_path = path.join(OsStr::from_bytes(name.to_bytes()));
        let child = NamedEntry::new(directory, &name, &child_path);
        let before = child.stat()?;
        if kind_from_mode(before.st_mode) == degu_core::oplog::ObjectKind::Directory {
            remove_child_directory(&child, root_mount, &before)?;
        } else {
            remove_child_entry(&child, root_mount, &before)?;
        }
    }
    Ok(())
}

fn remove_child_directory(
    child: &NamedEntry<'_>,
    root_mount: &MountIdentity,
    before: &Stat,
) -> io::Result<()> {
    let directory = child.open_directory()?;
    let opened =
        object_identity_from_stat(&rustix::fs::fstat(&directory).map_err(io::Error::from)?);
    IdentityExpectation::Exact(object_identity_from_stat(before)).require(child.path(), opened)?;
    require_same_mount(
        child.path(),
        root_mount,
        &degu_walk::mount::identity_for_fd(&directory, child.path())?,
    )?;
    remove_directory_contents(&directory, child.path(), root_mount)?;
    child.unlink_directory(opened, root_mount)
}

fn remove_child_entry(
    child: &NamedEntry<'_>,
    root_mount: &MountIdentity,
    before: &Stat,
) -> io::Result<()> {
    let expected = object_identity_from_stat(before);
    child.unlink_file(expected, root_mount)
}

fn directory_entries(directory: &OwnedFd, path: &Path) -> io::Result<Vec<CString>> {
    let entries = rustix::fs::Dir::read_from(directory)
        .map_err(|error| contextual_error("read directory", path, error))?;
    entries
        .filter_map(|entry| match entry {
            Ok(entry) if matches!(entry.file_name().to_bytes(), b"." | b"..") => None,
            Ok(entry) => Some(Ok(entry.file_name().to_owned())),
            Err(error) => Some(Err(contextual_error("read directory", path, error))),
        })
        .collect()
}

fn split_path(path: &Path) -> io::Result<(&Path, CString)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let name = path.file_name();
    match (parent, name) {
        (Some(parent), Some(name)) => CString::new(name.as_bytes())
            .map(|name| (parent, name))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry name contains NUL")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("entry has no parent or file name: {}", path.display()),
        )),
    }
}
