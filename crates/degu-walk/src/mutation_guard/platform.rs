use super::{Root, TreeAccess, TreeNode, contextual_error};
use crate::mount::{self, MountIdentity};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use std::ffi::{CStr, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const OPEN_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
#[cfg(target_os = "linux")]
const OPEN_PARENT_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
#[cfg(not(target_os = "linux"))]
const OPEN_PARENT_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

pub(super) struct FileSystem;

pub(super) struct Directory {
    entries: Dir,
    path: PathBuf,
    mount: MountIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryIdentity {
    file_type: FileType,
    device: u64,
    inode: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

struct Inspection {
    identity: EntryIdentity,
    mount: Option<MountIdentity>,
}

impl TreeAccess for FileSystem {
    type Directory = Directory;

    fn open_root(&self, path: &Path) -> io::Result<Root<Self::Directory>> {
        let lookup = root_lookup(path)?;
        let parent_mount = containing_parent_mount(&lookup)?;
        let inspection = inspect_at(rustix::fs::CWD, &lookup, path)?;
        if crosses_mount(&inspection, parent_mount.as_ref()) {
            return unopened_root(path, inspection, parent_mount);
        }
        if inspection.identity.file_type != FileType::Directory {
            return unopened_root(path, inspection, parent_mount);
        }
        let fd = open_verified_directory(rustix::fs::CWD, &lookup, path, inspection.identity)?;
        let parent_mount = opened_parent_mount(&fd, path)?;
        Ok(Root {
            node: directory_node(fd, path.to_path_buf())?,
            parent_mount,
        })
    }

    fn next_child(
        &self,
        directory: &mut Self::Directory,
    ) -> io::Result<Option<TreeNode<Self::Directory>>> {
        loop {
            let Some(entry) = directory.entries.next() else {
                return Ok(None);
            };
            let entry = entry.map_err(|error| {
                contextual_error("read directory", &directory.path, io::Error::from(error))
            })?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            let name = entry.file_name().to_owned();
            return child_node(directory, &name).map(Some);
        }
    }
}

fn child_node(directory: &Directory, name: &CStr) -> io::Result<TreeNode<Directory>> {
    let path = directory.path.join(OsStr::from_bytes(name.to_bytes()));
    let parent = directory_fd(directory)?;
    let inspection = inspect_at(parent, name, &path)?;
    let mount = inspection
        .mount
        .clone()
        .unwrap_or_else(|| directory.mount.clone());
    if mount != directory.mount {
        return Ok(TreeNode {
            path,
            mount,
            directory: None,
        });
    }
    if inspection.identity.file_type == FileType::Directory {
        let fd = open_verified_directory(parent, name, &path, inspection.identity)?;
        return directory_node(fd, path);
    }
    Ok(TreeNode {
        path,
        mount,
        directory: None,
    })
}

fn unopened_root(
    path: &Path,
    inspection: Inspection,
    parent_mount: Option<MountIdentity>,
) -> io::Result<Root<Directory>> {
    let mount = inspection
        .mount
        .or_else(|| parent_mount.clone())
        .ok_or_else(|| mount::unsupported(path))?;
    Ok(Root {
        node: TreeNode {
            path: path.to_path_buf(),
            mount,
            directory: None,
        },
        parent_mount,
    })
}

fn root_lookup(path: &Path) -> io::Result<PathBuf> {
    if path == Path::new("/") {
        return Ok(path.to_path_buf());
    }
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
    match (parent, path.file_name()) {
        (Some(parent), Some(name)) => Ok(parent.join(name)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tree mutation root has no final entry: {}", path.display()),
        )),
    }
}

fn containing_parent_mount(path: &Path) -> io::Result<Option<MountIdentity>> {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(mount::containing_mount)
        .transpose()
}

fn crosses_mount(inspection: &Inspection, parent: Option<&MountIdentity>) -> bool {
    inspection
        .mount
        .as_ref()
        .zip(parent)
        .is_some_and(|(entry, parent)| entry != parent)
}

fn directory_node(fd: OwnedFd, path: PathBuf) -> io::Result<TreeNode<Directory>> {
    let mount = mount::identity_for_fd(&fd, &path)?;
    let entries = Dir::new(fd)
        .map_err(|error| contextual_error("read directory", &path, io::Error::from(error)))?;
    Ok(TreeNode {
        path: path.clone(),
        mount: mount.clone(),
        directory: Some(Directory {
            entries,
            path,
            mount,
        }),
    })
}

fn opened_parent_mount(fd: &OwnedFd, path: &Path) -> io::Result<Option<MountIdentity>> {
    let Some(parent_path) = path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(None);
    };
    let parent = rustix::fs::openat(fd, c"..", OPEN_PARENT_FLAGS, Mode::empty())
        .map_err(|error| contextual_error("open parent", parent_path, io::Error::from(error)))?;
    mount::identity_for_fd(parent, parent_path).map(Some)
}

#[cfg(target_os = "linux")]
fn inspect_at<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
) -> io::Result<Inspection> {
    use rustix::fs::{StatxFlags, statx};

    let flags = AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT;
    let requested = StatxFlags::BASIC_STATS | StatxFlags::MNT_ID;
    let stat = statx(parent, name, flags, requested)
        .map_err(|error| mount::linux_statx_error(path, error))?;
    Ok(Inspection {
        identity: linux_identity(&stat, path)?,
        mount: Some(mount::linux_mount(path, stat.stx_mask, stat.stx_mnt_id)?),
    })
}

#[cfg(not(target_os = "linux"))]
fn inspect_at<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
) -> io::Result<Inspection> {
    rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|stat| Inspection {
            identity: EntryIdentity::from(&stat),
            mount: None,
        })
        .map_err(|error| contextual_error("inspect", path, io::Error::from(error)))
}

fn open_verified_directory<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
    expected: EntryIdentity,
) -> io::Result<OwnedFd> {
    let fd = rustix::fs::openat(parent, name, OPEN_DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| contextual_error("open directory", path, error.into()))?;
    let opened = rustix::fs::fstat(&fd).map_err(|error| {
        contextual_error("inspect opened directory", path, io::Error::from(error))
    })?;
    require_identity(path, expected, EntryIdentity::from(&opened))?;
    Ok(fd)
}

fn require_identity(path: &Path, expected: EntryIdentity, actual: EntryIdentity) -> io::Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("entry identity changed while validating {}", path.display()),
        ))
    }
}

fn directory_fd(directory: &Directory) -> io::Result<rustix::fd::BorrowedFd<'_>> {
    directory.entries.fd().map_err(|error| {
        contextual_error("access directory", &directory.path, io::Error::from(error))
    })
}

#[cfg(target_os = "linux")]
fn linux_identity(stat: &rustix::fs::Statx, path: &Path) -> io::Result<EntryIdentity> {
    use rustix::fs::StatxFlags;

    let present = StatxFlags::from_bits_retain(stat.stx_mask);
    let required = StatxFlags::TYPE | StatxFlags::INO | StatxFlags::CTIME;
    if !present.contains(required) {
        return Err(mount::unsupported(path));
    }
    Ok(EntryIdentity {
        file_type: FileType::from_raw_mode(stat.stx_mode as _),
        device: ((stat.stx_dev_major as u64) << 32) | stat.stx_dev_minor as u64,
        inode: stat.stx_ino,
        ctime_seconds: stat.stx_ctime.tv_sec,
        ctime_nanoseconds: stat.stx_ctime.tv_nsec.into(),
    })
}

impl From<&Stat> for EntryIdentity {
    fn from(stat: &Stat) -> Self {
        Self {
            file_type: FileType::from_raw_mode(stat.st_mode),
            device: ((rustix::fs::major(stat.st_dev) as u64) << 32)
                | rustix::fs::minor(stat.st_dev) as u64,
            inode: stat.st_ino as _,
            ctime_seconds: stat.st_ctime as _,
            ctime_nanoseconds: stat.st_ctime_nsec as _,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_symlink_replacement_after_directory_inspection() {
        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        let original = temp.path().join("original");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&victim).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let parent = rustix::fs::openat(
            rustix::fs::CWD,
            temp.path(),
            OPEN_DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .unwrap();
        let identity = inspect_at(&parent, c"victim", &victim).unwrap().identity;
        std::fs::rename(&victim, &original).unwrap();
        std::os::unix::fs::symlink(&outside, &victim).unwrap();

        let error = open_verified_directory(&parent, c"victim", &victim, identity).unwrap_err();

        assert!(error.to_string().contains("failed to open directory"));
    }
}
