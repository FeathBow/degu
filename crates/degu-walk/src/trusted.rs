//! Trusted-ancestry path resolution on held descriptors.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

const STICKY_BIT: u32 = 0o1000;
const SYMLINK_BUDGET: u32 = 40;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Walk `path` from `/` one component at a time on held descriptors, requiring
/// every directory to be a trusted namespace and following a symlink only when
/// it is owned by the effective user or root. `label` names the subject (e.g.
/// "relocate target ancestor") in error messages. Returns the descriptor for the
/// fully validated directory. Every component must already exist.
pub fn resolve_trusted_directory(path: &Path, label: &str) -> io::Result<OwnedFd> {
    let euid = rustix::process::geteuid().as_raw();
    let root = Path::new("/");
    let mut current = open_directory_at(rustix::fs::CWD, "/", root, label)?;
    require_trusted_namespace(&stat_fd(&current, root, label)?, root, euid, label)?;
    let mut pending = lexical_components(path, label)?;
    let mut walked = PathBuf::from("/");
    let mut symlink_budget = SYMLINK_BUDGET;
    while let Some(component) = pending.pop_front() {
        if component == *OsStr::new(".") {
            continue;
        }
        if component == *OsStr::new("..") {
            let candidate = walked.parent().unwrap_or(root).to_path_buf();
            let next = open_directory_at(&current, "..", &candidate, label)?;
            require_trusted_namespace(
                &stat_fd(&next, &candidate, label)?,
                &candidate,
                euid,
                label,
            )?;
            require_stable_filesystem(&next, &candidate, label)?;
            current = next;
            walked = candidate;
            continue;
        }
        let candidate = walked.join(&component);
        let parent_sticky = is_sticky(&stat_fd(&current, &walked, label)?);
        let entry = stat_at(&current, component.as_os_str())
            .map_err(|error| io_error("inspect", &candidate, error, label))?;
        if FileType::from_raw_mode(entry.st_mode) == FileType::Symlink {
            require_owner_is_local(&entry, &candidate, euid, label)?;
            symlink_budget = symlink_budget.checked_sub(1).ok_or_else(|| {
                refuse(format!(
                    "too many symbolic links resolving {label} {}",
                    path.display()
                ))
            })?;
            let link = rustix::fs::readlinkat(&current, component.as_os_str(), Vec::new())
                .map_err(|error| io_error("read symlink", &candidate, error, label))?;
            let link = PathBuf::from(OsString::from_vec(link.into_bytes()));
            if link.is_absolute() {
                current = open_directory_at(rustix::fs::CWD, "/", root, label)?;
                require_trusted_namespace(&stat_fd(&current, root, label)?, root, euid, label)?;
                walked = PathBuf::from("/");
            }
            push_front_components(&mut pending, &link);
        } else if FileType::from_raw_mode(entry.st_mode) == FileType::Directory {
            if parent_sticky {
                require_owner_is_local(&entry, &candidate, euid, label)?;
            }
            let next = open_directory_at(&current, component.as_os_str(), &candidate, label)?;
            let opened = stat_fd(&next, &candidate, label)?;
            require_same_identity(&entry, &opened, &candidate, label)?;
            require_trusted_namespace(&opened, &candidate, euid, label)?;
            require_stable_filesystem(&next, &candidate, label)?;
            current = next;
            walked = candidate;
        } else {
            return Err(refuse(format!(
                "{label} {} is not a directory",
                candidate.display()
            )));
        }
    }
    Ok(current)
}

fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn io_error(action: &str, path: &Path, error: rustix::io::Errno, label: &str) -> io::Error {
    io::Error::new(
        io::Error::from(error).kind(),
        format!("{action} {label} {}: {error}", path.display()),
    )
}

fn lexical_components(path: &Path, label: &str) -> io::Result<VecDeque<OsString>> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refuse(format!(
            "{label} {} must be absolute",
            path.display()
        )));
    }
    let mut pending = VecDeque::new();
    for component in components {
        match component {
            Component::Normal(name) => pending.push_back(name.to_os_string()),
            Component::ParentDir => pending.push_back(OsString::from("..")),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(refuse(format!(
                    "{label} {} has an unexpected path component",
                    path.display()
                )));
            }
        }
    }
    Ok(pending)
}

fn push_front_components(pending: &mut VecDeque<OsString>, link: &Path) {
    for component in link.components().rev() {
        match component {
            Component::Normal(name) => pending.push_front(name.to_os_string()),
            Component::ParentDir => pending.push_front(OsString::from("..")),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
}

fn is_sticky(stat: &Stat) -> bool {
    raw_mode_u32(stat.st_mode) & STICKY_BIT != 0
}

fn require_owner_is_local(stat: &Stat, path: &Path, euid: u32, label: &str) -> io::Result<()> {
    if stat.st_uid != euid && stat.st_uid != 0 {
        return Err(refuse(format!(
            "{label} {} is owned by UID {}, which could rename or re-point it",
            path.display(),
            stat.st_uid
        )));
    }
    Ok(())
}

fn require_trusted_namespace(stat: &Stat, path: &Path, euid: u32, label: &str) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(refuse(format!(
            "{label} {} is not a directory",
            path.display()
        )));
    }
    if crate::directory_grants_foreign_mutation(stat.st_uid, raw_mode_u32(stat.st_mode), euid) {
        return Err(refuse(format!(
            "{label} {} is not a trusted namespace for effective UID {euid}",
            path.display()
        )));
    }
    Ok(())
}

fn require_same_identity(before: &Stat, after: &Stat, path: &Path, label: &str) -> io::Result<()> {
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || FileType::from_raw_mode(before.st_mode) != FileType::from_raw_mode(after.st_mode)
    {
        return Err(refuse(format!(
            "{label} {} changed identity while it was being verified",
            path.display()
        )));
    }
    Ok(())
}

/// Reject a directory on procfs: its magic links resolve per-process, so a path
/// that traverses procfs would not name a stable directory.
#[cfg(target_os = "linux")]
fn require_stable_filesystem(fd: &OwnedFd, path: &Path, label: &str) -> io::Result<()> {
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    let statfs = rustix::fs::fstatfs(fd)
        .map_err(|error| io_error("inspect filesystem of", path, error, label))?;
    if statfs.f_type as u64 == PROC_SUPER_MAGIC {
        return Err(refuse(format!(
            "{label} {} is on procfs, whose magic links resolve differently per process",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_stable_filesystem(_fd: &OwnedFd, _path: &Path, _label: &str) -> io::Result<()> {
    Ok(())
}

fn open_directory_at<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
    label: &str,
) -> io::Result<OwnedFd> {
    rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| io_error("open (no-follow)", path, error, label))
}

fn stat_at<Fd: AsFd, P: rustix::path::Arg>(parent: Fd, name: P) -> rustix::io::Result<Stat> {
    rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
}

fn stat_fd(fd: &OwnedFd, path: &Path, label: &str) -> io::Result<Stat> {
    rustix::fs::fstat(fd).map_err(|error| io_error("inspect", path, error, label))
}

#[cfg(target_vendor = "apple")]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A tempdir forced to 0700 so the resolver's trust check passes regardless
    /// of the ambient umask (tests run under both 022 and 002).
    fn owned_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    fn resolves_an_owned_absolute_directory() {
        let temp = owned_tempdir();
        let fd = resolve_trusted_directory(temp.path(), "test path").unwrap();
        let stat = rustix::fs::fstat(&fd).unwrap();
        let meta = std::fs::metadata(temp.path()).unwrap();
        assert_eq!(stat.st_ino, meta.ino());
    }

    #[test]
    fn rejects_a_relative_path() {
        let error = resolve_trusted_directory(Path::new("relative/dir"), "test path").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_a_non_directory_final_component() {
        let temp = owned_tempdir();
        let file = temp.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let error = resolve_trusted_directory(&file, "test path").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_a_group_writable_non_sticky_ancestor() {
        let temp = owned_tempdir();
        let child = temp.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, Permissions::from_mode(0o700)).unwrap();
        // Make the ancestor group-writable without the sticky bit: a co-tenant
        // could rename the child, so the resolver must refuse the whole path.
        std::fs::set_permissions(temp.path(), Permissions::from_mode(0o770)).unwrap();
        let error = resolve_trusted_directory(&child, "test path").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
