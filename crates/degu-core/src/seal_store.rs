//! Secure, exact-file storage for the seal transaction WAL.
//!
//! This foundation deliberately has no lifecycle integration. It owns one fixed
//! WAL entry in one private directory and returns a lease whose descriptor is the
//! descriptor used for replay, repair, and subsequent append.
//!
//! The authority boundary excludes malicious same-EUID and root processes: they
//! can already enter 0700/0600 state and modify it. Descriptor-relative ancestor
//! validation plus fail-closed ACL absence prevents a foreign UID from gaining
//! namespace authority and detaching the durable WAL.

use crate::local_backend::{
    CertifiedLocalBackend, HeldLocalBackendEvidence, certify_held_fd, certify_held_fd_backend,
    require_held_fd_acl_absent,
};
use crate::seal_wal::{ExclusiveFileLock, RecoveryLockError, RecoverySession};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The only entry managed by [`SealWalStore`].
pub const WAL_FILE_NAME: &str = "seal.wal";

const DIRECTORY_MODE: Mode = Mode::RWXU;
const WAL_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_WAL: OFlags = OFlags::RDWR.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("seal WAL store path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("failed to access seal WAL store at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe seal WAL store directory at {path}: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
    #[error("unsafe seal WAL entry at {path}: {reason}")]
    UnsafeWal { path: PathBuf, reason: &'static str },
    #[error(transparent)]
    Lease(#[from] RecoveryLockError),
}

/// An EUID-owned, exact-mode directory containing exactly addressed WAL state.
///
/// Opening the store never relaxes an existing directory's permissions. Creation
/// is limited to the final component beneath an already-open parent directory.
pub struct SealWalStore {
    parent: OwnedFd,
    name: OsString,
    directory: OwnedFd,
    backend: CertifiedLocalBackend,
    device: u64,
    path: PathBuf,
}

impl SealWalStore {
    /// Opens `path`, creating only its final directory component when absent.
    pub fn open_or_create(path: &Path) -> Result<Self, StoreError> {
        Self::open_or_create_with_sync(path, |fd| rustix::fs::fsync(fd).map_err(io::Error::from))
    }

    fn open_or_create_with_sync<F>(path: &Path, mut sync: F) -> Result<Self, StoreError>
    where
        F: FnMut(&OwnedFd) -> io::Result<()>,
    {
        let (parent, name, parent_path) = open_authenticated_parent(path)?;
        validate_parent_for_creation(&parent, &parent_path)?;

        let created = match rustix::fs::mkdirat(&parent, &name, DIRECTORY_MODE) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(io_error(path, error.into())),
        };
        let directory = rustix::fs::openat(&parent, &name, OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(path, error.into()))?;
        if created {
            // mkdir(2)'s mode is filtered by umask. Tighten to the exact invariant
            // before the directory is accepted or any WAL entry is created.
            rustix::fs::fchmod(&directory, DIRECTORY_MODE)
                .map_err(|error| io_error(path, error.into()))?;
        }
        validate_directory(&directory, path)?;
        let certified = certify_directory(&directory, path)?;
        let backend = certified.backend();
        let device = certified.device();
        validate_store_binding(
            &parent,
            &name,
            &directory,
            backend,
            device,
            path,
            &parent_path,
        )?;
        // Always repeat both syncs, including when mkdir reported EEXIST. This
        // completes a prior attempt whose directory fsync succeeded but parent
        // fsync failed, leaving creation durability uncertain. No WAL lease can
        // be issued until a retry observes both syncs succeeding.
        sync(&directory).map_err(|error| io_error(path, error))?;
        sync(&parent).map_err(|error| io_error(&parent_path, error))?;
        Ok(Self {
            parent,
            name,
            directory,
            backend,
            device,
            path: path.to_path_buf(),
        })
    }

    /// Opens or creates the exact WAL entry and acquires a nonblocking exclusive
    /// lock on that same descriptor.
    pub(crate) fn try_lease(&self) -> Result<RecoverySession, StoreError> {
        let wal_path = self.path.join(WAL_FILE_NAME);
        let parent_path = self.path.parent().unwrap_or_else(|| Path::new("/"));
        validate_store_binding(
            &self.parent,
            &self.name,
            &self.directory,
            self.backend,
            self.device,
            &self.path,
            parent_path,
        )?;
        // Serialize protocol participants across the create/publish durability
        // window. A fresh open file description is required: locking the store's
        // shared directory descriptor would not exclude another call in-process.
        let creation_fd = rustix::fs::openat(&self.directory, ".", OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(&self.path, error.into()))?;
        let creation_lock = ExclusiveFileLock::try_acquire(File::from(creation_fd))?;
        // Recheck after serialization so a replacement that raced the first
        // observation cannot redirect WAL replay or append into a detached store.
        validate_store_binding(
            &self.parent,
            &self.name,
            &self.directory,
            self.backend,
            self.device,
            &self.path,
            parent_path,
        )?;

        let (fd, created) =
            match rustix::fs::openat(&self.directory, WAL_FILE_NAME, OPEN_WAL, Mode::empty()) {
                Ok(fd) => (fd, false),
                Err(rustix::io::Errno::NOENT) => match rustix::fs::openat(
                    &self.directory,
                    WAL_FILE_NAME,
                    OPEN_WAL | OFlags::CREATE | OFlags::EXCL,
                    WAL_MODE,
                ) {
                    Ok(fd) => (fd, true),
                    // Another same-EUID creator may have won. Re-open without CREATE
                    // and validate the descriptor instead of trusting its pathname.
                    Err(rustix::io::Errno::EXIST) => (
                        rustix::fs::openat(&self.directory, WAL_FILE_NAME, OPEN_WAL, Mode::empty())
                            .map_err(|error| io_error(&wal_path, error.into()))?,
                        false,
                    ),
                    Err(error) => return Err(io_error(&wal_path, error.into())),
                },
                Err(error) => return Err(io_error(&wal_path, error.into())),
            };

        if created {
            // openat's requested mode is umask-filtered and can never be broader
            // than 0600. Establish the exact invariant while creation remains
            // serialized, but do not publish durability before locking the WAL.
            rustix::fs::fchmod(&fd, WAL_MODE).map_err(|error| io_error(&wal_path, error.into()))?;
        }
        validate_wal(&fd, self.backend, self.device, &wal_path)?;
        let file = File::from(fd);
        let lease = RecoverySession::try_acquire(file)?;
        // Bind the locked descriptor back to the exact directory entry. A
        // malicious same-EUID or root process is the explicit trust boundary;
        // foreign UIDs have no mode or ACL namespace authority.
        validate_wal(lease.as_file(), self.backend, self.device, &wal_path)?;
        validate_entry_binding(&self.directory, lease.as_file(), &wal_path)?;
        // The exact WAL lease is already held. A second protocol participant
        // cannot append before both the inode and its directory entry are
        // durable. Sync existing entries too: this safely completes a previous
        // creator whose file or directory fsync returned an error. Any failure
        // drops the lease on return.
        lease
            .as_file()
            .sync_all()
            .map_err(|error| io_error(&wal_path, error))?;
        rustix::fs::fsync(&self.directory).map_err(|error| io_error(&self.path, error.into()))?;
        // Final delivery check: exact store mode/owner/backend/ACL and the locked
        // WAL mode/owner/device/ACL/binding must still hold after durability.
        validate_store_binding(
            &self.parent,
            &self.name,
            &self.directory,
            self.backend,
            self.device,
            &self.path,
            parent_path,
        )?;
        validate_wal(lease.as_file(), self.backend, self.device, &wal_path)?;
        validate_entry_binding(&self.directory, lease.as_file(), &wal_path)?;
        drop(creation_lock);
        Ok(lease)
    }
}

fn open_authenticated_parent(path: &Path) -> Result<(OwnedFd, OsString, PathBuf), StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::InvalidPath(
            "an absolute dedicated store path is required",
        ));
    }
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::ParentDir => {
                return Err(StoreError::InvalidPath("parent traversal is not allowed"));
            }
            Component::CurDir | Component::Prefix(_) => {
                return Err(StoreError::InvalidPath(
                    "only absolute normal path components are allowed",
                ));
            }
        }
    }
    let name = names.pop().ok_or(StoreError::InvalidPath(
        "a dedicated directory with a final component is required",
    ))?;
    let mut current_path = PathBuf::from("/");
    let mut current = rustix::fs::open("/", OPEN_DIRECTORY, Mode::empty())
        .map_err(|error| io_error(Path::new("/"), error.into()))?;
    validate_directory_controller(&current, &current_path)?;

    for component in names {
        let child_path = current_path.join(&component);
        let entry = rustix::fs::statat(&current, &component, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error(&child_path, error.into()))?;
        let parent_stat =
            rustix::fs::fstat(&current).map_err(|error| io_error(&current_path, error.into()))?;
        validate_binding_policy(&parent_stat, entry.st_uid, &current_path)?;
        if FileType::from_raw_mode(entry.st_mode) != FileType::Directory {
            return Err(StoreError::UnsafeDirectory {
                path: child_path,
                reason: "ancestor is not a no-follow directory",
            });
        }
        let opened = rustix::fs::openat(&current, &component, OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(&child_path, error.into()))?;
        let opened_stat =
            rustix::fs::fstat(&opened).map_err(|error| io_error(&child_path, error.into()))?;
        require_same_entry(
            &entry,
            &opened_stat,
            &child_path,
            "ancestor binding changed",
        )?;
        validate_directory_controller(&opened, &child_path)?;
        current = opened;
        current_path = child_path;
    }
    Ok((current, name, current_path))
}

fn validate_parent_for_creation(fd: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    validate_directory_controller(fd, path)?;
    if nonowner_write_and_search(raw_mode_u32(stat.st_mode))
        && raw_mode_u32(stat.st_mode) & 0o1000 == 0
    {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "non-sticky parent grants non-owner write and search",
        });
    }
    Ok(())
}

fn validate_directory_controller(fd: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    certify_directory(fd, path)?;
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid && stat.st_uid != 0 {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "ancestor has a foreign non-root owner",
        });
    }
    Ok(())
}

fn validate_binding_policy(
    parent: &rustix::fs::Stat,
    child_uid: u32,
    path: &Path,
) -> Result<(), StoreError> {
    let euid = rustix::process::geteuid().as_raw();
    if parent.st_uid != euid && parent.st_uid != 0 {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "parent has a foreign non-root owner",
        });
    }
    if nonowner_write_and_search(raw_mode_u32(parent.st_mode)) {
        if raw_mode_u32(parent.st_mode) & 0o1000 == 0 {
            return Err(StoreError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: "non-sticky parent grants non-owner write and search",
            });
        }
        if child_uid != euid {
            return Err(StoreError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: "sticky shared parent does not bind an EUID-owned child",
            });
        }
    }
    Ok(())
}

fn nonowner_write_and_search(mode: u32) -> bool {
    mode & 0o030 == 0o030 || mode & 0o003 == 0o003
}

fn validate_store_binding(
    parent: &OwnedFd,
    name: &OsString,
    directory: &OwnedFd,
    expected_backend: CertifiedLocalBackend,
    expected_device: u64,
    path: &Path,
    parent_path: &Path,
) -> Result<(), StoreError> {
    validate_directory_controller(parent, parent_path)?;
    validate_directory(directory, path)?;
    let certified = certify_directory(directory, path)?;
    if certified.backend() != expected_backend || certified.device() != expected_device {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "store backend or device changed",
        });
    }
    let parent_stat =
        rustix::fs::fstat(parent).map_err(|error| io_error(parent_path, error.into()))?;
    let entry = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(path, error.into()))?;
    validate_binding_policy(&parent_stat, entry.st_uid, parent_path)?;
    let opened = rustix::fs::fstat(directory).map_err(|error| io_error(path, error.into()))?;
    require_same_entry(
        &entry,
        &opened,
        path,
        "opened directory is not the exact store entry",
    )?;
    if FileType::from_raw_mode(entry.st_mode) != FileType::Directory {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "store entry is not a directory",
        });
    }
    Ok(())
}

fn require_same_entry(
    expected: &rustix::fs::Stat,
    actual: &rustix::fs::Stat,
    path: &Path,
    reason: &'static str,
) -> Result<(), StoreError> {
    if expected.st_dev != actual.st_dev
        || expected.st_ino != actual.st_ino
        || FileType::from_raw_mode(expected.st_mode) != FileType::from_raw_mode(actual.st_mode)
    {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason,
        });
    }
    Ok(())
}

fn require_directory_acl_absent(fd: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    require_held_fd_acl_absent(fd).map_err(|_| StoreError::UnsafeDirectory {
        path: path.to_path_buf(),
        reason: "directory ACL is present or could not be verified absent",
    })
}

fn certify_directory(fd: &OwnedFd, path: &Path) -> Result<HeldLocalBackendEvidence, StoreError> {
    require_directory_acl_absent(fd, path)?;
    let duplicate =
        rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(|error| io_error(path, error.into()))?;
    certify_held_fd(duplicate).map_err(|_| StoreError::UnsafeDirectory {
        path: path.to_path_buf(),
        reason: "directory is not on a certified ACL-free local backend",
    })
}

fn validate_directory(fd: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    require_directory_acl_absent(fd, path)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "entry is not a directory",
        });
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "directory is not owned by the effective user",
        });
    }
    if raw_mode_u32(stat.st_mode) & 0o7777 != raw_mode_u32(DIRECTORY_MODE.bits()) {
        return Err(StoreError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "directory mode is not exactly 0700",
        });
    }
    Ok(())
}

fn validate_entry_binding<Fd: AsFd>(
    directory: &OwnedFd,
    fd: Fd,
    path: &Path,
) -> Result<(), StoreError> {
    let opened = rustix::fs::fstat(fd).map_err(|error| io_error(path, error.into()))?;
    let entry = rustix::fs::statat(
        directory,
        WAL_FILE_NAME,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| io_error(path, error.into()))?;
    if opened.st_dev != entry.st_dev
        || opened.st_ino != entry.st_ino
        || FileType::from_raw_mode(entry.st_mode) != FileType::RegularFile
    {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "locked descriptor is not the exact WAL directory entry",
        });
    }
    Ok(())
}

fn validate_wal<Fd: AsFd>(
    fd: Fd,
    expected_backend: CertifiedLocalBackend,
    expected_device: u64,
    path: &Path,
) -> Result<(), StoreError> {
    let stat = rustix::fs::fstat(&fd).map_err(|error| io_error(path, error.into()))?;
    require_held_fd_acl_absent(&fd).map_err(|_| StoreError::UnsafeWal {
        path: path.to_path_buf(),
        reason: "WAL ACL is present or could not be verified absent",
    })?;
    let backend = certify_held_fd_backend(&fd).map_err(|_| StoreError::UnsafeWal {
        path: path.to_path_buf(),
        reason: "WAL backend could not be certified",
    })?;
    if backend != expected_backend {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "WAL backend does not match the certified store backend",
        });
    }
    #[cfg(target_vendor = "apple")]
    let device = u64::try_from(stat.st_dev).map_err(|_| StoreError::UnsafeWal {
        path: path.to_path_buf(),
        reason: "WAL device identity is invalid",
    })?;
    #[cfg(not(target_vendor = "apple"))]
    let device = stat.st_dev;
    if device != expected_device {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "WAL device does not match the certified store backend",
        });
    }
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "entry is not a regular file",
        });
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "WAL is not owned by the effective user",
        });
    }
    if raw_mode_u32(stat.st_mode) & 0o7777 != raw_mode_u32(WAL_MODE.bits()) {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "WAL mode is not exactly 0600",
        });
    }
    if stat.st_nlink != 1 {
        return Err(StoreError::UnsafeWal {
            path: path.to_path_buf(),
            reason: "WAL link count is not exactly one",
        });
    }
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
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
mod tests;
