use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags, Stat};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::time::SystemTime;

const ALLOCATED_BLOCK_BYTES: u64 = 512;
#[cfg(target_os = "linux")]
const NANOS_PER_SECOND: u32 = 1_000_000_000;

// No-follow directory open: a symlink swapped in after inspection is refused.
const OPEN_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileMeta {
    pub(super) is_dir: bool,
    pub(super) len: u64,
    pub(super) bytes_allocated: u64,
    pub(super) nlink: u64,
    pub(super) mtime: Option<SystemTime>,
    pub(super) dev: u64,
    pub(super) uid: u32,
    pub(super) mode: u32,
}

/// Re-checked after opening a directory to reject a rename-then-symlink swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EntryIdentity {
    file_type: FileType,
    device: u64,
    inode: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

/// Accounting metadata and the open-guard identity from one no-follow stat.
pub(super) struct Inspection {
    pub(super) meta: FileMeta,
    pub(super) identity: EntryIdentity,
}

pub(super) type RootDevice = Option<u64>;

pub(super) fn root_device(meta: &FileMeta, one_filesystem: bool) -> RootDevice {
    one_filesystem.then_some(meta.dev)
}

pub(super) fn crosses_filesystem_boundary(meta: &FileMeta, root_device: RootDevice) -> bool {
    root_device.is_some_and(|root_device| meta.dev != root_device)
}

/// No-follow stat yielding accounting metadata and the open-guard identity.
#[cfg(target_os = "linux")]
pub(super) fn inspect_at<Fd: AsFd, P: rustix::path::Arg + Copy>(
    parent: Fd,
    name: P,
) -> io::Result<Inspection> {
    if !STATX_BROKEN.load(Ordering::Relaxed)
        && let Some(inspection) = inspect_at_statx(parent.as_fd(), name)?
    {
        return Ok(inspection);
    }
    inspect_at_fstatat(parent, name)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn inspect_at<Fd: AsFd, P: rustix::path::Arg + Copy>(
    parent: Fd,
    name: P,
) -> io::Result<Inspection> {
    inspect_at_fstatat(parent, name)
}

#[cfg(target_os = "linux")]
fn inspect_at_statx<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
) -> io::Result<Option<Inspection>> {
    use rustix::fs::{AtFlags, StatxFlags};

    let requested = StatxFlags::TYPE
        | StatxFlags::MODE
        | StatxFlags::SIZE
        | StatxFlags::BLOCKS
        | StatxFlags::NLINK
        | StatxFlags::MTIME
        | StatxFlags::CTIME
        | StatxFlags::INO
        | StatxFlags::UID;
    let statx = match rustix::fs::statx(
        parent,
        name,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        requested,
    ) {
        Ok(statx) => statx,
        Err(error) if statx_fallback_error(error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    let present = StatxFlags::from_bits_retain(statx.stx_mask);
    if !present.contains(requested) {
        return Ok(None);
    }

    Ok(Some(Inspection {
        meta: file_meta_from_statx(&statx),
        identity: identity_from_statx(&statx),
    }))
}

fn inspect_at_fstatat<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
) -> io::Result<Inspection> {
    use rustix::fs::AtFlags;

    let stat = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(Inspection {
        meta: file_meta_from_stat(&stat),
        identity: EntryIdentity::from(&stat),
    })
}

/// No-follow open plus an identity re-check: refuses any post-inspection swap.
pub(super) fn open_verified_directory<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    expected: EntryIdentity,
) -> io::Result<OwnedFd> {
    let fd = rustix::fs::openat(parent, name, OPEN_DIRECTORY_FLAGS, Mode::empty())?;
    verify_opened(fd, expected)
}

/// Verified open of `root`; a symlinked root is caught earlier by the caller's `lstat`.
pub(super) fn open_root(root: &Path, expected: EntryIdentity) -> io::Result<OwnedFd> {
    open_verified_directory(rustix::fs::CWD, root, expected)
}

fn verify_opened(fd: OwnedFd, expected: EntryIdentity) -> io::Result<OwnedFd> {
    let opened = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    let actual = EntryIdentity::from(&opened);
    if actual == expected {
        Ok(fd)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory identity changed between inspection and open",
        ))
    }
}

#[cfg(target_os = "linux")]
static STATX_BROKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Root's classifying no-follow stat; its identity guards the later `open_root`.
pub(super) fn lstat(path: &Path) -> io::Result<Inspection> {
    inspect_at(rustix::fs::CWD, path)
}

/// Strip trailing `/` and `.` (keeping a symlinked final no-follow-refused) while preserving relative roots.
pub(super) fn normalize_root(root: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in root.components() {
        if component != Component::CurDir {
            normalized.push(component);
        }
    }
    if normalized.as_os_str().is_empty() {
        return root.to_path_buf();
    }
    normalized
}

#[cfg(target_os = "linux")]
fn statx_fallback_error(error: rustix::io::Errno) -> bool {
    use rustix::io::Errno;

    if !matches!(error, Errno::NOSYS | Errno::PERM | Errno::INVAL) {
        return false;
    }
    if STATX_BROKEN
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        tracing::warn!(err = %error, "statx unavailable; using lstat for the rest of this process");
    }
    true
}

#[cfg(target_os = "linux")]
fn file_meta_from_statx(statx: &rustix::fs::Statx) -> FileMeta {
    FileMeta {
        is_dir: statx.stx_mode & libc_mode::S_IFMT == libc_mode::S_IFDIR,
        len: statx.stx_size,
        bytes_allocated: statx.stx_blocks.saturating_mul(ALLOCATED_BLOCK_BYTES),
        nlink: u64::from(statx.stx_nlink),
        mtime: statx_timestamp_to_system_time(statx.stx_mtime.tv_sec, statx.stx_mtime.tv_nsec),
        dev: rustix::fs::makedev(statx.stx_dev_major, statx.stx_dev_minor),
        uid: statx.stx_uid,
        mode: u32::from(statx.stx_mode),
    }
}

// Std reference the tests cross-check the statx accounting path against.
#[cfg(all(target_os = "linux", test))]
fn lstat_std(path: &Path) -> io::Result<FileMeta> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path)?;
    Ok(FileMeta {
        is_dir: meta.file_type().is_dir(),
        len: meta.len(),
        bytes_allocated: meta.blocks().saturating_mul(ALLOCATED_BLOCK_BYTES),
        nlink: meta.nlink(),
        mtime: meta.modified().ok(),
        dev: meta.dev(),
        uid: meta.uid(),
        mode: meta.mode(),
    })
}

fn file_meta_from_stat(stat: &Stat) -> FileMeta {
    FileMeta {
        is_dir: FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
        len: stat.st_size as _,
        bytes_allocated: (stat.st_blocks as u64).saturating_mul(ALLOCATED_BLOCK_BYTES),
        nlink: stat.st_nlink as _,
        mtime: stat_timestamp_to_system_time(stat.st_mtime as _, stat.st_mtime_nsec as _),
        dev: stat.st_dev as _,
        uid: stat.st_uid,
        mode: stat.st_mode as _,
    }
}

fn stat_timestamp_to_system_time(sec: i64, nsec: i64) -> Option<SystemTime> {
    use std::time::{Duration, UNIX_EPOCH};

    let nsec = u32::try_from(nsec).ok()?;
    if sec >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(sec as u64, nsec))
    } else if nsec == 0 {
        UNIX_EPOCH.checked_sub(Duration::new(sec.unsigned_abs(), 0))
    } else {
        UNIX_EPOCH.checked_sub(Duration::new(sec.unsigned_abs() - 1, 1_000_000_000 - nsec))
    }
}

#[cfg(target_os = "linux")]
fn identity_from_statx(statx: &rustix::fs::Statx) -> EntryIdentity {
    EntryIdentity {
        file_type: FileType::from_raw_mode(statx.stx_mode as _),
        device: ((statx.stx_dev_major as u64) << 32) | statx.stx_dev_minor as u64,
        inode: statx.stx_ino,
        ctime_seconds: statx.stx_ctime.tv_sec,
        ctime_nanoseconds: statx.stx_ctime.tv_nsec.into(),
    }
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

#[cfg(target_os = "linux")]
fn statx_timestamp_to_system_time(sec: i64, nsec: u32) -> Option<SystemTime> {
    use std::time::{Duration, UNIX_EPOCH};

    if nsec >= NANOS_PER_SECOND {
        return None;
    }
    if sec >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(sec as u64, nsec))
    } else if nsec == 0 {
        UNIX_EPOCH.checked_sub(Duration::new(sec.unsigned_abs(), 0))
    } else {
        UNIX_EPOCH.checked_sub(Duration::new(
            sec.unsigned_abs() - 1,
            NANOS_PER_SECOND - nsec,
        ))
    }
}

#[cfg(target_os = "linux")]
mod libc_mode {
    pub const S_IFMT: u16 = 0o170000;
    pub const S_IFDIR: u16 = 0o040000;
}

#[cfg(test)]
mod tests;
