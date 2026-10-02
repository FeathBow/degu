use super::attributes::{reject_extended_acl, reject_unpreserved_xattrs};
use super::error::{UvExecutableProbeError, inspect, unsafe_path};
use degu_adapters::native::NativeExecutableSelection;
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const SHARED_WRITE_MASK: u32 = 0o022;
const EXECUTE_MASK: u32 = 0o111;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutableIdentity {
    device: u64,
    inode: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
    pub(super) size: u64,
}

pub(super) struct OpenedExecutable {
    pub(super) canonical_path: PathBuf,
    pub(super) identity: ExecutableIdentity,
    pub(super) executable: OwnedFd,
}

pub(super) fn open_selected_executable(
    selection: &NativeExecutableSelection,
) -> Result<OpenedExecutable, UvExecutableProbeError> {
    let selected = selection.as_path();
    validate_namespace_chain(selected, false)?;
    let canonical_path =
        std::fs::canonicalize(selected).map_err(|source| inspect(selected, source))?;
    validate_namespace_chain(&canonical_path, true)?;

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let executable = rustix::fs::openat(rustix::fs::CWD, &canonical_path, flags, Mode::empty())
        .map_err(|source| inspect(&canonical_path, io::Error::from(source)))?;
    let stat = rustix::fs::fstat(&executable)
        .map_err(|source| inspect(&canonical_path, io::Error::from(source)))?;
    require_executable_permissions(&stat, &canonical_path)?;
    reject_extended_acl(&executable, &canonical_path)?;
    reject_unpreserved_xattrs(&executable, &canonical_path)?;
    require_native_binary(&executable, &canonical_path)?;

    let selected_metadata =
        std::fs::metadata(selected).map_err(|source| inspect(selected, source))?;
    let identity = executable_identity(&stat, &canonical_path)?;
    if selected_metadata.dev() != identity.device || selected_metadata.ino() != identity.inode {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(OpenedExecutable {
        canonical_path,
        identity,
        executable,
    })
}

pub(super) fn executable_identity(
    stat: &rustix::fs::Stat,
    path: &Path,
) -> Result<ExecutableIdentity, UvExecutableProbeError> {
    Ok(ExecutableIdentity {
        device: stat_device(stat.st_dev, path)?,
        inode: stat.st_ino,
        ctime_seconds: stat.st_ctime,
        ctime_nanoseconds: stat_ctime_nanoseconds(stat.st_ctime_nsec, path)?,
        size: u64::try_from(stat.st_size)
            .map_err(|_| unsafe_path(path, "executable size is negative"))?,
    })
}

/// Validate every lexical namespace used to resolve `path`. Calling this once
/// for the selected path and once for its canonical target covers both the
/// namespace containing each symlink and all directories reached by its target.
pub(super) fn validate_namespace_chain(
    path: &Path,
    canonical_final: bool,
) -> Result<(), UvExecutableProbeError> {
    let euid = rustix::process::geteuid().as_raw();
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path(path, "executable has no parent directory"))?;
    let mut prefix = PathBuf::from("/");
    validate_directory(&prefix, euid)?;
    for component in parent.components().skip(1) {
        let name = match component {
            std::path::Component::Normal(name) => name,
            _ => return Err(unsafe_path(path, "path is not lexically normalized")),
        };
        prefix.push(name);
        let link_metadata =
            std::fs::symlink_metadata(&prefix).map_err(|source| inspect(&prefix, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                &prefix,
                "ancestor symlink is owned by a foreign UID",
            ));
        }
        validate_directory(&prefix, euid)?;
    }
    if !canonical_final {
        let link_metadata =
            std::fs::symlink_metadata(path).map_err(|source| inspect(path, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                path,
                "executable symlink is owned by a foreign UID",
            ));
        }
    }
    Ok(())
}

fn validate_directory(path: &Path, euid: u32) -> Result<(), UvExecutableProbeError> {
    let metadata = std::fs::metadata(path).map_err(|source| inspect(path, source))?;
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "ancestor is not a directory"));
    }
    if degu_walk::directory_grants_foreign_mutation(metadata.uid(), metadata.mode(), euid) {
        return Err(unsafe_path(
            path,
            "ancestor namespace grants foreign mutation authority",
        ));
    }
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(path, io::Error::from(source)))?;
    let opened =
        rustix::fs::fstat(&directory).map_err(|source| inspect(path, io::Error::from(source)))?;
    let device = stat_device(opened.st_dev, path)?;
    let inode = opened.st_ino;
    if device != metadata.dev() || inode != metadata.ino() {
        return Err(UvExecutableProbeError::PathChanged);
    }
    reject_extended_acl(&directory, path)
}

fn require_native_binary(fd: &impl AsFd, path: &Path) -> Result<(), UvExecutableProbeError> {
    let mut magic = [0_u8; 4];
    let mut read = 0_usize;
    while read < magic.len() {
        // SAFETY: the live descriptor is borrowed and the remaining slice is a
        // valid writable allocation. pread does not alter its file offset.
        let result = unsafe {
            libc::pread(
                fd.as_fd().as_raw_fd(),
                magic[read..].as_mut_ptr().cast(),
                magic.len() - read,
                read as libc::off_t,
            )
        };
        if result > 0 {
            read += usize::try_from(result).expect("positive read count fits usize");
            continue;
        }
        if result == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(UvExecutableProbeError::Inspect {
            path: path.to_path_buf(),
            source: error,
        });
    }
    const MAGICS: [[u8; 4]; 9] = [
        *b"\x7fELF",
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
        [0xca, 0xfe, 0xba, 0xbf],
        [0xbf, 0xba, 0xfe, 0xca],
    ];
    if read != magic.len() || !MAGICS.contains(&magic) {
        return Err(UvExecutableProbeError::NotNativeBinary(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
fn stat_device(device: libc::dev_t, path: &Path) -> Result<u64, UvExecutableProbeError> {
    u64::try_from(device).map_err(|_| unsafe_path(path, "device ID is out of range"))
}

#[cfg(not(target_vendor = "apple"))]
fn stat_device(device: libc::dev_t, _path: &Path) -> Result<u64, UvExecutableProbeError> {
    Ok(device)
}

#[cfg(target_vendor = "apple")]
fn stat_ctime_nanoseconds(
    nanoseconds: libc::c_long,
    _path: &Path,
) -> Result<i64, UvExecutableProbeError> {
    Ok(nanoseconds)
}

#[cfg(not(target_vendor = "apple"))]
fn stat_ctime_nanoseconds(nanoseconds: u64, path: &Path) -> Result<i64, UvExecutableProbeError> {
    i64::try_from(nanoseconds).map_err(|_| unsafe_path(path, "ctime is out of range"))
}

#[cfg(target_vendor = "apple")]
pub(super) fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
pub(super) fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

fn require_executable_permissions(
    stat: &rustix::fs::Stat,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(unsafe_path(path, "executable is not a regular file"));
    }
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid && stat.st_uid != 0 {
        return Err(unsafe_path(path, "executable is owned by a foreign UID"));
    }
    let mode = raw_mode_u32(stat.st_mode);
    if mode & SHARED_WRITE_MASK != 0 {
        return Err(unsafe_path(path, "executable is group- or world-writable"));
    }
    if mode & EXECUTE_MASK == 0 {
        return Err(unsafe_path(path, "file has no executable mode bit"));
    }
    rustix::fs::accessat(
        rustix::fs::CWD,
        path,
        rustix::fs::Access::EXEC_OK,
        rustix::fs::AtFlags::EACCESS,
    )
    .map_err(|_| unsafe_path(path, "effective user cannot execute selected file"))?;
    Ok(())
}
