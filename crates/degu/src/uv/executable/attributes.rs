use super::error::{UvExecutableProbeError, unsafe_path};
use rustix::fd::{AsFd, AsRawFd};
use std::io;
use std::path::Path;

const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
/// Extended attributes whose absence from a private snapshot cannot change what it
/// executes, so snapshotting may drop them.
///
/// macOS attaches `com.apple.provenance` to what it downloaded or extracted, and the
/// official uv release carries it. It records where bytes came from and restricts
/// nothing, so a snapshot without it runs under exactly the restrictions the selected
/// object ran under. `com.apple.quarantine` is the opposite and stays refused with
/// every other name: dropping it would execute bytes the selected path could not.
///
/// This is deliberately not the staging admission allowlist, which admits quarantine.
/// Moving a quarantined file to the trash carries the attribute along, and running a
/// copy that lost it does not, so one list cannot answer both questions.
#[cfg(target_os = "macos")]
const DROPPABLE_XATTRS: [&[u8]; 1] = [b"com.apple.provenance"];
#[cfg(not(target_os = "macos"))]
const DROPPABLE_XATTRS: [&[u8]; 0] = [];

#[cfg(target_os = "linux")]
pub(super) fn reject_extended_acl(
    fd: &impl AsFd,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    let names = list_xattrs(fd).map_err(|source| UvExecutableProbeError::AclInspection {
        path: path.to_path_buf(),
        source,
    })?;
    if names
        .split(|byte| *byte == 0)
        .any(|name| name == b"system.posix_acl_access")
    {
        return Err(unsafe_path(path, "extended ACL is present"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn reject_extended_acl(
    fd: &impl AsFd,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    match crate::uv::grants_mutation(fd) {
        Ok(false) => Ok(()),
        Ok(true) => Err(unsafe_path(
            path,
            "extended ACL grants mutation authority or has an unknown tag",
        )),
        Err(source) => Err(UvExecutableProbeError::AclInspection {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(super) fn reject_unpreserved_xattrs(
    fd: &impl AsFd,
    path: &Path,
) -> Result<(), UvExecutableProbeError> {
    let names = list_xattrs(fd).map_err(|source| UvExecutableProbeError::XattrInspection {
        path: path.to_path_buf(),
        source,
    })?;
    match first_undroppable_xattr(&names) {
        None => Ok(()),
        Some(name) => Err(UvExecutableProbeError::UnpreservedXattr {
            path: path.to_path_buf(),
            name,
        }),
    }
}

/// The first attribute in a `flistxattr` name list that snapshotting may not drop.
///
/// The list is NUL-separated and NUL-terminated, so its last split is empty. A real
/// name never is, and counting the terminator as one would refuse every file for an
/// attribute that does not exist.
pub(super) fn first_undroppable_xattr(names: &[u8]) -> Option<String> {
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .find(|name| !DROPPABLE_XATTRS.contains(name))
        .map(|name| String::from_utf8_lossy(name).into_owned())
}

fn list_xattrs(fd: &impl AsFd) -> io::Result<Vec<u8>> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let size = flistxattr(raw_fd, std::ptr::null_mut(), 0)?;
    if size > MAX_XATTR_LIST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list exceeds the safety bound",
        ));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; size];
    let read = flistxattr(raw_fd, names.as_mut_ptr().cast(), names.len())?;
    if read > names.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list grew beyond the allocated bound",
        ));
    }
    names.truncate(read);
    Ok(names)
}

fn flistxattr(fd: libc::c_int, buffer: *mut libc::c_char, size: usize) -> io::Result<usize> {
    loop {
        #[cfg(target_os = "linux")]
        // SAFETY: buffer is null with size zero or names a writable allocation
        // of exactly `size` bytes; the descriptor remains borrowed and live.
        let result = unsafe { libc::flistxattr(fd, buffer, size) };
        #[cfg(target_os = "macos")]
        // SAFETY: same contract as Linux; options zero requests ordinary names.
        let result = unsafe { libc::flistxattr(fd, buffer, size, 0) };
        if result >= 0 {
            return usize::try_from(result)
                .map_err(|_| io::Error::other("extended attribute list size overflow"));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}
