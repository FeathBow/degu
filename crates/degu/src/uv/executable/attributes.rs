use super::error::{UvExecutableProbeError, unsafe_path};
use rustix::fd::AsFd;
use std::path::Path;

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
    let names =
        crate::uv::xattr::names(fd).map_err(|source| UvExecutableProbeError::AclInspection {
            path: path.to_path_buf(),
            source,
        })?;
    if crate::uv::xattr::names_a_posix_acl(&names) {
        return Err(unsafe_path(path, "extended or default ACL is present"));
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
    let names =
        crate::uv::xattr::names(fd).map_err(|source| UvExecutableProbeError::XattrInspection {
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
