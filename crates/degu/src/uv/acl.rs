//! Minimal macOS ACL classification shared by native executable/root seals.
//!
//! The standard macOS home-directory ACL is deny-only (`everyone deny delete`)
//! and cannot grant an attacker mutation authority. Allow entries remain
//! fail-closed when they grant any permission that can modify an object or its
//! directory namespace.

use rustix::fd::{AsFd, AsRawFd};
use std::io;

const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;

const ACL_WRITE_DATA: u64 = 1 << 2;
const ACL_DELETE: u64 = 1 << 4;
const ACL_APPEND_DATA: u64 = 1 << 5;
const ACL_DELETE_CHILD: u64 = 1 << 6;
const ACL_WRITE_ATTRIBUTES: u64 = 1 << 8;
const ACL_WRITE_EXTATTRIBUTES: u64 = 1 << 10;
const ACL_WRITE_SECURITY: u64 = 1 << 12;
const ACL_CHANGE_OWNER: u64 = 1 << 13;
const MUTATION_PERMISSIONS: u64 = ACL_WRITE_DATA
    | ACL_DELETE
    | ACL_APPEND_DATA
    | ACL_DELETE_CHILD
    | ACL_WRITE_ATTRIBUTES
    | ACL_WRITE_EXTATTRIBUTES
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_permset_mask_np(entry: *mut libc::c_void, mask: *mut u64) -> libc::c_int;
    fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
}

struct OwnedAcl(*mut libc::c_void);

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        // SAFETY: this pointer is the allocation returned by `acl_get_fd_np`
        // and this guard owns its one matching release.
        unsafe {
            acl_free(self.0);
        }
    }
}

/// Returns true if an extended ACL grants mutation or contains an unknown tag.
/// A missing ACL and a deny-only ACL return false. Inspection errors propagate.
pub(crate) fn grants_mutation(fd: &impl AsFd) -> io::Result<bool> {
    // SAFETY: the borrowed descriptor stays live for the call and the ACL type
    // is the macOS ABI value from `<sys/acl.h>`.
    let acl = unsafe { acl_get_fd_np(fd.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` stays allocated, and `entry` is an out pointer valid for
        // the duration of this iteration.
        let status = unsafe { acl_get_entry(acl.0, entry_id, &mut entry) };
        if status != 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        let mut tag = 0;
        // SAFETY: a successful `acl_get_entry` returned a live entry belonging
        // to `acl`; `tag` is a valid out pointer.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match tag {
            ACL_EXTENDED_DENY => {}
            ACL_EXTENDED_ALLOW => {
                let mut permissions = 0_u64;
                // SAFETY: same live entry; `permissions` is a valid out pointer.
                if unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                if permissions & MUTATION_PERMISSIONS != 0 {
                    return Ok(true);
                }
            }
            _ => return Ok(true),
        }
        entry_id = ACL_NEXT_ENTRY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{Mode, OFlags};
    use std::process::Command;

    fn add_acl(path: &std::path::Path, rule: &str) {
        let status = Command::new("/bin/chmod")
            .args(["+a", rule])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "failed to add test ACL {rule:?}");
    }

    fn clear_first_acl(path: &std::path::Path) {
        let status = Command::new("/bin/chmod")
            .args(["-a#", "0"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "failed to clear test ACL");
    }

    fn inspect(path: &std::path::Path) -> bool {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        grants_mutation(&fd).unwrap()
    }

    #[test]
    fn no_acl_and_standard_deny_only_acl_do_not_grant_mutation() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!inspect(directory.path()));
        add_acl(directory.path(), "everyone deny delete");
        assert!(!inspect(directory.path()));
        clear_first_acl(directory.path());
    }

    #[test]
    fn read_only_allow_is_safe_but_write_allow_grants_mutation() {
        let read_only = tempfile::tempdir().unwrap();
        add_acl(read_only.path(), "everyone allow read");
        assert!(!inspect(read_only.path()));
        clear_first_acl(read_only.path());

        let writable = tempfile::tempdir().unwrap();
        add_acl(writable.path(), "everyone allow write,delete");
        assert!(inspect(writable.path()));
        clear_first_acl(writable.path());
    }
}
