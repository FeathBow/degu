//! The extended attribute name list behind one descriptor.
//!
//! The kernel is asked for a size and then for the names, and the attribute set
//! can change between the two calls. A list that outgrew its buffer is retried
//! within a bound rather than trusted, and one that keeps growing is reported
//! rather than truncated.

use rustix::fd::AsFd;
use std::io;

const MAX_NAME_LIST_BYTES: usize = 64 * 1024;
const LIST_ATTEMPTS: usize = 3;

/// The NUL-separated, NUL-terminated attribute name list on `fd`.
pub(in crate::uv) fn names(fd: &impl AsFd) -> io::Result<Vec<u8>> {
    for _ in 0..LIST_ATTEMPTS {
        let size = list(fd, &mut [])?;
        if size == 0 {
            return Ok(Vec::new());
        }
        if size > MAX_NAME_LIST_BYTES {
            return Err(unusable("name list exceeds the safety bound"));
        }
        let mut names = vec![0_u8; size];
        match list(fd, &mut names) {
            Ok(read) if read > names.len() => {
                return Err(unusable("name list grew beyond the allocated bound"));
            }
            Ok(read) => {
                names.truncate(read);
                return Ok(names);
            }
            Err(error) if error.raw_os_error() == Some(libc::ERANGE) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(unusable(
        "name list kept growing between the size and the read",
    ))
}

fn list(fd: &impl AsFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match rustix::fs::flistxattr(fd.as_fd(), &mut *buffer) {
            Ok(size) => return Ok(size),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Whether a name list records a POSIX ACL.
///
/// Linux keeps the ACL that applies to an object under one name and the ACL its
/// new children inherit under another. Either means the namespace carries ACL
/// authority, so a walk that counted only the first would admit a directory the
/// cache-root seal and content admission both refuse.
#[cfg(any(target_os = "linux", test))]
pub(in crate::uv) fn names_a_posix_acl(names: &[u8]) -> bool {
    names.split(|byte| *byte == 0).any(|name| {
        matches!(
            name,
            b"system.posix_acl_access" | b"system.posix_acl_default"
        )
    })
}

fn unusable(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::XattrFlags;

    #[cfg(target_os = "linux")]
    const PLANTED: [&str; 2] = ["user.degu-one", "user.degu-two"];
    #[cfg(target_os = "macos")]
    const PLANTED: [&str; 2] = ["degu-one", "degu-two"];

    #[test]
    fn both_the_applied_and_the_inherited_acl_name_count_as_an_acl() {
        for present in [
            &b"system.posix_acl_access\0"[..],
            &b"system.posix_acl_default\0"[..],
            &b"user.comment\0system.posix_acl_default\0"[..],
        ] {
            assert!(names_a_posix_acl(present), "{present:?}");
        }
        for absent in [
            &b""[..],
            &b"user.comment\0"[..],
            &b"system.posix_acl_accessory\0"[..],
        ] {
            assert!(!names_a_posix_acl(absent), "{absent:?}");
        }
    }

    fn listed(file: &std::fs::File) -> Vec<String> {
        names(file)
            .unwrap()
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect()
    }

    /// Measured, not assumed: a host may attach an attribute to everything it writes,
    /// so the baseline is read rather than taken to be empty. What the listing has to
    /// report is exactly what the descriptor carries, whatever that already was.
    #[test]
    fn the_listing_reports_exactly_what_the_descriptor_carries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("decorated");
        std::fs::write(&path, b"bytes").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let baseline = listed(&file);
        for name in PLANTED {
            rustix::fs::fsetxattr(&file, name, b"value", XattrFlags::empty())
                .unwrap_or_else(|error| panic!("failed to plant {name}: {error}"));
        }

        let decorated = listed(&file);
        for name in PLANTED {
            assert!(
                decorated.contains(&name.to_owned()),
                "{name} missing: {decorated:?}"
            );
        }
        assert_eq!(
            decorated.len(),
            baseline.len() + PLANTED.len(),
            "the listing gained something the test did not plant: {baseline:?} -> {decorated:?}"
        );

        for name in PLANTED {
            rustix::fs::fremovexattr(&file, name)
                .unwrap_or_else(|error| panic!("failed to remove {name}: {error}"));
        }
        assert_eq!(
            listed(&file),
            baseline,
            "removing what the test planted must return the listing to what the host had"
        );
    }
}
