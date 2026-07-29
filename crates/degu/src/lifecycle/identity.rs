use std::io;
use std::path::{Path, PathBuf};

use degu_core::oplog::ObjectIdentity;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntryIdentity(ObjectIdentity);

#[derive(Debug)]
pub(crate) enum RenameFailure {
    Source(io::Error),
    UnverifiedDestination {
        destination: PathBuf,
        error: io::Error,
    },
}

impl EntryIdentity {
    pub(crate) fn capture(path: &Path) -> io::Result<Self> {
        ObjectIdentity::capture(path).map(Self)
    }

    pub(crate) fn matches(&self, path: &Path) -> io::Result<bool> {
        ObjectIdentity::capture(path).map(|current| self.0 == current)
    }

    pub(crate) fn oplog_identity(&self) -> ObjectIdentity {
        self.0
    }

    pub(crate) fn rename_verified_located(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<Self, RenameFailure> {
        let matches = self.matches(source).map_err(RenameFailure::Source)?;
        if !matches {
            return Err(RenameFailure::Source(identity_changed(
                source,
                "before the move",
            )));
        }
        rename_noreplace(source, destination).map_err(RenameFailure::Source)?;
        let moved = Self::capture(destination)
            .map_err(|error| unverified_destination(source, destination, Some(error)))?;
        if !self.same_object(&moved) {
            return Err(unverified_destination(source, destination, None));
        }
        Ok(moved)
    }

    fn same_object(&self, other: &Self) -> bool {
        self.0.same_object(&other.0)
    }
}

fn unverified_destination(
    source: &Path,
    destination: &Path,
    inspection_error: Option<io::Error>,
) -> RenameFailure {
    let detail = inspection_error
        .map(|error| format!("identity inspection failed: {error}"))
        .unwrap_or_else(|| "destination identity did not match the planned source".to_string());
    RenameFailure::UnverifiedDestination {
        destination: destination.to_path_buf(),
        error: io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "entry moved from {} but could not be verified at {}: {detail}; automatic rollback was not attempted",
                source.display(),
                destination.display()
            ),
        ),
    }
}

fn identity_changed(path: &Path, phase: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("entry identity changed {phase}: {}", path.display()),
    )
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(crate) fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub(crate) fn rename_noreplace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified no-replace rename is supported only on Linux and macOS",
    ))
}

/// Open `logical_parent` as a directory, following ancestor symlinks so a stable
/// relocation resolves. Used at stage time to snapshot the directory a later
/// restore must move the entry back into.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn open_directory_following(logical_parent: &Path) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};

    let flags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC);
    rustix::fs::openat(rustix::fs::CWD, logical_parent, flags, Mode::empty())
        .map_err(io::Error::from)
}

/// Snapshot the identity of `logical_parent`, resolving ancestor symlinks.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(in crate::lifecycle) fn capture_parent_following(
    logical_parent: &Path,
) -> io::Result<ObjectIdentity> {
    use crate::lifecycle::trash::parent_identity;

    let fd = open_directory_following(logical_parent)?;
    let opened = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    Ok(parent_identity(&opened))
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub(in crate::lifecycle) fn capture_parent_following(
    _logical_parent: &Path,
) -> io::Result<ObjectIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified parent capture is supported only on Linux and macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::{EntryIdentity, RenameFailure, unverified_destination};

    #[test]
    fn verified_rename_rejects_a_replaced_source_without_moving_it() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&source, "planned").unwrap();
        let identity = EntryIdentity::capture(&source).unwrap();
        std::fs::rename(&source, dir.path().join("old-source")).unwrap();
        std::fs::write(&source, "replacement").unwrap();

        let error = identity
            .rename_verified_located(&source, &destination)
            .unwrap_err();

        let RenameFailure::Source(error) = error else {
            panic!("source should not have moved");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "replacement");
        assert!(!destination.exists());
    }

    #[test]
    fn ctime_distinguishes_a_reused_inode_before_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entry");
        std::fs::write(&path, "data").unwrap();
        let expected = EntryIdentity::capture(&path).unwrap();
        let mut reused = expected.clone();
        reused.0.ctime_nanoseconds ^= 1;

        assert_ne!(expected, reused);
        assert!(expected.same_object(&reused));
    }

    #[test]
    fn verified_rename_returns_the_destination_identity() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&source, "planned").unwrap();
        let expected = EntryIdentity::capture(&source).unwrap();

        let moved = expected
            .rename_verified_located(&source, &destination)
            .unwrap();

        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "planned");
        assert!(expected.same_object(&moved));
        assert!(moved.matches(&destination).unwrap());
    }

    #[test]
    fn unverified_destination_is_never_moved_back_to_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&destination, "concurrent replacement").unwrap();

        let failure = unverified_destination(&source, &destination, None);

        let RenameFailure::UnverifiedDestination {
            destination: unverified,
            ..
        } = failure
        else {
            panic!("destination should remain unverified");
        };
        assert_eq!(unverified, destination);
        assert!(!source.exists());
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "concurrent replacement"
        );
    }
}
