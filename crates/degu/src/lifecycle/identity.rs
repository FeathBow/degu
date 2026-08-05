use std::io;
use std::path::{Path, PathBuf};

use degu_core::oplog::ObjectIdentity;

use crate::lifecycle::trash::ParentIdentityExpectation as ParentExpectation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntryIdentity(ObjectIdentity);

#[derive(Debug)]
pub(crate) enum RenameFailure {
    Source(io::Error),
    UnauthenticatedParent {
        parent: PathBuf,
        error: io::Error,
    },
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

    /// Stage `source` into `destination` without re-resolving `AT_FDCWD + source`:
    /// open the source's parent as a verified no-follow FD, authenticate the entry
    /// through it (`fstatat`), then `renameat(RENAME_NOREPLACE)` the basename via the
    /// same FD. The pinned FD defeats an ancestor-path swap, but `fstatat`+`renameat`
    /// are two syscalls, not atomic: a basename swap between them is prevented not by
    /// the FD but by the parent being trusted (no untrusted writer), checked at open.
    /// The destination is degu's own validated trash entry (plain-path guard).
    pub(crate) fn rename_from_verified_parent(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<Self, RenameFailure> {
        let (parent, basename) = split_source_parent(source).map_err(RenameFailure::Source)?;
        let parent_fd = open_source_parent_verified(parent).map_err(|error| {
            RenameFailure::UnauthenticatedParent {
                parent: parent.to_path_buf(),
                error,
            }
        })?;
        // Authenticate the entry through the held FD; this catches a pre-check swap.
        // The check->rename gap relies on the trusted parent, not on atomicity.
        let current = entry_identity_via_parent(&parent_fd, &basename, source)
            .map_err(RenameFailure::Source)?;
        if self.0 != current {
            return Err(RenameFailure::Source(identity_changed(
                source,
                "before the move",
            )));
        }
        rename_from_parent_noreplace(&parent_fd, &basename, destination)
            .map_err(RenameFailure::Source)?;
        let moved = Self::capture(destination)
            .map_err(|error| unverified_destination(source, destination, Some(error)))?;
        if !self.same_object(&moved) {
            return Err(unverified_destination(source, destination, None));
        }
        Ok(moved)
    }

    /// Rename `source` into the directory `destination` names, pinned to
    /// `destination_parent` (physical device+inode+kind) so a swapped ancestor
    /// symlink cannot divert the move. Verified `Stable`, not `Exact`: see
    /// `open_parent_verified` for why.
    pub(crate) fn rename_verified_into_parent(
        &self,
        source: &Path,
        destination: &Path,
        destination_parent: ObjectIdentity,
    ) -> Result<Self, RenameFailure> {
        let (parent, basename) = split_destination(destination).map_err(RenameFailure::Source)?;
        // Do NOT tighten this to `Exact`. A directory's ctime bumps on every
        // entry add/remove, so `Exact` would spuriously refuse (a) the parent
        // after the stage rename that removed this entry from it, and (b) every
        // sibling past the first when a multi-entry reclamation restores several
        // entries back into the same parent.
        let parent_fd = open_parent_verified(parent, ParentExpectation::Stable(destination_parent))
            .map_err(|error| RenameFailure::UnauthenticatedParent {
                parent: parent.to_path_buf(),
                error,
            })?;
        // The source recheck sits after parent authentication, which resolves
        // and opens paths and is not constant time: a source swapped during it
        // would otherwise be renamed into the authenticated destination.
        let matches = self.matches(source).map_err(RenameFailure::Source)?;
        if !matches {
            return Err(RenameFailure::Source(identity_changed(
                source,
                "before the move",
            )));
        }
        rename_into_noreplace(source, &parent_fd, &basename).map_err(RenameFailure::Source)?;
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

fn split_source_parent(source: &Path) -> io::Result<(&Path, std::ffi::OsString)> {
    let parent = source
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    match (parent, source.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name.to_os_string())),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source has no parent or file name: {}", source.display()),
        )),
    }
}

fn split_destination(destination: &Path) -> io::Result<(&Path, std::ffi::OsString)> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    match (parent, destination.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name.to_os_string())),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "restore destination has no parent or file name: {}",
                destination.display()
            ),
        )),
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

/// Open `logical_parent` as a directory, following ancestor symlinks so a stable
/// relocation resolves, and authenticate the opened directory against `expected`.
///
/// `ParentExpectation::Exact` requires a full match including ctime, which
/// defeats delete-and-recreate inode reuse that `same_object` alone would miss.
/// `ParentExpectation::Stable` matches only device+inode+kind, which still pins
/// the physical directory (defeating an ancestor-symlink swap) while tolerating
/// the ctime bump a directory takes whenever an entry is added or removed.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(in crate::lifecycle) fn open_parent_verified(
    logical_parent: &Path,
    expected: ParentExpectation,
) -> io::Result<rustix::fd::OwnedFd> {
    use crate::lifecycle::trash::parent_identity;

    let fd = open_directory_following(logical_parent)?;
    let opened = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    expected.require(logical_parent, parent_identity(&opened))?;
    Ok(fd)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub(in crate::lifecycle) fn open_parent_verified(
    _logical_parent: &Path,
    _expected: ParentExpectation,
) -> io::Result<rustix::fd::OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified parent open is supported only on Linux and macOS",
    ))
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_into_noreplace(
    source: &Path,
    parent_fd: &rustix::fd::OwnedFd,
    basename: &std::ffi::OsStr,
) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        parent_fd,
        basename,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_into_noreplace(
    _source: &Path,
    _parent_fd: &rustix::fd::OwnedFd,
    _basename: &std::ffi::OsStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified no-replace rename is supported only on Linux and macOS",
    ))
}

/// Open the source's parent as an `O_DIRECTORY` FD and authenticate it as a
/// trusted namespace (owner- and sticky-aware, via
/// `degu_walk::directory_grants_foreign_mutation`). Ancestor symlinks are followed
/// so a relocated XDG cache home resolves; the anti-swap defense is not the open
/// flags but the pinned FD returned here -- every later `fstatat`/`renameat` acts
/// through this handle, not `AT_FDCWD + source`, so a swap after this open cannot
/// divert the move.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn open_source_parent_verified(parent: &Path) -> io::Result<rustix::fd::OwnedFd> {
    let fd = open_directory_following(parent)?;
    let opened = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    let euid = rustix::process::geteuid().as_raw();
    if opened.st_uid != euid && opened.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "source parent {} is owned by UID {} not the invoking UID {euid}",
                parent.display(),
                opened.st_uid
            ),
        ));
    }
    if degu_walk::directory_grants_foreign_mutation(opened.st_uid, opened.st_mode as u32, euid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "source parent {} is group- or world-writable without the sticky bit",
                parent.display()
            ),
        ));
    }
    Ok(fd)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn open_source_parent_verified(_parent: &Path) -> io::Result<rustix::fd::OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified source-parent open is supported only on Linux and macOS",
    ))
}

/// Capture the identity of `basename` relative to the held `parent_fd`, no-follow,
/// so the entry is authenticated in the exact namespace the rename will use.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn entry_identity_via_parent(
    parent_fd: &rustix::fd::OwnedFd,
    basename: &std::ffi::OsStr,
    source: &Path,
) -> io::Result<ObjectIdentity> {
    use crate::lifecycle::trash::parent_identity;

    let stat = rustix::fs::statat(parent_fd, basename, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| {
            io::Error::new(
                io::Error::from(error).kind(),
                format!("failed to inspect source entry {}", source.display()),
            )
        })?;
    Ok(parent_identity(&stat))
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn entry_identity_via_parent(
    _parent_fd: &rustix::fd::OwnedFd,
    _basename: &std::ffi::OsStr,
    _source: &Path,
) -> io::Result<ObjectIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified source-entry inspection is supported only on Linux and macOS",
    ))
}

/// Rename `basename` (relative to the held source `parent_fd`) to `destination`
/// with `RENAME_NOREPLACE`. Source pinned to the FD; destination is degu's trash.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_from_parent_noreplace(
    parent_fd: &rustix::fd::OwnedFd,
    basename: &std::ffi::OsStr,
    destination: &Path,
) -> io::Result<()> {
    rustix::fs::renameat_with(
        parent_fd,
        basename,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_from_parent_noreplace(
    _parent_fd: &rustix::fd::OwnedFd,
    _basename: &std::ffi::OsStr,
    _destination: &Path,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "verified no-replace rename is supported only on Linux and macOS",
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

    // (3) ino-reuse: a directory with the same device+inode but a different
    // ctime (delete-and-recreate) is refused by the Exact parent primitive, and
    // accepted by the Stable variant the restore path uses.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn exact_parent_check_refuses_a_reused_inode_that_stable_accepts() {
        use super::{ParentExpectation, open_parent_verified};
        use degu_core::oplog::ObjectIdentity;

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let actual = ObjectIdentity::capture(&parent).unwrap();
        // A recreated directory that reused the inode: identical object, later
        // ctime. Mirrors identity.rs's documented ino-reuse gap.
        let mut reused = actual;
        reused.ctime_nanoseconds ^= 1;

        assert!(actual.same_object(&reused));
        assert_ne!(actual, reused);

        // Exact refuses the reused inode.
        let error = open_parent_verified(&parent, ParentExpectation::Exact(reused)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        // Stable (device+inode+kind), used by the live restore path, accepts it.
        open_parent_verified(&parent, ParentExpectation::Stable(reused)).unwrap();
    }

    // (1)/(4) rename_verified_into_parent follows a stable symlink to the
    // physical directory and refuses once that symlink is swapped for another.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the attack fixture swaps an ancestor symlink with a raw remove_file; the verified deletion engine is the subject under test"
    )]
    fn rename_into_parent_follows_a_stable_symlink_and_refuses_a_swap() {
        use crate::lifecycle::identity::capture_parent_following;

        let dir = tempfile::tempdir().unwrap();
        let physical = dir.path().join("physical");
        let evil = dir.path().join("evil");
        std::fs::create_dir(&physical).unwrap();
        std::fs::create_dir(&evil).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&physical, &alias).unwrap();

        let source = dir.path().join("source");
        std::fs::write(&source, "payload").unwrap();
        let identity = EntryIdentity::capture(&source).unwrap();
        // Parent identity captured through the symlink names the physical dir.
        let recorded_parent = capture_parent_following(&alias).unwrap();

        // Swap the symlink to the evil directory before the restore.
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&evil, &alias).unwrap();

        let destination = alias.join("restored");
        let error = identity
            .rename_verified_into_parent(&source, &destination, recorded_parent)
            .unwrap_err();
        let RenameFailure::UnauthenticatedParent { .. } = error else {
            panic!("swapped ancestor must fail parent authentication");
        };
        assert!(source.exists());
        assert!(!evil.join("restored").exists());

        // Restore the legitimate symlink target: the move now resolves and lands
        // in the physical directory.
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&physical, &alias).unwrap();
        identity
            .rename_verified_into_parent(&source, &destination, recorded_parent)
            .unwrap();
        assert!(!source.exists());
        assert_eq!(
            std::fs::read_to_string(physical.join("restored")).unwrap(),
            "payload"
        );
    }

    // Crux: a parent-writer swaps the root entry after the final path-based
    // validation but before the rename. The held source-parent FD authenticates
    // the entry's identity immediately before the renameat, so the swapped
    // foreign object is refused and never lands in the destination.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn rename_from_parent_refuses_a_swapped_source_and_never_moves_the_foreign_object() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&source, "planned").unwrap();
        let identity = EntryIdentity::capture(&source).unwrap();

        // A parent-writer replaces the root name with a foreign object between
        // the planned identity capture and the rename.
        std::fs::rename(&source, dir.path().join("stashed")).unwrap();
        std::fs::write(&source, "foreign").unwrap();

        let error = identity
            .rename_from_verified_parent(&source, &destination)
            .unwrap_err();

        let RenameFailure::Source(error) = error else {
            panic!("a swapped source must fail the entry-identity check, not move");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "foreign");
        assert!(!destination.exists());
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn rename_from_parent_moves_a_verified_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&source, "planned").unwrap();
        let identity = EntryIdentity::capture(&source).unwrap();

        let moved = identity
            .rename_from_verified_parent(&source, &destination)
            .unwrap();

        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "planned");
        assert!(identity.same_object(&moved));
    }

    // An ancestor of the source is replaced with a symlink AFTER the parent FD
    // is open. The held FD binds the original physical parent, so the entry
    // check and the renameat still act on the original namespace, not the
    // diverted one. Proven by opening the parent FD ourselves, swapping the
    // ancestor, then renaming through the held FD.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the fixture swaps an ancestor with raw fs calls; the held-parent-FD rename is the subject under test"
    )]
    fn rename_from_parent_binds_the_original_namespace_after_an_ancestor_swap() {
        use super::{open_source_parent_verified, rename_from_parent_noreplace};

        let dir = tempfile::tempdir().unwrap();
        let physical = dir.path().join("physical");
        let evil = dir.path().join("evil");
        std::fs::create_dir(&physical).unwrap();
        std::fs::create_dir(&evil).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&physical, &alias).unwrap();

        // The source lives inside the physical directory, reached via the alias.
        let logical_parent = alias.join("holder");
        std::fs::create_dir(&logical_parent).unwrap();
        let source = logical_parent.join("source");
        std::fs::write(&source, "payload").unwrap();
        let identity = EntryIdentity::capture(&source).unwrap();

        // Open the parent FD through the alias; it now pins the physical holder.
        let parent_fd = open_source_parent_verified(&logical_parent).unwrap();

        // Swap the ancestor symlink to the evil tree AFTER the FD is open.
        let evil_holder = evil.join("holder");
        std::fs::create_dir(&evil_holder).unwrap();
        std::fs::write(evil_holder.join("source"), "planted").unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&evil, &alias).unwrap();

        // The entry check via the held FD still sees the original object.
        let current =
            super::entry_identity_via_parent(&parent_fd, std::ffi::OsStr::new("source"), &source)
                .unwrap();
        assert_eq!(identity.0, current);

        let destination = dir.path().join("destination");
        rename_from_parent_noreplace(&parent_fd, std::ffi::OsStr::new("source"), &destination)
            .unwrap();

        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "payload");
        assert_eq!(
            std::fs::read_to_string(evil_holder.join("source")).unwrap(),
            "planted"
        );
    }

    // The held-parent-FD open is no-follow, owner- and sticky-aware: a group/
    // world-writable, non-sticky parent is refused before any rename, and an
    // EUID-owned sticky (1777) parent -- the crux P1-B regression case -- is
    // still accepted.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn open_source_parent_refuses_an_untrusted_parent() {
        use super::open_source_parent_verified;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("shared");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();

        let error = open_source_parent_verified(&parent).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        // The EUID-owned sticky variant of the same mode is accepted: sticky
        // confines rename/delete to the entry owner and the parent is ours.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777)).unwrap();
        open_source_parent_verified(&parent).unwrap();

        // Regression: a plain EUID-owned 0700 parent is accepted.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        open_source_parent_verified(&parent).unwrap();
    }

    // A ROOT-owned parent that is not shared-writable-without-sticky is trusted:
    // root is outside degu's unprivileged threat model, so the owner clause does
    // not demote a root-owned system directory (`/usr`, `/tmp`, container roots,
    // HPC scratch). This uses a real root-owned system directory (`/usr`),
    // searchable by all and mode 0755, and skips cleanly when the test itself
    // runs as root or owns `/usr` (the root exemption is then indistinguishable
    // from same-owner trust).
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn open_source_parent_trusts_a_root_owned_parent() {
        use super::open_source_parent_verified;
        use std::os::unix::fs::MetadataExt;

        let euid = rustix::process::geteuid().as_raw();
        let root_owned = std::path::Path::new("/usr");
        let Ok(metadata) = std::fs::metadata(root_owned) else {
            eprintln!("skipping: /usr is unavailable on this platform");
            return;
        };
        if metadata.uid() != 0 || metadata.uid() == euid {
            eprintln!("skipping: /usr is not a foreign root-owned directory here");
            return;
        }
        // Guard against the mode clause: /usr must not be shared-writable without
        // sticky, or the refusal would come from mode, not the owner exemption.
        assert_eq!(
            metadata.mode() & 0o022,
            0,
            "/usr is unexpectedly group/world-writable"
        );

        open_source_parent_verified(root_owned).expect("root-owned 0755 parent must be trusted");
    }
}
