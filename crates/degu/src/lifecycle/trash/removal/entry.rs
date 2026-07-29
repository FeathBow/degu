use std::ffi::CStr;
use std::io;
use std::path::Path;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags, Stat};

use degu_core::oplog::{ObjectIdentity, ObjectKind};
use degu_walk::mount::MountIdentity;

use super::error::{contextual_error, require_same_mount};
use super::identity::{IdentityExpectation, object_identity_from_stat};

const OPEN_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(super) struct NamedEntry<'a> {
    parent: &'a OwnedFd,
    name: &'a CStr,
    path: &'a Path,
}

impl<'a> NamedEntry<'a> {
    pub(super) fn new(parent: &'a OwnedFd, name: &'a CStr, path: &'a Path) -> Self {
        Self { parent, name, path }
    }

    pub(super) fn path(&self) -> &Path {
        self.path
    }

    pub(super) fn stat(&self) -> io::Result<Stat> {
        rustix::fs::statat(self.parent, self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| contextual_error("inspect entry", self.path, error))
    }

    pub(super) fn open_if_directory(
        &self,
        expected: ObjectIdentity,
    ) -> io::Result<Option<OwnedFd>> {
        if expected.kind != ObjectKind::Directory {
            return Ok(None);
        }
        let directory = self.open_directory()?;
        let opened = rustix::fs::fstat(&directory).map_err(io::Error::from)?;
        IdentityExpectation::Exact(expected)
            .require(self.path, object_identity_from_stat(&opened))?;
        Ok(Some(directory))
    }

    pub(super) fn open_directory(&self) -> io::Result<OwnedFd> {
        open_directory_at(self.parent, self.name, self.path)
    }

    pub(super) fn mount(
        &self,
        directory: Option<&OwnedFd>,
        parent_mount: &MountIdentity,
    ) -> io::Result<MountIdentity> {
        match directory {
            Some(directory) => degu_walk::mount::identity_for_fd(directory, self.path),
            None => self.current_mount(parent_mount),
        }
    }

    pub(super) fn unlink_directory(
        &self,
        identity: ObjectIdentity,
        mount: &MountIdentity,
    ) -> io::Result<()> {
        self.unlink(UnlinkExpectation::directory(identity, mount))
    }

    pub(super) fn unlink_file(
        &self,
        identity: ObjectIdentity,
        mount: &MountIdentity,
    ) -> io::Result<()> {
        self.unlink(UnlinkExpectation::file(identity, mount))
    }

    fn current_mount(&self, _parent_mount: &MountIdentity) -> io::Result<MountIdentity> {
        #[cfg(target_os = "linux")]
        return degu_walk::mount::identity_for_entry(self.parent.as_fd(), self.name, self.path);
        #[cfg(target_os = "macos")]
        return Ok(_parent_mount.clone());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "reliable mount identity is unavailable for {}",
                self.path.display()
            ),
        ))
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "verified fd-relative unlink is confined to the lifecycle trash engine"
    )]
    fn unlink(&self, expected: UnlinkExpectation<'_>) -> io::Result<()> {
        self.revalidate(&expected)?;
        match rustix::fs::unlinkat(self.parent, self.name, expected.flags) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::ACCESS | rustix::io::Errno::PERM) => {
                add_owner_write(self.parent, self.path)?;
                self.revalidate(&expected)?;
                rustix::fs::unlinkat(self.parent, self.name, expected.flags)
                    .map_err(|error| contextual_error("remove entry", self.path, error))
            }
            Err(error) => Err(contextual_error("remove entry", self.path, error)),
        }
    }

    fn revalidate(&self, expected: &UnlinkExpectation<'_>) -> io::Result<()> {
        expected
            .identity
            .require(self.path, object_identity_from_stat(&self.stat()?))?;
        let actual_mount = self.current_mount(expected.mount)?;
        require_same_mount(self.path, expected.mount, &actual_mount)
    }
}

struct UnlinkExpectation<'a> {
    identity: IdentityExpectation,
    mount: &'a MountIdentity,
    flags: AtFlags,
}

impl<'a> UnlinkExpectation<'a> {
    fn directory(identity: ObjectIdentity, mount: &'a MountIdentity) -> Self {
        Self {
            identity: IdentityExpectation::Stable(identity),
            mount,
            flags: AtFlags::REMOVEDIR,
        }
    }

    fn file(identity: ObjectIdentity, mount: &'a MountIdentity) -> Self {
        Self {
            identity: IdentityExpectation::Exact(identity),
            mount,
            flags: AtFlags::empty(),
        }
    }
}

pub(super) fn open_directory_at<Fd: AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
) -> io::Result<OwnedFd> {
    rustix::fs::openat(parent, name, OPEN_DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| contextual_error("open directory", path, error))
}

fn add_owner_write(directory: &OwnedFd, path: &Path) -> io::Result<()> {
    let stat = rustix::fs::fstat(directory).map_err(io::Error::from)?;
    let mode = Mode::from_raw_mode(stat.st_mode).union(Mode::WUSR);
    rustix::fs::fchmod(directory, mode)
        .map_err(|error| contextual_error("make directory owner-writable", path, error))
}
