#[cfg(target_os = "linux")]
use std::ffi::CStr;
use std::io;
use std::path::Path;

use rustix::fd::AsFd;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountIdentity(MountKey);

#[derive(Clone, Debug, Eq, PartialEq)]
enum MountKey {
    #[cfg(target_os = "linux")]
    Linux(u64),
    #[cfg(target_os = "macos")]
    Mac(Vec<u8>),
    #[cfg(test)]
    Fake(u8),
}

#[cfg(test)]
impl MountIdentity {
    pub(crate) fn fake(value: u8) -> Self {
        Self(MountKey::Fake(value))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn containing_mount(path: &Path) -> io::Result<MountIdentity> {
    use rustix::fs::{AtFlags, StatxFlags};

    let requested = StatxFlags::MNT_ID;
    let stat = rustix::fs::statx(rustix::fs::CWD, path, AtFlags::NO_AUTOMOUNT, requested)
        .map_err(|error| linux_statx_error(path, error))?;
    linux_mount(path, stat.stx_mask, stat.stx_mnt_id)
}

#[cfg(target_os = "linux")]
pub fn identity_for_fd(fd: impl AsFd, path: &Path) -> io::Result<MountIdentity> {
    use rustix::fs::{AtFlags, StatxFlags};

    let stat = rustix::fs::statx(fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(|error| linux_statx_error(path, error))?;
    linux_mount(path, stat.stx_mask, stat.stx_mnt_id)
}

#[cfg(target_os = "linux")]
pub fn identity_for_entry(
    parent: impl AsFd,
    name: &CStr,
    path: &Path,
) -> io::Result<MountIdentity> {
    use rustix::fs::{AtFlags, StatxFlags};

    let flags = AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT;
    let stat = rustix::fs::statx(parent, name, flags, StatxFlags::MNT_ID)
        .map_err(|error| linux_statx_error(path, error))?;
    linux_mount(path, stat.stx_mask, stat.stx_mnt_id)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_mount(path: &Path, present: u32, mount_id: u64) -> io::Result<MountIdentity> {
    require_linux_field(path, present, rustix::fs::StatxFlags::MNT_ID)?;
    Ok(MountIdentity(MountKey::Linux(mount_id)))
}

#[cfg(target_os = "linux")]
fn require_linux_field(
    path: &Path,
    present: u32,
    required: rustix::fs::StatxFlags,
) -> io::Result<()> {
    let present = rustix::fs::StatxFlags::from_bits_retain(present);
    if present.contains(required) {
        Ok(())
    } else {
        Err(unsupported(path))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_statx_error(path: &Path, error: rustix::io::Errno) -> io::Error {
    if matches!(error, rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) {
        unsupported(path)
    } else {
        contextual_error(path, error)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn containing_mount(path: &Path) -> io::Result<MountIdentity> {
    let stat = rustix::fs::statfs(path).map_err(|error| contextual_error(path, error))?;
    mac_mount(stat.f_mntonname.iter().map(|byte| *byte as u8), path)
}

#[cfg(target_os = "macos")]
pub fn identity_for_fd(fd: impl AsFd, path: &Path) -> io::Result<MountIdentity> {
    let stat = rustix::fs::fstatfs(fd).map_err(|error| contextual_error(path, error))?;
    mac_mount(stat.f_mntonname.iter().map(|byte| *byte as u8), path)
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_mount(bytes: impl Iterator<Item = u8>, path: &Path) -> io::Result<MountIdentity> {
    let mount = bytes.take_while(|byte| *byte != 0).collect::<Vec<_>>();
    (!mount.is_empty())
        .then_some(MountIdentity(MountKey::Mac(mount)))
        .ok_or_else(|| unsupported(path))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn containing_mount(path: &Path) -> io::Result<MountIdentity> {
    Err(unsupported(path))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn identity_for_fd(_fd: impl AsFd, path: &Path) -> io::Result<MountIdentity> {
    Err(unsupported(path))
}

pub(crate) fn unsupported(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "reliable mount identity is unavailable for {}",
            path.display()
        ),
    )
}

pub(crate) fn contextual_error(path: &Path, error: rustix::io::Errno) -> io::Error {
    let kind = io::Error::from(error).kind();
    io::Error::new(
        kind,
        format!("failed to inspect mount for {}: {error}", path.display()),
    )
}
