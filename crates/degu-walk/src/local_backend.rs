//! Strict certification evidence for the local mode-bit backend.
//!
//! This is deliberately separate from `FsFlavor::Local`: that coarse flavor is
//! only a scan-concurrency hint. Certification accepts Linux ext4/XFS only when
//! statx mount-id, `/proc/self/mountinfo` filesystem type, and fstatfs magic all
//! agree; macOS accepts APFS only. No chmod or cleanup operation lives here.

use rustix::fd::OwnedFd;
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io;
use std::os::fd::{AsRawFd, RawFd};

const LINUX_MAGIC_MASK: u64 = u32::MAX as u64;
const EXT4_MAGIC: u64 = 0x0000_EF53;
const XFS_MAGIC: u64 = 0x5846_5342;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedLocalBackend {
    Ext4,
    Xfs,
    Apfs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationError {
    UnsupportedPlatform,
    MountIdentityUnavailable,
    MountInfoUnreadable,
    MountInfoMalformed,
    MountInfoMissing,
    MountInfoAmbiguous,
    UnsupportedFilesystem,
    FilesystemMagicMismatch,
    InspectionFailed,
    NotDirectory,
    AclPresent,
    AclProbeUnknown,
    ProcessCredentialsUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxMountRecord {
    mount_id: u64,
    filesystem_type: String,
}

fn parse_linux_mountinfo(
    input: &str,
    wanted_mount_id: u64,
) -> Result<LinuxMountRecord, CertificationError> {
    let mut found = None;
    for line in input.lines() {
        let (mount_fields, filesystem_fields) = line
            .split_once(" - ")
            .ok_or(CertificationError::MountInfoMalformed)?;
        let mount_id = mount_fields
            .split_whitespace()
            .next()
            .ok_or(CertificationError::MountInfoMalformed)?
            .parse::<u64>()
            .map_err(|_| CertificationError::MountInfoMalformed)?;
        let filesystem_type = filesystem_fields
            .split_whitespace()
            .next()
            .filter(|value| !value.is_empty())
            .ok_or(CertificationError::MountInfoMalformed)?;
        if mount_id == wanted_mount_id {
            if found.is_some() {
                return Err(CertificationError::MountInfoAmbiguous);
            }
            found = Some(LinuxMountRecord {
                mount_id,
                filesystem_type: filesystem_type.to_owned(),
            });
        }
    }
    found.ok_or(CertificationError::MountInfoMissing)
}

/// Hermetic certification core used by the Linux held-FD probe.
pub fn certify_linux_mount(
    mount_id: u64,
    mountinfo: &str,
    filesystem_magic: u64,
) -> Result<CertifiedLocalBackend, CertificationError> {
    let record = parse_linux_mountinfo(mountinfo, mount_id)?;
    debug_assert_eq!(record.mount_id, mount_id);
    match (
        record.filesystem_type.as_str(),
        filesystem_magic & LINUX_MAGIC_MASK,
    ) {
        ("ext4", EXT4_MAGIC) => Ok(CertifiedLocalBackend::Ext4),
        ("xfs", XFS_MAGIC) => Ok(CertifiedLocalBackend::Xfs),
        ("ext4" | "xfs", _) => Err(CertificationError::FilesystemMagicMismatch),
        _ => Err(CertificationError::UnsupportedFilesystem),
    }
}

/// Hermetic macOS certification core. HFS, network filesystems, FUSE, and
/// tmpfs are intentionally not certified even if another detector calls them
/// local.
pub fn certify_macos_filesystem_name(
    filesystem_name: &[u8],
) -> Result<CertifiedLocalBackend, CertificationError> {
    if filesystem_name == b"apfs" {
        Ok(CertifiedLocalBackend::Apfs)
    } else {
        Err(CertificationError::UnsupportedFilesystem)
    }
}

/// Opaque live-descriptor backend evidence. It is neither serializable nor
/// clonable and carries no mutation, staging, or purge authority.
#[derive(Debug)]
pub struct HeldLocalBackendEvidence {
    fd: OwnedFd,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    device: u64,
    inode: u64,
    effective_uid: u32,
    effective_groups: BTreeSet<u32>,
}

impl HeldLocalBackendEvidence {
    pub fn backend(&self) -> CertifiedLocalBackend {
        self.backend
    }

    pub fn mount_id(&self) -> u64 {
        self.mount_id
    }

    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub fn group_gid(&self) -> u32 {
        self.group_gid
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    pub fn effective_groups(&self) -> &BTreeSet<u32> {
        &self.effective_groups
    }

    /// Keep the descriptor observably live without exposing it as an authority
    /// token to existing mutation code.
    pub fn is_live(&self) -> bool {
        rustix::fs::fcntl_getfl(&self.fd).is_ok()
    }
}

/// Certify an already-held descriptor. Path-level filesystem classification is
/// never accepted as a substitute for this object-relative probe.
#[cfg(target_os = "linux")]
pub fn certify_held_fd(fd: OwnedFd) -> Result<HeldLocalBackendEvidence, CertificationError> {
    use rustix::fs::{AtFlags, StatxFlags};

    let statx = rustix::fs::statx(&fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(|_| CertificationError::MountIdentityUnavailable)?;
    if !StatxFlags::from_bits_retain(statx.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(CertificationError::MountIdentityUnavailable);
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| CertificationError::MountInfoUnreadable)?;
    let statfs = rustix::fs::fstatfs(&fd).map_err(|_| CertificationError::InspectionFailed)?;
    let backend = certify_linux_mount(statx.stx_mnt_id, &mountinfo, statfs.f_type as u64)?;
    finish_certification(fd, backend, statx.stx_mnt_id)
}

#[cfg(target_os = "macos")]
pub fn certify_held_fd(fd: OwnedFd) -> Result<HeldLocalBackendEvidence, CertificationError> {
    let statfs = rustix::fs::fstatfs(&fd).map_err(|_| CertificationError::InspectionFailed)?;
    let filesystem_name = statfs
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    let backend = certify_macos_filesystem_name(&filesystem_name)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| CertificationError::InspectionFailed)?;
    let mount_id = stat.st_dev as u64;
    finish_certification(fd, backend, mount_id)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn certify_held_fd(_fd: OwnedFd) -> Result<HeldLocalBackendEvidence, CertificationError> {
    Err(CertificationError::UnsupportedPlatform)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finish_certification(
    fd: OwnedFd,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<HeldLocalBackendEvidence, CertificationError> {
    let stat = rustix::fs::fstat(&fd).map_err(|_| CertificationError::InspectionFailed)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        return Err(CertificationError::NotDirectory);
    }
    require_acl_absent(probe_acl(fd.as_raw_fd()))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let mut effective_groups = rustix::process::getgroups()
        .map_err(|_| CertificationError::ProcessCredentialsUnavailable)?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect::<BTreeSet<_>>();
    effective_groups.insert(rustix::process::getegid().as_raw());
    Ok(HeldLocalBackendEvidence {
        backend,
        mount_id,
        owner_uid: stat.st_uid,
        group_gid: stat.st_gid,
        mode: stat.st_mode as u32 & 0o7777,
        // Preserve the kernel's raw st_dev value; do not invent a packed
        // major/minor encoding which would disagree with MetadataExt::dev.
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        effective_uid,
        effective_groups,
        fd,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclProbe {
    Absent,
    Present,
    Unknown,
}

fn require_acl_absent(probe: AclProbe) -> Result<(), CertificationError> {
    match probe {
        AclProbe::Absent => Ok(()),
        AclProbe::Present => Err(CertificationError::AclPresent),
        AclProbe::Unknown => Err(CertificationError::AclProbeUnknown),
    }
}

#[cfg(target_os = "linux")]
fn probe_acl(fd: RawFd) -> AclProbe {
    let probes = [
        probe_linux_xattr(fd, c"system.posix_acl_access"),
        probe_linux_xattr(fd, c"system.posix_acl_default"),
    ];
    if probes.contains(&AclProbe::Present) {
        AclProbe::Present
    } else if probes.contains(&AclProbe::Unknown) {
        AclProbe::Unknown
    } else {
        AclProbe::Absent
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_xattr(fd: RawFd, name: &std::ffi::CStr) -> AclProbe {
    // SAFETY: fd is live and name is NUL-terminated. A null zero-sized buffer
    // asks only for the attribute length and cannot write memory.
    let result = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
    if result >= 0 {
        AclProbe::Present
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
        AclProbe::Absent
    } else {
        AclProbe::Unknown
    }
}

#[cfg(target_os = "macos")]
fn probe_acl(fd: RawFd) -> AclProbe {
    type Acl = *mut libc::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    // On macOS, acl_get_fd_np returns NULL with ENOENT when the object has no
    // extended ACL. A non-null ACL is therefore itself presence evidence.
    // Other NULL errno values are probe uncertainty and fail closed.
    // SAFETY: fd is live; a non-null returned ACL is released exactly once.
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            AclProbe::Absent
        } else {
            AclProbe::Unknown
        };
    }
    // SAFETY: acl came from acl_get_fd_np and is not used after this call.
    if unsafe { acl_free(acl) } == 0 {
        AclProbe::Present
    } else {
        AclProbe::Unknown
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe_acl(_fd: RawFd) -> AclProbe {
    AclProbe::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_requires_mount_id_type_and_magic_to_agree() {
        let mountinfo = concat!(
            "31 20 0:27 / / rw - overlay overlay rw\n",
            "44 31 8:1 / /data rw - ext4 /dev/sda1 rw\n",
            "45 31 8:2 / /xfs rw shared:1 - xfs /dev/sda2 rw\n",
        );
        assert_eq!(
            certify_linux_mount(44, mountinfo, EXT4_MAGIC),
            Ok(CertifiedLocalBackend::Ext4)
        );
        assert_eq!(
            certify_linux_mount(45, mountinfo, XFS_MAGIC),
            Ok(CertifiedLocalBackend::Xfs)
        );
        assert_eq!(
            certify_linux_mount(44, mountinfo, XFS_MAGIC),
            Err(CertificationError::FilesystemMagicMismatch)
        );
        assert_eq!(
            certify_linux_mount(31, mountinfo, 0x794c_7630),
            Err(CertificationError::UnsupportedFilesystem)
        );
        assert_eq!(
            certify_linux_mount(99, mountinfo, EXT4_MAGIC),
            Err(CertificationError::MountInfoMissing)
        );
    }

    #[test]
    fn malformed_or_duplicate_mountinfo_fails_closed() {
        assert_eq!(
            parse_linux_mountinfo("not mountinfo", 1),
            Err(CertificationError::MountInfoMalformed)
        );
        let duplicate = concat!(
            "2 1 8:1 / /a rw - ext4 /dev/a rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/b rw\n",
        );
        assert_eq!(
            parse_linux_mountinfo(duplicate, 2),
            Err(CertificationError::MountInfoAmbiguous)
        );
    }

    #[test]
    fn overlay_tmpfs_network_and_distributed_types_are_not_certified() {
        for (name, magic) in [
            ("overlay", 0x794c_7630),
            ("tmpfs", 0x0102_1994),
            ("nfs", 0x6969),
            ("lustre", 0x0bd0_0bd0),
            ("gpfs", 0x4750_4653),
            ("fuse", 0x6573_5546),
        ] {
            let mountinfo = format!("7 1 0:1 / /mnt rw - {name} source rw\n");
            assert_eq!(
                certify_linux_mount(7, &mountinfo, magic),
                Err(CertificationError::UnsupportedFilesystem),
                "filesystem {name}"
            );
        }
    }

    #[test]
    fn acl_presence_and_probe_uncertainty_fail_closed() {
        assert_eq!(require_acl_absent(AclProbe::Absent), Ok(()));
        assert_eq!(
            require_acl_absent(AclProbe::Present),
            Err(CertificationError::AclPresent)
        );
        assert_eq!(
            require_acl_absent(AclProbe::Unknown),
            Err(CertificationError::AclProbeUnknown)
        );
    }

    #[test]
    fn macos_certifies_apfs_only() {
        assert_eq!(
            certify_macos_filesystem_name(b"apfs"),
            Ok(CertifiedLocalBackend::Apfs)
        );
        for name in [b"hfs".as_slice(), b"nfs", b"smbfs", b"tmpfs", b"fuse"] {
            assert_eq!(
                certify_macos_filesystem_name(name),
                Err(CertificationError::UnsupportedFilesystem)
            );
        }
    }

    #[test]
    fn real_filesystem_probe_does_not_promote_ci_overlay_or_tmpfs() {
        let temp = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            temp.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        match certify_held_fd(fd) {
            Ok(evidence) => {
                use std::os::unix::fs::MetadataExt;
                assert!(evidence.is_live());
                assert_eq!(
                    evidence.effective_uid(),
                    rustix::process::geteuid().as_raw()
                );
                assert!(
                    evidence
                        .effective_groups()
                        .contains(&rustix::process::getegid().as_raw())
                );
                assert_eq!(
                    evidence.device(),
                    std::fs::metadata(temp.path()).unwrap().dev()
                );
                assert!(matches!(
                    evidence.backend(),
                    CertifiedLocalBackend::Ext4
                        | CertifiedLocalBackend::Xfs
                        | CertifiedLocalBackend::Apfs
                ));
            }
            Err(CertificationError::UnsupportedFilesystem) => {
                // Expected on the common Linux overlay/tmpfs CI workspace.
            }
            Err(error) => panic!("unexpected certification error: {error:?}"),
        }
    }
}
