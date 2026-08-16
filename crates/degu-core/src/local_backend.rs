//! Strict certification evidence for the local mode-bit backend.
//!
//! This is deliberately separate from `FsFlavor::Local`: that coarse flavor is
//! only a scan-concurrency hint. Certification accepts Linux ext4/XFS only when
//! statx mount-id, `/proc/self/mountinfo` filesystem type, and fstatfs magic all
//! agree; macOS accepts APFS only. Its sole mutation seam is a held-FD
//! `fchmod` primitive reserved for degu-core's durable WAL wrapper.

use crate::seal_wal::TransactionId;

#[allow(dead_code)] // closed, authority-neutral traversal API
pub(crate) mod held_tree;
use rustix::fd::{AsFd, OwnedFd};
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io;
use std::os::fd::{AsRawFd, RawFd};

const LINUX_MAGIC_MASK: u64 = u32::MAX as u64;
const EXT4_MAGIC: u64 = 0x0000_EF53;
const XFS_MAGIC: u64 = 0x5846_5342;

fn crate_minimal_sealed_mode(mode: u32) -> u32 {
    let mut sealed = mode;
    if mode & 0o030 == 0o030 {
        sealed &= !0o020;
    }
    if mode & 0o003 == 0o003 {
        sealed &= !0o002;
    }
    sealed
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalModeRevalidationFailure {
    DescriptorUnavailable,
    DescriptorCannotChmod,
    BackendUnavailable,
    BackendChanged,
    MountChanged,
    IdentityChanged,
    NotDirectory,
    OwnerChanged,
    GroupChanged,
    EffectiveUidChanged,
    EffectiveGroupsChanged,
    ModeChanged { expected: u32, actual: u32 },
    AclPresent,
    AclProbeUnknown,
    InvalidTargetMode,
    EvidenceUnverified,
    SealAlreadyActive,
    MissingSealLineage,
    SealLineageMismatch,
    NamespaceWritersPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedLocalFileType {
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedLocalModeSnapshot {
    backend: CertifiedLocalBackend,
    mount_id: u64,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    device: u64,
    inode: u64,
    file_type: VerifiedLocalFileType,
    effective_uid: u32,
    effective_groups: BTreeSet<u32>,
}

/// One-use, non-clonable precondition for a mode change on a held descriptor.
#[derive(Debug)]
pub(crate) struct PreparedHeldModeChange {
    pre: VerifiedLocalModeSnapshot,
    target_mode: u32,
    kind: PreparedModeChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealLineage {
    transaction: TransactionId,
    mutation_id: u64,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    device: u64,
    inode: u64,
    owner_uid: u32,
    group_gid: u32,
    effective_uid: u32,
    effective_groups: BTreeSet<u32>,
    original_mode: u32,
    sealed_mode: u32,
}

#[derive(Debug)]
enum PreparedModeChangeKind {
    Seal,
    Restore(SealLineage),
}

impl PreparedHeldModeChange {
    pub fn pre_mode(&self) -> u32 {
        self.pre.mode
    }
    pub fn target_mode(&self) -> u32 {
        self.target_mode
    }
    pub fn device(&self) -> u64 {
        self.pre.device
    }
    pub fn inode(&self) -> u64 {
        self.pre.inode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeSyscallFailure(pub i32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeldModeChangeOutcome {
    AppliedVerified {
        pre: VerifiedLocalModeSnapshot,
        post: VerifiedLocalModeSnapshot,
    },
    NotAppliedVerified {
        snapshot: VerifiedLocalModeSnapshot,
        cause: ModeSyscallFailure,
    },
    RefusedBeforeMutation {
        reason: LocalModeRevalidationFailure,
    },
    AppliedButUnverified {
        expected_target: u32,
        reason: LocalModeRevalidationFailure,
    },
    OutcomeUnknown {
        syscall: ModeSyscallFailure,
        post_failure: LocalModeRevalidationFailure,
    },
}

#[derive(Debug)]
pub struct HeldLocalBackendEvidence {
    fd: OwnedFd,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    mode_verified: bool,
    device: u64,
    inode: u64,
    effective_uid: u32,
    effective_groups: BTreeSet<u32>,
    seal_lineage: Option<SealLineage>,
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

    pub fn mode_is_verified(&self) -> bool {
        self.mode_verified
    }

    /// Reads only the current mode bits from the already-held descriptor.
    /// This does not expose the descriptor or grant mutation authority.
    pub(crate) fn fresh_mode(&self) -> std::io::Result<u32> {
        rustix::fs::fstat(&self.fd)
            .map(|stat| raw_mode_u32(stat.st_mode) & 0o7777)
            .map_err(std::io::Error::from)
    }

    /// Revalidates the complete certified directory snapshot at a required
    /// current mode without exposing the held descriptor or mutation authority.
    pub(crate) fn verify_current_mode(
        &self,
        expected_mode: u32,
    ) -> Result<(), LocalModeRevalidationFailure> {
        let actual = inspect_held_fd(&self.fd)?;
        validate_snapshot(&actual, &self.certified_snapshot(), expected_mode)
    }

    /// Requires the exact held parent to exclude group/world namespace writers.
    /// Owner write+search remains necessary for the later FD-relative rename.
    pub(crate) fn verify_namespace_exclusive(&self) -> Result<(), LocalModeRevalidationFailure> {
        self.verify_current_mode(self.mode)?;
        if self.mode & 0o030 == 0o030 || self.mode & 0o003 == 0o003 {
            Err(LocalModeRevalidationFailure::NamespaceWritersPresent)
        } else {
            Ok(())
        }
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

    /// Parent-private adapter for the child held-tree implementation. Sibling
    /// modules cannot obtain this descriptor, and the borrow cannot escape the
    /// operation's lifetime.
    fn with_authority_fd<R>(&self, operation: impl FnOnce(rustix::fd::BorrowedFd<'_>) -> R) -> R {
        operation(self.fd.as_fd())
    }

    pub(crate) fn prepare_minimal_seal(
        &mut self,
        acquire_owner_write_search: bool,
    ) -> Result<PreparedHeldModeChange, LocalModeRevalidationFailure> {
        if !self.mode_verified {
            return Err(LocalModeRevalidationFailure::EvidenceUnverified);
        }
        if self.seal_lineage.is_some() {
            return Err(LocalModeRevalidationFailure::SealAlreadyActive);
        }
        let base = if acquire_owner_write_search {
            self.mode | 0o300
        } else {
            self.mode
        };
        self.prepare_exact_mode_change(
            crate_minimal_sealed_mode(base),
            PreparedModeChangeKind::Seal,
        )
    }

    /// Re-establish seal lineage after startup recovery has independently
    /// authenticated this exact held object with strong incarnation evidence.
    /// This does not inspect a path and cannot be called outside degu-core.
    #[allow(dead_code, clippy::too_many_arguments)] // startup recovery execution seam
    pub(crate) fn bind_recovered_seal_lineage(
        &mut self,
        transaction: TransactionId,
        original_mutation_id: u64,
        original_pre_mode: u32,
        original_expected_mode: u32,
        expected_backend: CertifiedLocalBackend,
        expected_device: u64,
        expected_inode: u64,
    ) -> Result<(), LocalModeRevalidationFailure> {
        if !self.mode_verified
            || self.seal_lineage.is_some()
            || self.backend != expected_backend
            || self.device != expected_device
            || self.inode != expected_inode
            || self.mode != original_expected_mode
        {
            return Err(LocalModeRevalidationFailure::SealLineageMismatch);
        }
        self.seal_lineage = Some(SealLineage {
            transaction,
            mutation_id: original_mutation_id,
            backend: self.backend,
            mount_id: self.mount_id,
            device: self.device,
            inode: self.inode,
            owner_uid: self.owner_uid,
            group_gid: self.group_gid,
            effective_uid: self.effective_uid,
            effective_groups: self.effective_groups.clone(),
            original_mode: original_pre_mode,
            sealed_mode: original_expected_mode,
        });
        Ok(())
    }

    pub(crate) fn prepare_wal_bound_restore(
        &mut self,
        transaction: TransactionId,
        original_mutation_id: u64,
        original_expected_mode: u32,
        original_pre_mode: u32,
    ) -> Result<PreparedHeldModeChange, LocalModeRevalidationFailure> {
        if !self.mode_verified || self.mode != original_expected_mode {
            return Err(LocalModeRevalidationFailure::EvidenceUnverified);
        }
        let lineage = self
            .seal_lineage
            .as_ref()
            .ok_or(LocalModeRevalidationFailure::MissingSealLineage)?;
        if lineage.transaction != transaction
            || lineage.mutation_id != original_mutation_id
            || lineage.backend != self.backend
            || lineage.mount_id != self.mount_id
            || lineage.device != self.device
            || lineage.inode != self.inode
            || lineage.owner_uid != self.owner_uid
            || lineage.group_gid != self.group_gid
            || lineage.effective_uid != self.effective_uid
            || lineage.effective_groups != self.effective_groups
            || lineage.original_mode != original_pre_mode
            || lineage.sealed_mode != original_expected_mode
        {
            return Err(LocalModeRevalidationFailure::SealLineageMismatch);
        }
        self.prepare_exact_mode_change(
            original_pre_mode,
            PreparedModeChangeKind::Restore(lineage.clone()),
        )
    }

    fn prepare_exact_mode_change(
        &mut self,
        target_mode: u32,
        kind: PreparedModeChangeKind,
    ) -> Result<PreparedHeldModeChange, LocalModeRevalidationFailure> {
        if target_mode & !0o7777 != 0 {
            return Err(LocalModeRevalidationFailure::InvalidTargetMode);
        }
        let expected = self.certified_snapshot();
        let pre = match inspect_held_fd(&self.fd) {
            Ok(pre) => pre,
            Err(error) => {
                self.mode_verified = false;
                return Err(error);
            }
        };
        if let Err(error) = validate_snapshot(&pre, &expected, expected.mode) {
            self.mode_verified = false;
            return Err(error);
        }
        Ok(PreparedHeldModeChange {
            pre,
            target_mode,
            kind,
        })
    }

    pub(crate) fn invalidate_after_wal_uncertainty(&mut self) {
        self.invalidate_mode(self.mode);
    }

    pub(crate) fn record_applied_seal_lineage(
        &mut self,
        transaction: TransactionId,
        mutation_id: u64,
        original_mode: u32,
        sealed_mode: u32,
    ) -> Result<(), LocalModeRevalidationFailure> {
        if !self.mode_verified || self.mode != sealed_mode {
            return Err(LocalModeRevalidationFailure::EvidenceUnverified);
        }
        if self.seal_lineage.is_some() {
            return Err(LocalModeRevalidationFailure::SealAlreadyActive);
        }
        self.seal_lineage = Some(SealLineage {
            transaction,
            mutation_id,
            backend: self.backend,
            mount_id: self.mount_id,
            device: self.device,
            inode: self.inode,
            owner_uid: self.owner_uid,
            group_gid: self.group_gid,
            effective_uid: self.effective_uid,
            effective_groups: self.effective_groups.clone(),
            original_mode,
            sealed_mode,
        });
        Ok(())
    }

    pub(crate) fn apply_wal_bound_mode_change(
        &mut self,
        prepared: PreparedHeldModeChange,
    ) -> HeldModeChangeOutcome {
        let pre = match inspect_held_fd(&self.fd).and_then(|actual| {
            validate_snapshot(&actual, &prepared.pre, prepared.pre.mode)?;
            Ok(actual)
        }) {
            Ok(pre) => pre,
            Err(reason) => {
                self.mode_verified = false;
                return HeldModeChangeOutcome::RefusedBeforeMutation { reason };
            }
        };

        let consumed_lineage = match &prepared.kind {
            PreparedModeChangeKind::Seal => None,
            PreparedModeChangeKind::Restore(expected) => match self.seal_lineage.take() {
                Some(actual) if actual == *expected => Some(actual),
                Some(actual) => {
                    self.seal_lineage = Some(actual);
                    return HeldModeChangeOutcome::RefusedBeforeMutation {
                        reason: LocalModeRevalidationFailure::SealLineageMismatch,
                    };
                }
                None => {
                    return HeldModeChangeOutcome::RefusedBeforeMutation {
                        reason: LocalModeRevalidationFailure::MissingSealLineage,
                    };
                }
            },
        };

        match rustix::fs::fchmod(
            &self.fd,
            rustix::fs::Mode::from_raw_mode(prepared.target_mode as _),
        ) {
            Ok(()) => {
                let post = inspect_held_fd(&self.fd).and_then(|actual| {
                    validate_snapshot(&actual, &prepared.pre, prepared.target_mode)?;
                    Ok(actual)
                });
                self.finish_successful_chmod(prepared.target_mode, pre, post)
            }
            Err(error) => match inspect_held_fd(&self.fd).and_then(|actual| {
                validate_snapshot(&actual, &prepared.pre, prepared.pre.mode)?;
                Ok(actual)
            }) {
                Ok(snapshot) => {
                    if let Some(lineage) = consumed_lineage {
                        self.seal_lineage = Some(lineage);
                    }
                    HeldModeChangeOutcome::NotAppliedVerified {
                        snapshot,
                        cause: ModeSyscallFailure(error.raw_os_error()),
                    }
                }
                Err(post_failure) => {
                    self.invalidate_mode(self.mode);
                    HeldModeChangeOutcome::OutcomeUnknown {
                        syscall: ModeSyscallFailure(error.raw_os_error()),
                        post_failure,
                    }
                }
            },
        }
    }

    fn finish_successful_chmod(
        &mut self,
        target_mode: u32,
        pre: VerifiedLocalModeSnapshot,
        post: Result<VerifiedLocalModeSnapshot, LocalModeRevalidationFailure>,
    ) -> HeldModeChangeOutcome {
        match post {
            Ok(post) => {
                self.mode = post.mode;
                self.mode_verified = true;
                HeldModeChangeOutcome::AppliedVerified { pre, post }
            }
            Err(reason) => {
                let observed = match reason {
                    LocalModeRevalidationFailure::ModeChanged { actual, .. } => actual,
                    _ => target_mode,
                };
                self.invalidate_mode(observed);
                HeldModeChangeOutcome::AppliedButUnverified {
                    expected_target: target_mode,
                    reason,
                }
            }
        }
    }

    fn invalidate_mode(&mut self, best_observation: u32) {
        self.mode = best_observation;
        self.mode_verified = false;
        self.seal_lineage = None;
    }

    fn certified_snapshot(&self) -> VerifiedLocalModeSnapshot {
        VerifiedLocalModeSnapshot {
            backend: self.backend,
            mount_id: self.mount_id,
            owner_uid: self.owner_uid,
            group_gid: self.group_gid,
            mode: self.mode,
            device: self.device,
            inode: self.inode,
            file_type: VerifiedLocalFileType::Directory,
            effective_uid: self.effective_uid,
            effective_groups: self.effective_groups.clone(),
        }
    }
}

fn validate_snapshot(
    actual: &VerifiedLocalModeSnapshot,
    expected: &VerifiedLocalModeSnapshot,
    expected_mode: u32,
) -> Result<(), LocalModeRevalidationFailure> {
    if actual.backend != expected.backend {
        return Err(LocalModeRevalidationFailure::BackendChanged);
    }
    if actual.mount_id != expected.mount_id {
        return Err(LocalModeRevalidationFailure::MountChanged);
    }
    if actual.device != expected.device || actual.inode != expected.inode {
        return Err(LocalModeRevalidationFailure::IdentityChanged);
    }
    if actual.file_type != expected.file_type {
        return Err(LocalModeRevalidationFailure::NotDirectory);
    }
    if actual.owner_uid != expected.owner_uid {
        return Err(LocalModeRevalidationFailure::OwnerChanged);
    }
    if actual.group_gid != expected.group_gid {
        return Err(LocalModeRevalidationFailure::GroupChanged);
    }
    if actual.effective_uid != expected.effective_uid || actual.effective_uid != actual.owner_uid {
        return Err(LocalModeRevalidationFailure::EffectiveUidChanged);
    }
    if actual.effective_groups != expected.effective_groups {
        return Err(LocalModeRevalidationFailure::EffectiveGroupsChanged);
    }
    if actual.mode != expected_mode {
        return Err(LocalModeRevalidationFailure::ModeChanged {
            expected: expected_mode,
            actual: actual.mode,
        });
    }
    Ok(())
}

fn current_groups() -> Result<BTreeSet<u32>, LocalModeRevalidationFailure> {
    let mut groups = rustix::process::getgroups()
        .map_err(|_| LocalModeRevalidationFailure::EffectiveGroupsChanged)?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect::<BTreeSet<_>>();
    groups.insert(rustix::process::getegid().as_raw());
    Ok(groups)
}

fn checked_acl(fd: RawFd) -> Result<(), LocalModeRevalidationFailure> {
    match probe_acl(fd) {
        AclProbe::Absent => Ok(()),
        AclProbe::Present => Err(LocalModeRevalidationFailure::AclPresent),
        AclProbe::Unknown => Err(LocalModeRevalidationFailure::AclProbeUnknown),
    }
}

#[cfg(target_os = "linux")]
fn inspect_held_fd(
    fd: &OwnedFd,
) -> Result<VerifiedLocalModeSnapshot, LocalModeRevalidationFailure> {
    use rustix::fs::{AtFlags, OFlags, StatxFlags};

    let flags = rustix::fs::fcntl_getfl(fd)
        .map_err(|_| LocalModeRevalidationFailure::DescriptorUnavailable)?;
    if flags.contains(OFlags::PATH) {
        return Err(LocalModeRevalidationFailure::DescriptorCannotChmod);
    }
    let statx = rustix::fs::statx(fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    if !StatxFlags::from_bits_retain(statx.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(LocalModeRevalidationFailure::BackendUnavailable);
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    let statfs =
        rustix::fs::fstatfs(fd).map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    let backend = certify_linux_mount(statx.stx_mnt_id, &mountinfo, statfs.f_type as u64)
        .map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    let stat =
        rustix::fs::fstat(fd).map_err(|_| LocalModeRevalidationFailure::DescriptorUnavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        return Err(LocalModeRevalidationFailure::NotDirectory);
    }
    checked_acl(fd.as_raw_fd())?;
    Ok(VerifiedLocalModeSnapshot {
        backend,
        mount_id: statx.stx_mnt_id,
        owner_uid: stat.st_uid,
        group_gid: stat.st_gid,
        mode: stat.st_mode as u32 & 0o7777,
        device: raw_dev_u64(stat.st_dev).ok_or(LocalModeRevalidationFailure::IdentityChanged)?,
        inode: stat.st_ino as u64,
        file_type: VerifiedLocalFileType::Directory,
        effective_uid: rustix::process::geteuid().as_raw(),
        effective_groups: current_groups()?,
    })
}

#[cfg(target_os = "macos")]
fn inspect_held_fd(
    fd: &OwnedFd,
) -> Result<VerifiedLocalModeSnapshot, LocalModeRevalidationFailure> {
    rustix::fs::fcntl_getfl(fd).map_err(|_| LocalModeRevalidationFailure::DescriptorUnavailable)?;
    let statfs =
        rustix::fs::fstatfs(fd).map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    let filesystem_name = statfs
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    let backend = certify_macos_filesystem_name(&filesystem_name)
        .map_err(|_| LocalModeRevalidationFailure::BackendUnavailable)?;
    let stat =
        rustix::fs::fstat(fd).map_err(|_| LocalModeRevalidationFailure::DescriptorUnavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        return Err(LocalModeRevalidationFailure::NotDirectory);
    }
    checked_acl(fd.as_raw_fd())?;
    let mount_id = raw_dev_u64(stat.st_dev).ok_or(LocalModeRevalidationFailure::MountChanged)?;
    Ok(VerifiedLocalModeSnapshot {
        backend,
        mount_id,
        owner_uid: stat.st_uid,
        group_gid: stat.st_gid,
        mode: stat.st_mode as u32 & 0o7777,
        device: raw_dev_u64(stat.st_dev).ok_or(LocalModeRevalidationFailure::IdentityChanged)?,
        inode: stat.st_ino as u64,
        file_type: VerifiedLocalFileType::Directory,
        effective_uid: rustix::process::geteuid().as_raw(),
        effective_groups: current_groups()?,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inspect_held_fd(
    _fd: &OwnedFd,
) -> Result<VerifiedLocalModeSnapshot, LocalModeRevalidationFailure> {
    Err(LocalModeRevalidationFailure::BackendUnavailable)
}

/// Certifies only the local filesystem backend of an already-held object. This
/// does not certify type, ownership, mode, or ACL absence.
#[cfg(target_os = "linux")]
pub fn certify_held_fd_backend<Fd: AsFd>(
    fd: Fd,
) -> Result<CertifiedLocalBackend, CertificationError> {
    use rustix::fs::{AtFlags, StatxFlags};

    let statx = rustix::fs::statx(fd.as_fd(), c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .map_err(|_| CertificationError::MountIdentityUnavailable)?;
    if !StatxFlags::from_bits_retain(statx.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(CertificationError::MountIdentityUnavailable);
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| CertificationError::MountInfoUnreadable)?;
    let statfs =
        rustix::fs::fstatfs(fd.as_fd()).map_err(|_| CertificationError::InspectionFailed)?;
    certify_linux_mount(statx.stx_mnt_id, &mountinfo, statfs.f_type as u64)
}

#[cfg(target_os = "macos")]
pub fn certify_held_fd_backend<Fd: AsFd>(
    fd: Fd,
) -> Result<CertifiedLocalBackend, CertificationError> {
    let statfs =
        rustix::fs::fstatfs(fd.as_fd()).map_err(|_| CertificationError::InspectionFailed)?;
    let filesystem_name = statfs
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    certify_macos_filesystem_name(&filesystem_name)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn certify_held_fd_backend<Fd: AsFd>(
    _fd: Fd,
) -> Result<CertifiedLocalBackend, CertificationError> {
    Err(CertificationError::UnsupportedPlatform)
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
    let mount_id = raw_dev_u64(stat.st_dev).ok_or(CertificationError::InspectionFailed)?;
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
    require_held_fd_acl_absent(&fd)?;
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
        mode_verified: true,
        // Preserve the kernel's raw st_dev value; do not invent a packed
        // major/minor encoding which would disagree with MetadataExt::dev.
        device: raw_dev_u64(stat.st_dev).ok_or(CertificationError::InspectionFailed)?,
        inode: stat.st_ino as u64,
        effective_uid,
        effective_groups,
        seal_lineage: None,
        fd,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclProbe {
    Absent,
    Present,
    Unknown,
}

/// Requires that an already-held object have no access/default POSIX ACL on
/// Linux and no extended ACL on macOS. Probe errors and unsupported platforms
/// are uncertainty and therefore fail closed.
pub fn require_held_fd_acl_absent<Fd: AsFd>(fd: Fd) -> Result<(), CertificationError> {
    require_acl_absent(probe_acl(fd.as_fd().as_raw_fd()))
}

fn require_acl_absent(probe: AclProbe) -> Result<(), CertificationError> {
    match probe {
        AclProbe::Absent => Ok(()),
        AclProbe::Present => Err(CertificationError::AclPresent),
        AclProbe::Unknown => Err(CertificationError::AclProbeUnknown),
    }
}

#[cfg(any(target_os = "linux", test))]
fn combine_acl_probes(probes: &[AclProbe]) -> AclProbe {
    if probes.contains(&AclProbe::Present) {
        AclProbe::Present
    } else if probes.contains(&AclProbe::Unknown) {
        AclProbe::Unknown
    } else {
        AclProbe::Absent
    }
}

#[cfg(target_os = "linux")]
fn probe_acl(fd: RawFd) -> AclProbe {
    combine_acl_probes(&[
        probe_linux_xattr(fd, c"system.posix_acl_access"),
        probe_linux_xattr(fd, c"system.posix_acl_default"),
    ])
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

#[cfg(target_vendor = "apple")]
fn raw_dev_u64(device: i32) -> Option<u64> {
    u64::try_from(device).ok()
}

#[cfg(not(target_vendor = "apple"))]
fn raw_dev_u64(device: u64) -> Option<u64> {
    Some(device)
}

#[cfg(target_vendor = "apple")]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> VerifiedLocalModeSnapshot {
        VerifiedLocalModeSnapshot {
            backend: CertifiedLocalBackend::Ext4,
            mount_id: 7,
            owner_uid: 10,
            group_gid: 20,
            mode: 0o770,
            device: 30,
            inode: 40,
            file_type: VerifiedLocalFileType::Directory,
            effective_uid: 10,
            effective_groups: [20, 21].into_iter().collect(),
        }
    }

    #[test]
    fn snapshot_validation_fails_closed_on_every_authority_field() {
        let expected = snapshot();
        let mut cases = Vec::new();
        let mut changed = expected.clone();
        changed.backend = CertifiedLocalBackend::Xfs;
        cases.push((changed, LocalModeRevalidationFailure::BackendChanged));
        let mut changed = expected.clone();
        changed.mount_id += 1;
        cases.push((changed, LocalModeRevalidationFailure::MountChanged));
        let mut changed = expected.clone();
        changed.device += 1;
        cases.push((changed, LocalModeRevalidationFailure::IdentityChanged));
        let mut changed = expected.clone();
        changed.inode += 1;
        cases.push((changed, LocalModeRevalidationFailure::IdentityChanged));
        let mut changed = expected.clone();
        changed.owner_uid += 1;
        changed.effective_uid = changed.owner_uid;
        cases.push((changed, LocalModeRevalidationFailure::OwnerChanged));
        let mut changed = expected.clone();
        changed.group_gid += 1;
        cases.push((changed, LocalModeRevalidationFailure::GroupChanged));
        let mut changed = expected.clone();
        changed.effective_uid += 1;
        cases.push((changed, LocalModeRevalidationFailure::EffectiveUidChanged));
        let mut changed = expected.clone();
        changed.effective_groups.insert(99);
        cases.push((
            changed,
            LocalModeRevalidationFailure::EffectiveGroupsChanged,
        ));
        let mut changed = expected.clone();
        changed.mode = 0o750;
        cases.push((
            changed,
            LocalModeRevalidationFailure::ModeChanged {
                expected: 0o770,
                actual: 0o750,
            },
        ));

        for (actual, error) in cases {
            assert_eq!(validate_snapshot(&actual, &expected, 0o770), Err(error));
        }
        assert_eq!(validate_snapshot(&expected, &expected, 0o770), Ok(()));
    }

    #[test]
    fn successful_chmod_with_failed_postvalidation_invalidates_cached_mode() {
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
        let mut held = match certify_held_fd(fd) {
            Ok(held) => held,
            Err(CertificationError::UnsupportedFilesystem) => return,
            Err(error) => panic!("unexpected certification failure: {error:?}"),
        };
        let prepared = held.prepare_minimal_seal(false).unwrap();
        let pre = prepared.pre.clone();
        let target = prepared.target_mode;
        assert!(matches!(
            held.finish_successful_chmod(
                target,
                pre,
                Err(LocalModeRevalidationFailure::AclProbeUnknown),
            ),
            HeldModeChangeOutcome::AppliedButUnverified { .. }
        ));
        assert!(!held.mode_is_verified());
        assert!(matches!(
            held.prepare_minimal_seal(false),
            Err(LocalModeRevalidationFailure::EvidenceUnverified)
        ));
    }

    #[test]
    fn wal_uncertainty_invalidates_mode_and_applied_seal_lineage() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
        let fd = std::fs::File::open(&directory).unwrap().into();
        let mut held = match certify_held_fd(fd) {
            Ok(held) => held,
            Err(CertificationError::UnsupportedFilesystem) => return,
            Err(error) => panic!("unexpected certification failure: {error:?}"),
        };
        let prepared = held.prepare_minimal_seal(false).unwrap();
        assert!(matches!(
            held.apply_wal_bound_mode_change(prepared),
            HeldModeChangeOutcome::AppliedVerified { .. }
        ));
        let transaction = TransactionId([41; 16]);
        held.record_applied_seal_lineage(transaction, 7, 0o770, 0o750)
            .unwrap();

        held.invalidate_after_wal_uncertainty();

        assert!(!held.mode_is_verified());
        assert!(matches!(
            held.prepare_minimal_seal(false),
            Err(LocalModeRevalidationFailure::EvidenceUnverified)
        ));
        assert!(matches!(
            held.prepare_wal_bound_restore(transaction, 7, 0o750, 0o770),
            Err(LocalModeRevalidationFailure::EvidenceUnverified)
        ));
    }

    #[test]
    fn held_fd_mode_change_survives_rename_without_touching_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o770)).unwrap();
        let fd = rustix::fs::open(
            &original,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut held = match certify_held_fd(fd) {
            Ok(held) => held,
            Err(CertificationError::UnsupportedFilesystem) => return,
            Err(error) => panic!("unexpected certification failure: {error:?}"),
        };
        let prepared = held.prepare_minimal_seal(false).unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o770)).unwrap();

        assert!(matches!(
            held.apply_wal_bound_mode_change(prepared),
            HeldModeChangeOutcome::AppliedVerified { .. }
        ));
        assert_eq!(held.mode(), 0o750);
        assert_eq!(
            std::fs::metadata(&moved).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&original).unwrap().permissions().mode() & 0o7777,
            0o770
        );
    }

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
    fn acl_probe_combination_is_hermetic_and_fail_closed() {
        assert_eq!(combine_acl_probes(&[AclProbe::Absent]), AclProbe::Absent);
        assert_eq!(
            combine_acl_probes(&[AclProbe::Absent, AclProbe::Unknown]),
            AclProbe::Unknown
        );
        assert_eq!(
            combine_acl_probes(&[AclProbe::Unknown, AclProbe::Present]),
            AclProbe::Present
        );
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
