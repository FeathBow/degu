//! Core-private bounded held-FD traversal and exact rewalk foundation.
//!
//! This deliberately narrow slice performs no chmod, WAL mutation, rename,
//! purge, or deletion. It returns no lifecycle authority token. A future
//! staging coordinator must add a lease-bound mutation seam and derive every
//! durable locator and incarnation from validated staging metadata and held
//! kernel evidence before this module may participate in sealing.

use crate::local_backend::{
    CertificationError, CertifiedLocalBackend, HeldLocalBackendEvidence, certify_held_fd,
};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const HARD_DIRECTORY_CAP: u64 = 1_024;
const MANIFEST_DOMAIN: &[u8] = b"degu-held-tree-manifest-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreeLimits {
    pub max_entries: u64,
    pub max_directories: u64,
    pub max_depth: u32,
    pub max_path_bytes: u64,
    pub max_manifest_bytes: u64,
}

impl Default for HeldTreeLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_directories: 256,
            max_depth: 128,
            max_path_bytes: 16 * 1024 * 1024,
            max_manifest_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeldTreeLimit {
    Entries,
    Directories,
    Depth,
    PathBytes,
    ManifestBytes,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HeldTreeError {
    #[error("held tree root must be exactly one normal component")]
    InvalidRoot,
    #[error("requested directory limit exceeds the hard FD cap")]
    InvalidDirectoryLimit,
    #[error("held tree exceeded its {kind:?} limit of {limit}")]
    Limit { kind: HeldTreeLimit, limit: u64 },
    #[error("source parent does not exclude foreign namespace writers")]
    ParentNotExclusive,
    #[error("entry is not owned by the effective UID at {0}")]
    ForeignOwner(PathBuf),
    #[error("protected name encountered at {0}")]
    ProtectedName(PathBuf),
    #[error("mount or certified backend boundary encountered at {0}")]
    BackendBoundary(PathBuf),
    #[error("entry identity changed at {0}")]
    IdentityChanged(PathBuf),
    #[error("strong kernel incarnation is unavailable at {0}")]
    StrongIncarnationUnavailable(PathBuf),
    #[error("root is not a directory")]
    RootNotDirectory,
    #[error("directory certification failed at {path}: {reason:?}")]
    Certification {
        path: PathBuf,
        reason: CertificationError,
    },
    #[error("post-rewalk tree has an added entry at {0}")]
    PostAdded(PathBuf),
    #[error("post-rewalk tree is missing an entry at {0}")]
    PostRemoved(PathBuf),
    #[error("post-rewalk tree entry changed at {0}")]
    PostChanged(PathBuf),
    #[error("root binding changed")]
    RootBindingChanged,
    #[error("filesystem operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeKind {
    Directory,
    Regular,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    kind: NodeKind,
    device: u64,
    inode: u64,
    incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestEntry {
    path: PathBuf,
    identity: NodeIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Canonical commitment to a bounded complete held-tree inventory. This is
/// evidence only and carries no FD, WAL lease, or mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreeFingerprint {
    pub(crate) entry_count: u64,
    pub(crate) sha256: [u8; 32],
}

/// Data-only ordering for a future recovery coordinator. It carries neither an
/// FD nor WAL/lease/transaction authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldDirectoryOrder {
    pub relative_path: PathBuf,
    pub depth: u32,
    pub device: u64,
    pub inode: u64,
    pub incarnation: u64,
    pub observed_mode: u32,
}

struct HeldDirectory {
    held: HeldLocalBackendEvidence,
    path: PathBuf,
    depth: u32,
    incarnation: u64,
}

/// Private bounded inventory retaining all directory FDs only so that the same
/// objects can be rewalked. This is not rename, purge, or staging authority.
pub(crate) struct HeldTreeInventory {
    parent: HeldLocalBackendEvidence,
    root_name: OsString,
    root_identity: NodeIdentity,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    directories: Vec<HeldDirectory>,
    manifest: Vec<ManifestEntry>,
}

impl HeldTreeInventory {
    /// Accepts the protected policy exactly once and uses it for both walks.
    pub(crate) fn collect(
        parent: HeldLocalBackendEvidence,
        root_name: &OsStr,
        protected_names: Vec<OsString>,
        limits: HeldTreeLimits,
    ) -> Result<Self, HeldTreeError> {
        require_one_component(root_name)?;
        validate_policy(&protected_names)?;
        if limits.max_directories > HARD_DIRECTORY_CAP {
            return Err(HeldTreeError::InvalidDirectoryLimit);
        }
        if protected_names.iter().any(|name| name == root_name) {
            return Err(HeldTreeError::ProtectedName(PathBuf::new()));
        }
        let backend = parent.backend();
        require_exclusive_parent(&parent, backend)?;
        let euid = rustix::process::geteuid().as_raw();
        let root_path = PathBuf::new();
        let inspected = with_fd(&parent, |fd| inspect_at(fd, root_name, &root_path))?;
        if inspected.identity.kind != NodeKind::Directory {
            return Err(HeldTreeError::RootNotDirectory);
        }
        require_owner(&root_path, inspected.uid, euid)?;
        require_boundary(&root_path, backend, parent.mount_id(), &inspected)?;
        let fd = with_fd(&parent, |parent_fd| {
            rustix::fs::openat(parent_fd, root_name, OPEN_DIRECTORY, Mode::empty())
        })
        .map_err(|error| io_error(&root_path, error))?;
        let held = certify_held_fd(fd).map_err(|reason| HeldTreeError::Certification {
            path: root_path.clone(),
            reason,
        })?;
        let opened = inspect_held(&held, &root_path)?;
        require_same_identity(&root_path, inspected.identity, opened.identity)?;
        require_owner(&root_path, opened.uid, euid)?;
        if held.backend() != backend || held.mount_id() != parent.mount_id() {
            return Err(HeldTreeError::BackendBoundary(root_path));
        }
        let root_identity = opened.identity;
        let root_entry = opened.into_manifest(PathBuf::new());
        let mut budget = Budget::new(limits);
        budget.add(&root_entry, 0)?;
        budget.add_directory()?;
        let mut tree = Self {
            parent,
            root_name: root_name.to_os_string(),
            root_identity,
            backend,
            mount_id: held.mount_id(),
            protected_names,
            limits,
            directories: vec![HeldDirectory {
                held,
                path: PathBuf::new(),
                depth: 0,
                incarnation: root_identity.incarnation,
            }],
            manifest: vec![root_entry],
        };
        let mut index = 0;
        while index < tree.directories.len() {
            tree.read_children(index, &mut budget)?;
            index += 1;
        }
        tree.manifest
            .sort_by(|left, right| left.path.cmp(&right.path));
        tree.verify_root_binding()?;
        Ok(tree)
    }

    pub(crate) fn entry_count(&self) -> u64 {
        self.manifest.len() as u64
    }

    /// Hashes the complete, already-sorted manifest using a fixed binary codec.
    /// Raw path bytes and fixed-width big-endian fields avoid display, UTF-8,
    /// serde, native-endian, and map-order ambiguity.
    pub(crate) fn fingerprint(&self) -> HeldTreeFingerprint {
        fingerprint_manifest(&self.manifest)
    }

    pub(crate) fn directories_deepest_first(
        &self,
    ) -> impl Iterator<Item = HeldDirectoryOrder> + '_ {
        self.directories
            .iter()
            .rev()
            .map(|directory| HeldDirectoryOrder {
                relative_path: directory.path.clone(),
                depth: directory.depth,
                device: directory.held.device(),
                inode: directory.held.inode(),
                incarnation: directory.incarnation,
                observed_mode: directory.held.mode(),
            })
    }

    /// Performs a complete second walk under the identical policy and limits.
    /// It only validates; success does not mint any lifecycle token.
    pub(crate) fn rewalk_exact(&self) -> Result<(), HeldTreeError> {
        self.verify_root_binding()?;
        let baseline = self
            .manifest
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut actual = BTreeMap::new();
        let mut budget = Budget::new(self.limits);
        let root =
            inspect_held(&self.directories[0].held, Path::new(""))?.into_manifest(PathBuf::new());
        budget.add(&root, 0)?;
        budget.add_directory()?;
        actual.insert(PathBuf::new(), root);
        for directory in &self.directories {
            require_directory_current(directory, self.backend, self.mount_id)?;
            let fresh = with_fd(&directory.held, |fd| {
                rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
            })
            .map_err(|error| io_error(&directory.path, error))?;
            let entries = Dir::new(fresh).map_err(|error| io_error(&directory.path, error))?;
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&directory.path, error))?;
                if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = OsStr::from_bytes(entry.file_name().to_bytes());
                let path = directory.path.join(name);
                require_unprotected(&self.protected_names, name, &path)?;
                let inspected = with_fd(&directory.held, |fd| inspect_at(fd, name, &path))?;
                require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
                require_boundary(&path, self.backend, self.mount_id, &inspected)?;
                let value = inspected.into_manifest(path.clone());
                budget.add(&value, directory.depth.saturating_add(1))?;
                if value.identity.kind == NodeKind::Directory {
                    budget.add_directory()?;
                }
                if !baseline.contains_key(&path) {
                    return Err(HeldTreeError::PostAdded(path));
                }
                if actual.insert(path.clone(), value).is_some() {
                    return Err(HeldTreeError::PostChanged(path));
                }
            }
        }
        for (path, expected) in baseline {
            let Some(found) = actual.get(&path) else {
                return Err(HeldTreeError::PostRemoved(path));
            };
            if found != expected {
                return Err(HeldTreeError::PostChanged(path));
            }
        }
        self.verify_root_binding()
    }

    fn read_children(&mut self, index: usize, budget: &mut Budget) -> Result<(), HeldTreeError> {
        let parent_path = self.directories[index].path.clone();
        let parent_depth = self.directories[index].depth;
        require_directory_current(&self.directories[index], self.backend, self.mount_id)?;
        let fresh = with_fd(&self.directories[index].held, |fd| {
            rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
        })
        .map_err(|error| io_error(&parent_path, error))?;
        let entries = Dir::new(fresh).map_err(|error| io_error(&parent_path, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&parent_path, error))?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            let path = parent_path.join(name);
            require_unprotected(&self.protected_names, name, &path)?;
            let inspected = with_fd(&self.directories[index].held, |fd| {
                inspect_at(fd, name, &path)
            })?;
            require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
            require_boundary(&path, self.backend, self.mount_id, &inspected)?;
            let depth = parent_depth.saturating_add(1);
            let child = if inspected.identity.kind == NodeKind::Directory {
                let fd = with_fd(&self.directories[index].held, |parent_fd| {
                    rustix::fs::openat(parent_fd, name, OPEN_DIRECTORY, Mode::empty())
                })
                .map_err(|error| io_error(&path, error))?;
                let held = certify_held_fd(fd).map_err(|reason| HeldTreeError::Certification {
                    path: path.clone(),
                    reason,
                })?;
                let opened = inspect_held(&held, &path)?;
                require_same_identity(&path, inspected.identity, opened.identity)?;
                require_owner(&path, opened.uid, rustix::process::geteuid().as_raw())?;
                if held.backend() != self.backend || held.mount_id() != self.mount_id {
                    return Err(HeldTreeError::BackendBoundary(path));
                }
                Some(held)
            } else {
                None
            };
            let manifest = inspected.into_manifest(path.clone());
            budget.add(&manifest, depth)?;
            if child.is_some() {
                budget.add_directory()?;
            }
            let incarnation = manifest.identity.incarnation;
            self.manifest.push(manifest);
            if let Some(held) = child {
                self.directories.push(HeldDirectory {
                    held,
                    path,
                    depth,
                    incarnation,
                });
            }
        }
        Ok(())
    }

    fn verify_root_binding(&self) -> Result<(), HeldTreeError> {
        require_exclusive_parent(&self.parent, self.backend)?;
        let inspected = with_fd(&self.parent, |fd| {
            inspect_at(fd, &self.root_name, Path::new(""))
        })
        .map_err(|_| HeldTreeError::RootBindingChanged)?;
        if root_binding_matches(self.root_identity, self.mount_id, self.backend, &inspected) {
            Ok(())
        } else {
            Err(HeldTreeError::RootBindingChanged)
        }
    }
}

#[derive(Clone, Debug)]
struct Inspection {
    identity: NodeIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
    mount_id: u64,
    backend: CertifiedLocalBackend,
}

impl Inspection {
    fn into_manifest(self, path: PathBuf) -> ManifestEntry {
        ManifestEntry {
            path,
            identity: self.identity,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
        }
    }
}

fn with_fd<R>(
    held: &HeldLocalBackendEvidence,
    operation: impl FnOnce(rustix::fd::BorrowedFd<'_>) -> R,
) -> R {
    held.with_authority_fd(operation)
}

#[cfg(target_os = "linux")]
fn inspect_held(held: &HeldLocalBackendEvidence, path: &Path) -> Result<Inspection, HeldTreeError> {
    use rustix::fs::{StatxFlags, statx};
    let requested = StatxFlags::BASIC_STATS | StatxFlags::BTIME | StatxFlags::MNT_ID;
    let stat = with_fd(held, |fd| statx(fd, c"", AtFlags::EMPTY_PATH, requested))
        .map_err(|error| io_error(path, error))?;
    inspection_from_linux_statx(stat, held.backend(), path)
}

#[cfg(target_os = "linux")]
fn inspect_at(
    parent: rustix::fd::BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    use rustix::fs::{StatxFlags, statx};
    let c_name = CString::new(name.as_bytes()).map_err(|_| HeldTreeError::InvalidRoot)?;
    let requested = StatxFlags::BASIC_STATS | StatxFlags::BTIME | StatxFlags::MNT_ID;
    let stat = statx(
        parent,
        c_name.as_c_str(),
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        requested,
    )
    .map_err(|error| io_error(path, error))?;
    let backend = crate::local_backend::certify_held_fd_backend(parent).map_err(|reason| {
        HeldTreeError::Certification {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    inspection_from_linux_statx(stat, backend, path)
}

#[cfg(target_os = "linux")]
fn inspection_from_linux_statx(
    stat: rustix::fs::Statx,
    backend: CertifiedLocalBackend,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    use rustix::fs::StatxFlags;
    let present = StatxFlags::from_bits_retain(stat.stx_mask);
    if !present.contains(
        StatxFlags::TYPE
            | StatxFlags::INO
            | StatxFlags::UID
            | StatxFlags::GID
            | StatxFlags::MODE
            | StatxFlags::BTIME
            | StatxFlags::MNT_ID,
    ) {
        return Err(HeldTreeError::StrongIncarnationUnavailable(
            path.to_path_buf(),
        ));
    }
    Ok(Inspection {
        identity: NodeIdentity {
            kind: node_kind(FileType::from_raw_mode(stat.stx_mode as _)),
            device: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor) as u64,
            inode: stat.stx_ino,
            incarnation: incarnation_from_timestamp(
                stat.stx_btime.tv_sec,
                stat.stx_btime.tv_nsec,
                path,
            )?,
        },
        uid: stat.stx_uid,
        gid: stat.stx_gid,
        mode: u32::from(stat.stx_mode) & 0o7777,
        mount_id: stat.stx_mnt_id,
        backend,
    })
}

#[cfg(target_os = "macos")]
fn inspect_held(held: &HeldLocalBackendEvidence, path: &Path) -> Result<Inspection, HeldTreeError> {
    let stat = with_fd(held, |fd| rustix::fs::fstat(fd)).map_err(|error| io_error(path, error))?;
    inspection_from_macos_stat(stat, held.backend(), path)
}

#[cfg(target_os = "macos")]
fn inspect_at(
    parent: rustix::fd::BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    let c_name = CString::new(name.as_bytes()).map_err(|_| HeldTreeError::InvalidRoot)?;
    let stat = rustix::fs::statat(parent, c_name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(path, error))?;
    let backend = crate::local_backend::certify_held_fd_backend(parent).map_err(|reason| {
        HeldTreeError::Certification {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    inspection_from_macos_stat(stat, backend, path)
}

#[cfg(target_os = "macos")]
fn inspection_from_macos_stat(
    stat: rustix::fs::Stat,
    backend: CertifiedLocalBackend,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    let nanos = u32::try_from(stat.st_birthtime_nsec)
        .map_err(|_| HeldTreeError::StrongIncarnationUnavailable(path.to_path_buf()))?;
    let device = u64::try_from(stat.st_dev)
        .map_err(|_| HeldTreeError::StrongIncarnationUnavailable(path.to_path_buf()))?;
    Ok(Inspection {
        identity: NodeIdentity {
            kind: node_kind(FileType::from_raw_mode(stat.st_mode)),
            device,
            inode: stat.st_ino,
            incarnation: incarnation_from_timestamp(stat.st_birthtime, nanos, path)?,
        },
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode as u32 & 0o7777,
        mount_id: device,
        backend,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inspect_held(
    _held: &HeldLocalBackendEvidence,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    Err(HeldTreeError::StrongIncarnationUnavailable(
        path.to_path_buf(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inspect_at(
    _parent: rustix::fd::BorrowedFd<'_>,
    _name: &OsStr,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    Err(HeldTreeError::StrongIncarnationUnavailable(
        path.to_path_buf(),
    ))
}

fn incarnation_from_timestamp(seconds: i64, nanos: u32, path: &Path) -> Result<u64, HeldTreeError> {
    if nanos >= 1_000_000_000 {
        return Err(HeldTreeError::StrongIncarnationUnavailable(
            path.to_path_buf(),
        ));
    }
    u64::try_from(seconds)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000_000))
        .and_then(|value| value.checked_add(u64::from(nanos)))
        .ok_or_else(|| HeldTreeError::StrongIncarnationUnavailable(path.to_path_buf()))
}

fn node_kind(kind: FileType) -> NodeKind {
    match kind {
        FileType::Directory => NodeKind::Directory,
        FileType::RegularFile => NodeKind::Regular,
        FileType::Symlink => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

fn root_binding_matches(
    identity: NodeIdentity,
    mount_id: u64,
    backend: CertifiedLocalBackend,
    actual: &Inspection,
) -> bool {
    actual.identity == identity && actual.mount_id == mount_id && actual.backend == backend
}

fn require_boundary(
    path: &Path,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    inspected: &Inspection,
) -> Result<(), HeldTreeError> {
    if inspected.backend == backend && inspected.mount_id == mount_id {
        Ok(())
    } else {
        Err(HeldTreeError::BackendBoundary(path.to_path_buf()))
    }
}

fn require_owner(path: &Path, actual: u32, expected: u32) -> Result<(), HeldTreeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(HeldTreeError::ForeignOwner(path.to_path_buf()))
    }
}

fn require_same_identity(
    path: &Path,
    expected: NodeIdentity,
    actual: NodeIdentity,
) -> Result<(), HeldTreeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(HeldTreeError::IdentityChanged(path.to_path_buf()))
    }
}

fn grants_namespace_write(mode: u32) -> bool {
    mode & 0o030 == 0o030 || mode & 0o003 == 0o003
}

fn require_exclusive_parent(
    parent: &HeldLocalBackendEvidence,
    backend: CertifiedLocalBackend,
) -> Result<(), HeldTreeError> {
    with_fd(parent, |fd| {
        crate::local_backend::require_held_fd_acl_absent(fd)
    })
    .map_err(|reason| HeldTreeError::Certification {
        path: PathBuf::new(),
        reason,
    })?;
    let stat = with_fd(parent, |fd| rustix::fs::fstat(fd))
        .map_err(|error| io_error(Path::new(""), error))?;
    let actual_backend = with_fd(parent, |fd| {
        crate::local_backend::certify_held_fd_backend(fd)
    })
    .map_err(|reason| HeldTreeError::Certification {
        path: PathBuf::new(),
        reason,
    })?;
    if parent.backend() != backend
        || actual_backend != backend
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || grants_namespace_write(super::raw_mode_u32(stat.st_mode) & 0o7777)
    {
        Err(HeldTreeError::ParentNotExclusive)
    } else {
        Ok(())
    }
}

fn require_directory_current(
    directory: &HeldDirectory,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<(), HeldTreeError> {
    with_fd(&directory.held, |fd| {
        crate::local_backend::require_held_fd_acl_absent(fd)
    })
    .map_err(|reason| HeldTreeError::Certification {
        path: directory.path.clone(),
        reason,
    })?;
    let inspected = inspect_held(&directory.held, &directory.path)?;
    require_owner(
        &directory.path,
        inspected.uid,
        rustix::process::geteuid().as_raw(),
    )?;
    require_boundary(&directory.path, backend, mount_id, &inspected)
}

fn require_unprotected(
    policy: &[OsString],
    name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    if policy.iter().any(|protected| protected == name) {
        Err(HeldTreeError::ProtectedName(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn validate_policy(policy: &[OsString]) -> Result<(), HeldTreeError> {
    for name in policy {
        require_one_component(name)?;
    }
    Ok(())
}

fn require_one_component(name: &OsStr) -> Result<(), HeldTreeError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == name => Ok(()),
        _ => Err(HeldTreeError::InvalidRoot),
    }
}

fn fingerprint_manifest(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    let mut digest = Sha256::new();
    digest.update(MANIFEST_DOMAIN);
    digest.update((manifest.len() as u64).to_be_bytes());
    for entry in manifest {
        let path = entry.path.as_os_str().as_bytes();
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path);
        digest.update([match entry.identity.kind {
            NodeKind::Directory => 0,
            NodeKind::Regular => 1,
            NodeKind::Symlink => 2,
            NodeKind::Other => 3,
        }]);
        digest.update(entry.identity.device.to_be_bytes());
        digest.update(entry.identity.inode.to_be_bytes());
        digest.update(entry.identity.incarnation.to_be_bytes());
        digest.update(entry.uid.to_be_bytes());
        digest.update(entry.gid.to_be_bytes());
        digest.update(entry.mode.to_be_bytes());
    }
    HeldTreeFingerprint {
        entry_count: manifest.len() as u64,
        sha256: digest.finalize().into(),
    }
}

struct Budget {
    limits: HeldTreeLimits,
    entries: u64,
    directories: u64,
    path_bytes: u64,
    manifest_bytes: u64,
}

impl Budget {
    fn new(limits: HeldTreeLimits) -> Self {
        Self {
            limits,
            entries: 0,
            directories: 0,
            path_bytes: 0,
            manifest_bytes: 0,
        }
    }

    fn add(&mut self, entry: &ManifestEntry, depth: u32) -> Result<(), HeldTreeError> {
        let path_len = entry.path.as_os_str().as_bytes().len() as u64;
        self.entries = self.entries.saturating_add(1);
        self.path_bytes = self.path_bytes.saturating_add(path_len);
        self.manifest_bytes = self
            .manifest_bytes
            .saturating_add(std::mem::size_of::<ManifestEntry>() as u64)
            .saturating_add(path_len);
        check(
            self.entries,
            self.limits.max_entries,
            HeldTreeLimit::Entries,
        )?;
        check(
            depth as u64,
            self.limits.max_depth as u64,
            HeldTreeLimit::Depth,
        )?;
        check(
            self.path_bytes,
            self.limits.max_path_bytes,
            HeldTreeLimit::PathBytes,
        )?;
        check(
            self.manifest_bytes,
            self.limits.max_manifest_bytes,
            HeldTreeLimit::ManifestBytes,
        )
    }

    fn add_directory(&mut self) -> Result<(), HeldTreeError> {
        self.directories = self.directories.saturating_add(1);
        check(
            self.directories,
            self.limits.max_directories,
            HeldTreeLimit::Directories,
        )
    }
}

fn check(value: u64, limit: u64, kind: HeldTreeLimit) -> Result<(), HeldTreeError> {
    if value <= limit {
        Ok(())
    } else {
        Err(HeldTreeError::Limit { kind, limit })
    }
}

fn io_error(path: &Path, error: impl Into<io::Error>) -> HeldTreeError {
    HeldTreeError::Io {
        path: path.to_path_buf(),
        source: error.into(),
    }
}

#[cfg(test)]
mod tests;
