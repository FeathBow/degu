//! Core-private bounded held-FD traversal, sealing, and exact rewalk foundation.
//!
//! Collection and rewalk are authority-neutral. A3c2 adds one narrow method that
//! can apply minimal directory seals only when given an exact leased staging WAL
//! and descriptor-derived incarnations. This module performs no rename, restore,
//! purge, unlink, or deletion and returns no lifecycle authority token.

use crate::local_backend::{
    CertificationError, CertifiedLocalBackend, HeldLocalBackendEvidence, certify_held_fd,
};
use crate::seal_executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeMutationResult, LocalModeTransform,
    RecoveryLocator, execute_staging_local_mode_mutation,
};
use crate::seal_wal::{DurableWrite, SealWal, StrongObjectIdentity, TransactionId};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const HARD_DIRECTORY_CAP: u64 = 1_024;
const MANIFEST_DOMAIN_V1: &[u8] = b"degu-held-tree-manifest-v1\0";
const MANIFEST_DOMAIN_V2: &[u8] = b"degu-held-tree-manifest-v2-content\0";
const CONTENT_PROOF_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreeLimits {
    pub max_entries: u64,
    pub max_directories: u64,
    pub max_depth: u32,
    pub max_path_bytes: u64,
    pub max_manifest_bytes: u64,
    /// Maximum aggregate regular-file bytes read through held no-follow FDs.
    pub max_content_bytes: u64,
}

impl Default for HeldTreeLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_directories: 256,
            max_depth: 128,
            max_path_bytes: 16 * 1024 * 1024,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_content_bytes: 1024 * 1024 * 1024,
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
    ContentBytes,
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
    #[error("regular file has an external hard link at {0}")]
    ExternalHardLink(PathBuf),
    #[error("non-directory ACL, xattr, or capability is present or cannot be proven absent at {0}")]
    NonDirectoryExtendedMetadata(PathBuf),
    #[error("non-directory content proof is unsupported at {0}")]
    UnsupportedContentProof(PathBuf),
    #[error("entry changed while its content was hashed at {0}")]
    ContentChangedDuringHash(PathBuf),
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum HeldTreeSealError {
    #[error("tree seal mutation id space is exhausted")]
    MutationIdExhausted,
    #[error("held tree seal failed at {path}: {source}")]
    Mutation {
        path: PathBuf,
        #[source]
        source: LocalModeExecutionError,
    },
    #[error("held tree seal was durably confirmed not applied at {0}")]
    ConfirmedNotApplied(PathBuf),
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
    content: ContentProof,
}

/// Mirrors the exact pre-v2 in-memory accounting shape. This is used only for
/// the historical manifest byte budget; it is never instantiated or persisted.
struct LegacyManifestEntryAccounting {
    path: PathBuf,
    identity: NodeIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContentProof {
    /// Schema-v1 inventory deliberately does not inspect non-directory content.
    /// The variant is also used for directories so exact legacy rewalks compare
    /// only the fields committed by the historical manifest.
    Legacy,
    Directory,
    Regular {
        size: u64,
        nlink: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        ctime_sec: i64,
        ctime_nsec: u32,
        sha256: [u8; 32],
    },
    Symlink {
        target: Vec<u8>,
    },
}

/// Canonical commitment to a bounded complete held-tree inventory. This is
/// evidence only and carries no FD, WAL lease, or mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreeFingerprint {
    pub(crate) schema_version: u16,
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

/// Private bounded inventory retaining all directory FDs for exact rewalk and
/// lease-bound minimal sealing. By itself it carries no WAL lease and is not
/// rename, restore, purge, or deletion authority.
pub(crate) struct HeldTreeInventory {
    parent: HeldLocalBackendEvidence,
    root_name: OsString,
    root_identity: NodeIdentity,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    manifest_schema: u16,
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
        Self::collect_for_schema(
            parent,
            root_name,
            protected_names,
            limits,
            CONTENT_PROOF_VERSION,
        )
    }

    /// Collects only the evidence committed by the requested durable schema.
    /// Schema 1 preserves historical recovery semantics and never reads file
    /// content or imposes v2 hardlink/xattr/content-budget constraints.
    pub(crate) fn collect_for_schema(
        parent: HeldLocalBackendEvidence,
        root_name: &OsStr,
        protected_names: Vec<OsString>,
        limits: HeldTreeLimits,
        manifest_schema: u16,
    ) -> Result<Self, HeldTreeError> {
        if !matches!(manifest_schema, 1 | CONTENT_PROOF_VERSION) {
            return Err(HeldTreeError::UnsupportedContentProof(PathBuf::new()));
        }
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
        let root_content = if manifest_schema == CONTENT_PROOF_VERSION {
            ContentProof::Directory
        } else {
            ContentProof::Legacy
        };
        let root_entry = opened.into_manifest(PathBuf::new(), root_content);
        let mut budget = Budget::new(limits, manifest_schema);
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
            manifest_schema,
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
        debug_assert_eq!(self.manifest_schema, CONTENT_PROOF_VERSION);
        fingerprint_manifest_v2(&self.manifest)
    }

    pub(crate) fn fingerprint_for_schema(
        &self,
        schema_version: u16,
    ) -> Option<HeldTreeFingerprint> {
        if schema_version != self.manifest_schema {
            return None;
        }
        match schema_version {
            1 => Some(fingerprint_manifest_v1(&self.manifest)),
            CONTENT_PROOF_VERSION => Some(fingerprint_manifest_v2(&self.manifest)),
            _ => None,
        }
    }

    /// Recomputes the complete manifest after substituting directory modes.
    /// Verified undo uses this after applying durable inverses: normalizing each
    /// directory back to its sealed mode proves that no content, identity,
    /// ownership, type, or non-directory mode drift occurred while modes were
    /// restored at the staged name.
    pub(crate) fn fingerprint_with_directory_modes(
        &self,
        modes: &std::collections::BTreeMap<PathBuf, u32>,
    ) -> Result<HeldTreeFingerprint, HeldTreeError> {
        let mut manifest = self.manifest.clone();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &mut manifest {
            if entry.identity.kind == NodeKind::Directory {
                let mode = modes
                    .get(&entry.path)
                    .copied()
                    .ok_or_else(|| HeldTreeError::IdentityChanged(entry.path.clone()))?;
                entry.mode = mode;
                seen.insert(entry.path.clone());
            }
        }
        if seen.len() != modes.len() {
            return Err(HeldTreeError::IdentityChanged(PathBuf::new()));
        }
        Ok(fingerprint_manifest_v2(&manifest))
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

    pub(crate) fn root_strong_identity(&self) -> StrongObjectIdentity {
        StrongObjectIdentity::new_with_mount(
            self.root_identity.device,
            self.root_identity.inode,
            crate::seal_wal::ObjectIncarnation::new(self.root_identity.incarnation),
            self.mount_id,
        )
    }

    /// Applies only the fixed minimal directory seals represented by this exact
    /// inventory. Every mutation is held-FD-only and bound to the leased staging
    /// WAL with the directory's strong incarnation.
    pub(crate) fn seal_directories_for_staging<W: DurableWrite>(
        &mut self,
        wal: &mut SealWal<W>,
        transaction: TransactionId,
        source_root: &Path,
        filesystem_id: &str,
        first_mutation_id: u64,
    ) -> Result<u64, HeldTreeSealError> {
        let mut mutation_id = first_mutation_id;
        for directory in self.directories.iter_mut().rev() {
            let relative_path = source_root.join(&directory.path);
            let result = execute_staging_local_mode_mutation(
                wal,
                &mut directory.held,
                LocalModeMutationRequest {
                    transaction,
                    mutation_id,
                    locator: RecoveryLocator::held_staging(
                        relative_path,
                        filesystem_id.to_owned(),
                        directory.incarnation,
                    ),
                    transform: LocalModeTransform::Seal {
                        acquire_owner_write_search: false,
                    },
                },
            )
            .map_err(|source| HeldTreeSealError::Mutation {
                path: directory.path.clone(),
                source,
            })?;
            if result == LocalModeMutationResult::ConfirmedNotApplied {
                return Err(HeldTreeSealError::ConfirmedNotApplied(
                    directory.path.clone(),
                ));
            }
            mutation_id = mutation_id
                .checked_add(1)
                .ok_or(HeldTreeSealError::MutationIdExhausted)?;
        }
        Ok(mutation_id)
    }

    /// Proves that a fresh post-seal inventory names the same objects and only
    /// changes directory modes to the exact modes held by this inventory.
    pub(crate) fn verify_post_seal_snapshot(
        &self,
        post: &HeldTreeInventory,
    ) -> Result<(), HeldTreeError> {
        if self.backend != post.backend
            || self.mount_id != post.mount_id
            || self.root_identity != post.root_identity
            || self.manifest.len() != post.manifest.len()
        {
            return Err(HeldTreeError::RootBindingChanged);
        }
        let sealed_modes = self
            .directories
            .iter()
            .map(|directory| (directory.path.as_path(), directory.held.mode()))
            .collect::<BTreeMap<_, _>>();
        for (before, after) in self.manifest.iter().zip(&post.manifest) {
            if before.path != after.path
                || before.identity != after.identity
                || before.uid != after.uid
                || before.gid != after.gid
                || before.content != after.content
            {
                return Err(HeldTreeError::PostChanged(after.path.clone()));
            }
            let expected_mode = if before.identity.kind == NodeKind::Directory {
                *sealed_modes
                    .get(before.path.as_path())
                    .ok_or_else(|| HeldTreeError::PostChanged(before.path.clone()))?
            } else {
                before.mode
            };
            if after.mode != expected_mode {
                return Err(HeldTreeError::PostChanged(after.path.clone()));
            }
        }
        Ok(())
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
        let mut budget = Budget::new(self.limits, self.manifest_schema);
        let root_content = if self.manifest_schema == CONTENT_PROOF_VERSION {
            ContentProof::Directory
        } else {
            ContentProof::Legacy
        };
        let root = inspect_held(&self.directories[0].held, Path::new(""))?
            .into_manifest(PathBuf::new(), root_content);
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
                let content = inspect_content_for_schema(
                    self.manifest_schema,
                    &directory.held,
                    name,
                    &path,
                    &inspected,
                    &mut budget,
                )?;
                let value = inspected.into_manifest(path.clone(), content);
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
            let content = inspect_content_for_schema(
                self.manifest_schema,
                &self.directories[index].held,
                name,
                &path,
                &inspected,
                budget,
            )?;
            let manifest = inspected.into_manifest(path.clone(), content);
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
    size: u64,
    nlink: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
    content_fields_available: bool,
    mount_id: u64,
    backend: CertifiedLocalBackend,
}

impl Inspection {
    fn into_manifest(self, path: PathBuf, content: ContentProof) -> ManifestEntry {
        ManifestEntry {
            path,
            identity: self.identity,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            content,
        }
    }

    fn stable_content_fields_equal(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.uid == other.uid
            && self.gid == other.gid
            && self.mode == other.mode
            && self.size == other.size
            && self.nlink == other.nlink
            && self.mtime_sec == other.mtime_sec
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime_sec == other.ctime_sec
            && self.ctime_nsec == other.ctime_nsec
            && self.content_fields_available == other.content_fields_available
            && self.mount_id == other.mount_id
            && self.backend == other.backend
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
    let content_fields =
        StatxFlags::SIZE | StatxFlags::NLINK | StatxFlags::MTIME | StatxFlags::CTIME;
    let content_fields_available = present.contains(content_fields);
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
        size: stat.stx_size,
        nlink: u64::from(stat.stx_nlink),
        mtime_sec: stat.stx_mtime.tv_sec,
        mtime_nsec: stat.stx_mtime.tv_nsec,
        ctime_sec: stat.stx_ctime.tv_sec,
        ctime_nsec: stat.stx_ctime.tv_nsec,
        content_fields_available,
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
        size: u64::try_from(stat.st_size)
            .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?,
        nlink: u64::from(stat.st_nlink),
        mtime_sec: stat.st_mtime,
        mtime_nsec: u32::try_from(stat.st_mtime_nsec)
            .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?,
        ctime_sec: stat.st_ctime,
        ctime_nsec: u32::try_from(stat.st_ctime_nsec)
            .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?,
        content_fields_available: true,
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

fn inspect_content_for_schema(
    schema_version: u16,
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<ContentProof, HeldTreeError> {
    match schema_version {
        1 => Ok(ContentProof::Legacy),
        CONTENT_PROOF_VERSION => inspect_content_at(parent, name, path, before, budget),
        _ => Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf())),
    }
}

fn inspect_content_at(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<ContentProof, HeldTreeError> {
    if !before.content_fields_available {
        return Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()));
    }
    match before.identity.kind {
        NodeKind::Directory => Ok(ContentProof::Directory),
        NodeKind::Regular => inspect_regular_content(parent, name, path, before, budget),
        NodeKind::Symlink => inspect_symlink_content(parent, name, path, before, budget),
        NodeKind::Other => Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf())),
    }
}

fn inspect_regular_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<ContentProof, HeldTreeError> {
    if before.nlink != 1 {
        return Err(HeldTreeError::ExternalHardLink(path.to_path_buf()));
    }
    budget.add_content(before.size)?;
    let fd = with_fd(parent, |parent_fd| {
        rustix::fs::openat(
            parent_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })
    .map_err(|error| io_error(path, error))?;
    require_fd_extended_metadata_absent(&fd, path)?;
    crate::local_backend::require_held_fd_acl_absent(&fd)
        .map_err(|_| HeldTreeError::NonDirectoryExtendedMetadata(path.to_path_buf()))?;
    let opened = inspect_raw_fd(&fd, parent.backend(), path)?;
    if !before.stable_content_fields_equal(&opened) || opened.identity.kind != NodeKind::Regular {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }

    let mut file = std::fs::File::from(fd);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(path.to_path_buf()))?;
        if total > before.size {
            return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
        }
        digest.update(&buffer[..read]);
    }
    let after = inspect_raw_fd(&file, parent.backend(), path)?;
    require_fd_extended_metadata_absent(&file, path)?;
    let final_inspection = inspect_raw_fd(&file, parent.backend(), path)?;
    if total != before.size
        || !before.stable_content_fields_equal(&after)
        || !opened.stable_content_fields_equal(&after)
        || !after.stable_content_fields_equal(&final_inspection)
        || after.nlink != 1
    {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(ContentProof::Regular {
        size: after.size,
        nlink: after.nlink,
        mtime_sec: after.mtime_sec,
        mtime_nsec: after.mtime_nsec,
        ctime_sec: after.ctime_sec,
        ctime_nsec: after.ctime_nsec,
        sha256: digest.finalize().into(),
    })
}

fn inspect_symlink_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<ContentProof, HeldTreeError> {
    require_symlink_extended_metadata_absent(parent, name, path)?;
    let target = with_fd(parent, |fd| rustix::fs::readlinkat(fd, name, Vec::new()))
        .map_err(|error| io_error(path, error))?
        .into_bytes();
    budget.add_content(target.len() as u64)?;
    let middle = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    require_symlink_extended_metadata_absent(parent, name, path)?;
    let target_again = with_fd(parent, |fd| rustix::fs::readlinkat(fd, name, Vec::new()))
        .map_err(|error| io_error(path, error))?
        .into_bytes();
    let after = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    require_symlink_extended_metadata_absent(parent, name, path)?;
    let final_inspection = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    if !before.stable_content_fields_equal(&middle)
        || !before.stable_content_fields_equal(&after)
        || !after.stable_content_fields_equal(&final_inspection)
        || target != target_again
    {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(ContentProof::Symlink { target })
}

#[cfg(target_os = "linux")]
fn inspect_raw_fd<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    backend: CertifiedLocalBackend,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    use rustix::fs::{StatxFlags, statx};
    let requested = StatxFlags::BASIC_STATS | StatxFlags::BTIME | StatxFlags::MNT_ID;
    let stat =
        statx(fd, c"", AtFlags::EMPTY_PATH, requested).map_err(|error| io_error(path, error))?;
    inspection_from_linux_statx(stat, backend, path)
}

#[cfg(target_os = "macos")]
fn inspect_raw_fd<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    backend: CertifiedLocalBackend,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    let stat = rustix::fs::fstat(fd).map_err(|error| io_error(path, error))?;
    inspection_from_macos_stat(stat, backend, path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inspect_raw_fd<Fd: rustix::fd::AsFd>(
    _fd: &Fd,
    _backend: CertifiedLocalBackend,
    path: &Path,
) -> Result<Inspection, HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
}

#[cfg(target_os = "linux")]
fn require_fd_extended_metadata_absent<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
) -> Result<(), HeldTreeError> {
    // SAFETY: the borrowed descriptor remains live and no output buffer is supplied.
    let result = unsafe { libc::flistxattr(fd.as_fd().as_raw_fd(), std::ptr::null_mut(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(HeldTreeError::NonDirectoryExtendedMetadata(
            path.to_path_buf(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn require_fd_extended_metadata_absent<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
) -> Result<(), HeldTreeError> {
    // SAFETY: the borrowed descriptor remains live and no output buffer is supplied.
    let result = unsafe { libc::flistxattr(fd.as_fd().as_raw_fd(), std::ptr::null_mut(), 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(HeldTreeError::NonDirectoryExtendedMetadata(
            path.to_path_buf(),
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn require_fd_extended_metadata_absent<Fd: rustix::fd::AsFd>(
    _fd: &Fd,
    path: &Path,
) -> Result<(), HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
}

#[cfg(target_os = "linux")]
fn require_symlink_extended_metadata_absent(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?;
    let proc_path = with_fd(parent, |fd| {
        let mut bytes = format!("/proc/self/fd/{}/", fd.as_raw_fd()).into_bytes();
        bytes.extend_from_slice(name.as_bytes());
        CString::new(bytes)
    })
    .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?;
    // SAFETY: the NUL-terminated path remains live and no output buffer is supplied.
    let result = unsafe { libc::llistxattr(proc_path.as_ptr(), std::ptr::null_mut(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(HeldTreeError::NonDirectoryExtendedMetadata(
            path.to_path_buf(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn require_symlink_extended_metadata_absent(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    use std::os::fd::FromRawFd;
    let name = CString::new(name.as_bytes())
        .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?;
    let raw = with_fd(parent, |fd| {
        // SAFETY: parent/name remain live; macOS O_SYMLINK opens the link
        // itself rather than following it to the target.
        unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
            )
        }
    });
    if raw < 0 {
        return Err(HeldTreeError::NonDirectoryExtendedMetadata(
            path.to_path_buf(),
        ));
    }
    // SAFETY: openat returned a new uniquely-owned descriptor.
    let fd = unsafe { rustix::fd::OwnedFd::from_raw_fd(raw) };
    require_fd_extended_metadata_absent(&fd, path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn require_symlink_extended_metadata_absent(
    _parent: &HeldLocalBackendEvidence,
    _name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
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

fn fingerprint_manifest_v1(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    fingerprint_manifest(manifest, 1, false)
}

fn fingerprint_manifest_v2(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    fingerprint_manifest(manifest, CONTENT_PROOF_VERSION, true)
}

fn fingerprint_manifest(
    manifest: &[ManifestEntry],
    schema_version: u16,
    include_content: bool,
) -> HeldTreeFingerprint {
    let mut digest = Sha256::new();
    digest.update(if include_content {
        MANIFEST_DOMAIN_V2
    } else {
        MANIFEST_DOMAIN_V1
    });
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
        if include_content {
            match &entry.content {
                ContentProof::Legacy => {
                    debug_assert!(false, "v2 fingerprint requires content proof");
                    digest.update([0xff]);
                }
                ContentProof::Directory => digest.update([0]),
                ContentProof::Regular {
                    size,
                    nlink,
                    mtime_sec,
                    mtime_nsec,
                    ctime_sec,
                    ctime_nsec,
                    sha256,
                } => {
                    digest.update([1]);
                    digest.update(size.to_be_bytes());
                    digest.update(nlink.to_be_bytes());
                    digest.update(mtime_sec.to_be_bytes());
                    digest.update(mtime_nsec.to_be_bytes());
                    digest.update(ctime_sec.to_be_bytes());
                    digest.update(ctime_nsec.to_be_bytes());
                    digest.update(sha256);
                }
                ContentProof::Symlink { target } => {
                    digest.update([2]);
                    digest.update((target.len() as u64).to_be_bytes());
                    digest.update(target);
                }
            }
        }
    }
    HeldTreeFingerprint {
        schema_version,
        entry_count: manifest.len() as u64,
        sha256: digest.finalize().into(),
    }
}

struct Budget {
    limits: HeldTreeLimits,
    manifest_entry_bytes: u64,
    entries: u64,
    directories: u64,
    path_bytes: u64,
    manifest_bytes: u64,
    content_bytes: u64,
}

impl Budget {
    fn new(limits: HeldTreeLimits, manifest_schema: u16) -> Self {
        let manifest_entry_bytes = if manifest_schema == 1 {
            std::mem::size_of::<LegacyManifestEntryAccounting>() as u64
        } else {
            std::mem::size_of::<ManifestEntry>() as u64
        };
        Self {
            limits,
            manifest_entry_bytes,
            entries: 0,
            directories: 0,
            path_bytes: 0,
            manifest_bytes: 0,
            content_bytes: 0,
        }
    }

    fn add(&mut self, entry: &ManifestEntry, depth: u32) -> Result<(), HeldTreeError> {
        let path_len = entry.path.as_os_str().as_bytes().len() as u64;
        self.entries = self.entries.saturating_add(1);
        self.path_bytes = self.path_bytes.saturating_add(path_len);
        self.manifest_bytes = self
            .manifest_bytes
            .saturating_add(self.manifest_entry_bytes)
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

    fn add_content(&mut self, bytes: u64) -> Result<(), HeldTreeError> {
        self.content_bytes = self.content_bytes.saturating_add(bytes);
        check(
            self.content_bytes,
            self.limits.max_content_bytes,
            HeldTreeLimit::ContentBytes,
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
