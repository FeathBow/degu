//! Core-private bounded held-FD traversal, sealing, and exact rewalk.
//!
//! Collection and rewalk are authority-neutral. One narrow method can apply
//! minimal directory seals only when given an exact leased staging WAL
//! and descriptor-derived incarnations. This module performs no rename, restore,
//! purge, unlink, or deletion and returns no lifecycle authority token.

use crate::admission::{
    Admission, EntryFacts, EntryKind, Evidence, LinkCount, RejectReason, XattrPlatform, Xattrs,
    assess_content,
};
use crate::authority::mode::{
    ModeSealAssessment, ModeSealDenial, assess_mode_seal, minimal_sealed_mode,
};
use crate::backend::{
    CertificationError, CertifiedLocalBackend, HeldLocalBackendEvidence, certify_held_fd,
};
use crate::seal::executor::{
    LocalModeExecutionError, LocalModeMutationRequest, LocalModeMutationResult, LocalModeTransform,
    RecoveryLocator, execute_staging_local_mode_mutation,
};
use crate::seal::wal::{DurableWrite, SealWal, StrongObjectIdentity, TransactionId};
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
/// A transient EINTR is retried, but every namespace operation remains bounded.
const PURGE_IO_ATTEMPTS: usize = 3;
/// Xattr name enumeration is diagnostic policy input only. Any oversized,
/// unstable, malformed, or unreadable list remains the same fail-closed result.
const XATTR_LIST_ATTEMPTS: usize = 3;
const MAX_XATTR_NAME_LIST_BYTES: usize = 64 * 1024;
const MAX_XATTR_NAMES: usize = 1_024;
#[cfg(test)]
std::thread_local! {
    pub(crate) static PURGE_FAIL_AFTER_REMOVALS: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    pub(crate) static PURGE_FAIL_PARENT_FSYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

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

#[derive(Debug)]
pub(crate) enum HeldTreePurgeError<E> {
    Tree(HeldTreeError),
    Journal(E),
}

impl<E> From<HeldTreeError> for HeldTreePurgeError<E> {
    fn from(error: HeldTreeError) -> Self {
        Self::Tree(error)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HeldTreeError {
    #[error("held tree root must be exactly one normal component")]
    InvalidRoot,
    #[error("requested directory limit exceeds the hard FD cap")]
    InvalidDirectoryLimit,
    #[error("held tree exceeded its {kind:?} limit of {limit}")]
    Limit { kind: HeldTreeLimit, limit: u64 },
    #[error("source parent policy rejects sealing by this process")]
    ParentPolicyRejected,
    #[error("source parent identity, backend, or mode changed")]
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
    #[error("non-directory ACL, xattr, or capability is present at {0}")]
    NonDirectoryExtendedMetadata(PathBuf),
    #[error("non-directory ACL or xattr evidence is unavailable at {0}")]
    NonDirectoryMetadataUnavailable(PathBuf),
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

/// A non-authorizing outcome of attempting metadata-only tree policy
/// assessment. No outcome claims that the source-parent seal has executed or
/// that staging is ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HeldTreeAdmissionAssessment {
    /// Tree policy was assessed; the separate seal projection remains untested.
    TreePolicyAssessed {
        tree: HeldTreePolicyAssessment,
        source_parent_seal: SourceParentSealProjection,
    },
    /// No tree-policy facts were obtained because traversal requires the seal.
    TreePolicyDeferredUntilSourceParentSeal {
        reason: TreePolicyDeferralReason,
        source_parent_seal: SourceParentSealProjection,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreePolicyAssessment {
    pub(crate) entries: u64,
    pub(crate) directories: u64,
    pub(crate) path_bytes: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) content_bytes: u64,
    pub(crate) assessed_at: std::time::SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceParentSealProjection {
    pub(crate) original_mode: u32,
    pub(crate) projected_mode: u32,
    pub(crate) validation: SourceParentSealValidation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceParentSealValidation {
    RequiresExecutionValidation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TreePolicyDeferralReason {
    SourceParentSearchRequiresExecutionSeal,
}

#[derive(Clone, Debug)]
struct AssessedEntry {
    path: PathBuf,
    identity: NodeIdentity,
}

/// Data-only admission uses the production v2 namespace traversal, admission
/// policy, and budgets, but substitutes metadata inspection for content proof.
pub(crate) fn assess_tree_admission(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
) -> Result<HeldTreeAdmissionAssessment, HeldTreeError> {
    validate_v2_inputs(root_name, &protected_names, limits)?;
    let projected = projected_parent_seal(&parent)?;
    let source_parent_seal = SourceParentSealProjection {
        original_mode: projected.original_mode,
        projected_mode: projected.projected_mode,
        validation: SourceParentSealValidation::RequiresExecutionValidation,
    };
    if projected.original_mode & 0o100 == 0 {
        return Ok(
            HeldTreeAdmissionAssessment::TreePolicyDeferredUntilSourceParentSeal {
                reason: TreePolicyDeferralReason::SourceParentSearchRequiresExecutionSeal,
                source_parent_seal,
            },
        );
    }
    let walked = traverse_v2::<AssessTraversal>(
        parent,
        root_name,
        protected_names,
        limits,
        ParentAdmission::Projected(projected),
    )?;
    Ok(HeldTreeAdmissionAssessment::TreePolicyAssessed {
        tree: HeldTreePolicyAssessment {
            entries: walked.budget.entries,
            directories: walked.budget.directories,
            path_bytes: walked.budget.path_bytes,
            manifest_bytes: walked.budget.manifest_bytes,
            content_bytes: walked.budget.content_bytes,
            assessed_at: std::time::SystemTime::now(),
        },
        source_parent_seal,
    })
}

/// Data-only ordering for deterministic recovery. It carries neither an
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

#[derive(Debug)]
struct HeldDirectory {
    held: HeldLocalBackendEvidence,
    path: PathBuf,
    depth: u32,
    incarnation: u64,
}

/// Private bounded inventory retaining all directory FDs for exact rewalk and
/// lease-bound minimal sealing. By itself it carries no WAL lease and is not
/// rename, restore, purge, or deletion authority.
#[derive(Debug)]
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

#[derive(Clone, Copy)]
struct ProjectedParentSeal {
    original_mode: u32,
    projected_mode: u32,
}

#[derive(Clone, Copy)]
enum ParentAdmission {
    CurrentExclusive,
    Projected(ProjectedParentSeal),
}

trait V2Traversal {
    type Entry;

    fn make_root(inspected: Inspection) -> Self::Entry;
    fn inspect_entry(
        parent: &HeldLocalBackendEvidence,
        name: &OsStr,
        path: &Path,
        inspected: &Inspection,
        budget: &mut Budget,
    ) -> Result<Self::Entry, HeldTreeError>;
    fn path(entry: &Self::Entry) -> &Path;
    fn identity(entry: &Self::Entry) -> NodeIdentity;
}

struct ProveTraversal;
struct AssessTraversal;

impl V2Traversal for ProveTraversal {
    type Entry = ManifestEntry;

    fn make_root(inspected: Inspection) -> Self::Entry {
        inspected.into_manifest(PathBuf::new(), ContentProof::Directory)
    }

    fn inspect_entry(
        parent: &HeldLocalBackendEvidence,
        name: &OsStr,
        path: &Path,
        inspected: &Inspection,
        budget: &mut Budget,
    ) -> Result<Self::Entry, HeldTreeError> {
        let content = inspect_content_at(parent, name, path, inspected, budget)?;
        Ok(inspected.clone().into_manifest(path.to_path_buf(), content))
    }

    fn path(entry: &Self::Entry) -> &Path {
        &entry.path
    }

    fn identity(entry: &Self::Entry) -> NodeIdentity {
        entry.identity
    }
}

impl V2Traversal for AssessTraversal {
    type Entry = AssessedEntry;

    fn make_root(inspected: Inspection) -> Self::Entry {
        AssessedEntry {
            path: PathBuf::new(),
            identity: inspected.identity,
        }
    }

    fn inspect_entry(
        parent: &HeldLocalBackendEvidence,
        name: &OsStr,
        path: &Path,
        inspected: &Inspection,
        budget: &mut Budget,
    ) -> Result<Self::Entry, HeldTreeError> {
        inspect_content_admission(parent, name, path, inspected, budget)?;
        Ok(AssessedEntry {
            path: path.to_path_buf(),
            identity: inspected.identity,
        })
    }

    fn path(entry: &Self::Entry) -> &Path {
        &entry.path
    }

    fn identity(entry: &Self::Entry) -> NodeIdentity {
        entry.identity
    }
}

struct V2Walk<M: V2Traversal> {
    parent: HeldLocalBackendEvidence,
    root_name: OsString,
    root_identity: NodeIdentity,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    directories: Vec<HeldDirectory>,
    entries: Vec<M::Entry>,
    budget: Budget,
}

fn validate_v2_inputs(
    root_name: &OsStr,
    protected_names: &[OsString],
    limits: HeldTreeLimits,
) -> Result<(), HeldTreeError> {
    require_one_component(root_name)?;
    validate_policy(protected_names)?;
    if limits.max_directories > HARD_DIRECTORY_CAP {
        return Err(HeldTreeError::InvalidDirectoryLimit);
    }
    if protected_names.iter().any(|name| name == root_name) {
        return Err(HeldTreeError::ProtectedName(PathBuf::new()));
    }
    Ok(())
}

fn collect_proven_v2(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
) -> Result<HeldTreeInventory, HeldTreeError> {
    let walked = traverse_v2::<ProveTraversal>(
        parent,
        root_name,
        protected_names,
        limits,
        ParentAdmission::CurrentExclusive,
    )?;
    Ok(HeldTreeInventory {
        parent: walked.parent,
        root_name: walked.root_name,
        root_identity: walked.root_identity,
        backend: walked.backend,
        mount_id: walked.mount_id,
        protected_names: walked.protected_names,
        limits: walked.limits,
        manifest_schema: CONTENT_PROOF_VERSION,
        directories: walked.directories,
        manifest: walked.entries,
    })
}

fn traverse_v2<M: V2Traversal>(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    parent_admission: ParentAdmission,
) -> Result<V2Walk<M>, HeldTreeError> {
    validate_v2_inputs(root_name, &protected_names, limits)?;
    let backend = parent.backend();
    require_parent_admission(&parent, backend, parent_admission)?;
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
    let root_entry = M::make_root(opened);
    let mut budget = Budget::new(limits, CONTENT_PROOF_VERSION);
    budget.add_path(M::path(&root_entry), 0)?;
    budget.add_directory()?;
    let mut walked = V2Walk::<M> {
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
        entries: vec![root_entry],
        budget,
    };
    let mut index = 0;
    while index < walked.directories.len() {
        read_v2_children::<M>(&mut walked, index)?;
        index += 1;
    }
    walked
        .entries
        .sort_by(|left, right| M::path(left).cmp(M::path(right)));
    require_parent_admission(&walked.parent, walked.backend, parent_admission)?;
    let rebound = with_fd(&walked.parent, |fd| {
        inspect_at(fd, &walked.root_name, Path::new(""))
    })
    .map_err(|_| HeldTreeError::RootBindingChanged)?;
    if !root_binding_matches(
        walked.root_identity,
        walked.mount_id,
        walked.backend,
        &rebound,
    ) {
        return Err(HeldTreeError::RootBindingChanged);
    }
    Ok(walked)
}

fn read_v2_children<M: V2Traversal>(
    walked: &mut V2Walk<M>,
    index: usize,
) -> Result<(), HeldTreeError> {
    let parent_path = walked.directories[index].path.clone();
    let parent_depth = walked.directories[index].depth;
    require_directory_current(&walked.directories[index], walked.backend, walked.mount_id)?;
    let fresh = with_fd(&walked.directories[index].held, |fd| {
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
        require_unprotected(&walked.protected_names, name, &path)?;
        let inspected = with_fd(&walked.directories[index].held, |fd| {
            inspect_at(fd, name, &path)
        })?;
        require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
        require_boundary(&path, walked.backend, walked.mount_id, &inspected)?;
        let depth = parent_depth.saturating_add(1);
        let child = if inspected.identity.kind == NodeKind::Directory {
            let fd = with_fd(&walked.directories[index].held, |parent_fd| {
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
            if held.backend() != walked.backend || held.mount_id() != walked.mount_id {
                return Err(HeldTreeError::BackendBoundary(path));
            }
            Some(held)
        } else {
            None
        };
        let result = M::inspect_entry(
            &walked.directories[index].held,
            name,
            &path,
            &inspected,
            &mut walked.budget,
        )?;
        walked.budget.add_path(M::path(&result), depth)?;
        if child.is_some() {
            walked.budget.add_directory()?;
        }
        let incarnation = M::identity(&result).incarnation;
        walked.entries.push(result);
        if let Some(held) = child {
            walked.directories.push(HeldDirectory {
                held,
                path,
                depth,
                incarnation,
            });
        }
    }
    Ok(())
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
        if manifest_schema == CONTENT_PROOF_VERSION {
            return collect_proven_v2(parent, root_name, protected_names, limits);
        }
        if manifest_schema != 1 {
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
        budget.add_path(&root_entry.path, 0)?;
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
            crate::seal::wal::ObjectIncarnation::new(self.root_identity.incarnation),
            self.mount_id,
        )
    }

    /// Consumes the freshly verified inventory and removes that exact tree using
    /// only retained directory descriptors. Every non-directory is revalidated
    /// (including content, one-link policy, ownership, type and strong
    /// incarnation) immediately before unlink. Directories are removed in
    /// bounded postorder, symlinks are never followed, and the retained trash
    /// parent is synced only after the exact root name has been removed.
    #[allow(clippy::disallowed_methods)] // this method is the verified fd-relative deletion engine
    pub(crate) fn purge_postorder<E>(
        self,
        mut record_progress: impl FnMut(u64, &Path) -> Result<(), E>,
    ) -> Result<u64, HeldTreePurgeError<E>> {
        self.verify_root_binding()?;
        let mut entries = self
            .manifest
            .iter()
            .filter(|entry| !entry.path.as_os_str().is_empty())
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .path
                .components()
                .count()
                .cmp(&left.path.components().count())
                .then_with(|| right.path.cmp(&left.path))
        });
        let mut content_budget = Budget::new(self.limits, CONTENT_PROOF_VERSION);
        let mut removed = 0_u64;
        for expected in entries {
            #[cfg(test)]
            if PURGE_FAIL_AFTER_REMOVALS.with(|limit| limit.get() == Some(removed)) {
                return Err(io_error(&expected.path, rustix::io::Errno::IO).into());
            }
            let parent_path = expected.path.parent().unwrap_or_else(|| Path::new(""));
            let name = expected
                .path
                .file_name()
                .ok_or(HeldTreeError::InvalidRoot)?;
            let parent = self
                .directories
                .iter()
                .find(|directory| directory.path == parent_path)
                .ok_or_else(|| HeldTreeError::IdentityChanged(expected.path.clone()))?;
            require_directory_current(parent, self.backend, self.mount_id)?;
            let before = with_fd(&parent.held, |fd| inspect_at(fd, name, &expected.path))?;
            require_owner(
                &expected.path,
                before.uid,
                rustix::process::geteuid().as_raw(),
            )?;
            require_boundary(&expected.path, self.backend, self.mount_id, &before)?;
            let content = inspect_content_at(
                &parent.held,
                name,
                &expected.path,
                &before,
                &mut content_budget,
            )?;
            let actual = before.into_manifest(expected.path.clone(), content);
            if &actual != expected {
                return Err(HeldTreeError::IdentityChanged(expected.path.clone()).into());
            }
            let flags = if expected.identity.kind == NodeKind::Directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            };
            retry_interrupted(|| with_fd(&parent.held, |fd| rustix::fs::unlinkat(fd, name, flags)))
                .map_err(|error| io_error(&expected.path, error))?;
            removed = removed.checked_add(1).ok_or(HeldTreeError::Limit {
                kind: HeldTreeLimit::Entries,
                limit: self.limits.max_entries,
            })?;
            record_progress(removed, &expected.path).map_err(HeldTreePurgeError::Journal)?;
        }

        // Child removal changes directory timestamps, but not the strong root
        // incarnation committed by the authority. Recheck both the name and
        // retained root FD immediately before the final rmdir.
        let named_root = with_fd(&self.parent, |fd| {
            inspect_at(fd, &self.root_name, Path::new(""))
        })?;
        let held_root = inspect_held(&self.directories[0].held, Path::new(""))?;
        require_same_identity(Path::new(""), self.root_identity, named_root.identity)?;
        require_same_identity(Path::new(""), self.root_identity, held_root.identity)?;
        retry_interrupted(|| {
            with_fd(&self.parent, |fd| {
                rustix::fs::unlinkat(fd, &self.root_name, AtFlags::REMOVEDIR)
            })
        })
        .map_err(|error| io_error(Path::new(""), error))?;
        removed = removed.checked_add(1).ok_or(HeldTreeError::Limit {
            kind: HeldTreeLimit::Entries,
            limit: self.limits.max_entries,
        })?;
        record_progress(removed, Path::new("")).map_err(HeldTreePurgeError::Journal)?;
        #[cfg(test)]
        if PURGE_FAIL_PARENT_FSYNC.with(std::cell::Cell::get) {
            return Err(io_error(Path::new(""), rustix::io::Errno::IO).into());
        }
        retry_interrupted(|| with_fd(&self.parent, |fd| rustix::fs::fsync(fd)))
            .map_err(|error| io_error(Path::new(""), error))?;
        Ok(removed)
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
        budget.add_path(&root.path, 0)?;
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
                budget.add_path(&value.path, directory.depth.saturating_add(1))?;
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
            budget.add_path(&manifest.path, depth)?;
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

fn retry_interrupted<T>(
    mut operation: impl FnMut() -> rustix::io::Result<T>,
) -> rustix::io::Result<T> {
    for attempt in 0..PURGE_IO_ATTEMPTS {
        match operation() {
            Err(rustix::io::Errno::INTR) if attempt + 1 < PURGE_IO_ATTEMPTS => continue,
            result => return result,
        }
    }
    unreachable!("bounded retry loop always returns")
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
    let backend = crate::backend::certify_held_fd_backend(parent).map_err(|reason| {
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
    let backend = crate::backend::certify_held_fd_backend(parent).map_err(|reason| {
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
        NodeKind::Directory => {
            require_content_admitted(
                EntryFacts {
                    kind: EntryKind::Directory,
                    nlink: LinkCount::Unknown,
                    acl: Evidence::Unknown,
                    xattr_platform: current_xattr_platform(),
                    xattrs: Xattrs::Unknown,
                },
                path,
            )?;
            Ok(ContentProof::Directory)
        }
        NodeKind::Regular => inspect_regular_content(parent, name, path, before, budget),
        NodeKind::Symlink => inspect_symlink_content(parent, name, path, before, budget),
        NodeKind::Other => {
            require_content_admitted(
                EntryFacts {
                    kind: EntryKind::Other,
                    nlink: LinkCount::Unknown,
                    acl: Evidence::Unknown,
                    xattr_platform: current_xattr_platform(),
                    xattrs: Xattrs::Unknown,
                },
                path,
            )?;
            // Special files have no v2 content-proof representation. Keep the
            // schema boundary fail-closed even if a later policy admits them.
            Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
        }
    }
}

fn inspect_content_admission(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<(), HeldTreeError> {
    if !before.content_fields_available {
        return Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()));
    }
    match before.identity.kind {
        NodeKind::Directory => Ok(()),
        NodeKind::Regular => assess_regular_content(parent, name, path, before, budget),
        NodeKind::Symlink => assess_symlink_content(parent, name, path, before, budget),
        NodeKind::Other => Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf())),
    }
}

fn assess_regular_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<(), HeldTreeError> {
    require_content_admitted(
        EntryFacts {
            kind: EntryKind::Regular,
            nlink: LinkCount::Known(before.nlink),
            acl: Evidence::Absent,
            xattr_platform: current_xattr_platform(),
            xattrs: Xattrs::Names(&[]),
        },
        path,
    )?;
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
    require_fd_metadata_admitted(&fd, path, EntryKind::Regular, true)?;
    let opened = inspect_raw_fd(&fd, parent.backend(), path)?;
    if !before.stable_content_fields_equal(&opened) || opened.identity.kind != NodeKind::Regular {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    require_fd_metadata_admitted(&fd, path, EntryKind::Regular, false)?;
    let final_inspection = inspect_raw_fd(&fd, parent.backend(), path)?;
    if !opened.stable_content_fields_equal(&final_inspection) || final_inspection.nlink != 1 {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(())
}

fn assess_symlink_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<(), HeldTreeError> {
    let target = read_stable_symlink_target(parent, name, path, before)?;
    budget.add_content(target.len() as u64)
}

fn inspect_regular_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<ContentProof, HeldTreeError> {
    require_content_admitted(
        EntryFacts {
            kind: EntryKind::Regular,
            nlink: LinkCount::Known(before.nlink),
            acl: Evidence::Absent,
            xattr_platform: current_xattr_platform(),
            xattrs: Xattrs::Names(&[]),
        },
        path,
    )?;
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
    require_fd_metadata_admitted(&fd, path, EntryKind::Regular, true)?;
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
    require_fd_metadata_admitted(&file, path, EntryKind::Regular, false)?;
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
    let target = read_stable_symlink_target(parent, name, path, before)?;
    budget.add_content(target.len() as u64)?;
    Ok(ContentProof::Symlink { target })
}

fn read_stable_symlink_target(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
) -> Result<Vec<u8>, HeldTreeError> {
    require_symlink_metadata_admitted(parent, name, path)?;
    let target = with_fd(parent, |fd| rustix::fs::readlinkat(fd, name, Vec::new()))
        .map_err(|error| io_error(path, error))?
        .into_bytes();
    let middle = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    require_symlink_metadata_admitted(parent, name, path)?;
    let target_again = with_fd(parent, |fd| rustix::fs::readlinkat(fd, name, Vec::new()))
        .map_err(|error| io_error(path, error))?
        .into_bytes();
    let after = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    require_symlink_metadata_admitted(parent, name, path)?;
    let final_inspection = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    if !before.stable_content_fields_equal(&middle)
        || !before.stable_content_fields_equal(&after)
        || !after.stable_content_fields_equal(&final_inspection)
        || target != target_again
    {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(target)
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

fn require_content_admitted(facts: EntryFacts<'_>, path: &Path) -> Result<(), HeldTreeError> {
    match assess_content(&facts) {
        Admission::Admit => Ok(()),
        Admission::Reject(reason) => Err(match reason {
            RejectReason::UnsupportedEntryKind | RejectReason::RegularFileLinkCountUnknown => {
                HeldTreeError::UnsupportedContentProof(path.to_path_buf())
            }
            RejectReason::RegularFileLinkCountNotOne { .. } => {
                HeldTreeError::ExternalHardLink(path.to_path_buf())
            }
            RejectReason::AclPresent
            | RejectReason::AclUnknown
            | RejectReason::ExtendedAttributePresent { .. }
            | RejectReason::ExtendedAttributesUnknown => {
                HeldTreeError::NonDirectoryExtendedMetadata(path.to_path_buf())
            }
        }),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CollectedXattrs {
    Names(Vec<Vec<u8>>),
    Unknown,
}

fn require_fd_metadata_admitted<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
    kind: EntryKind,
    inspect_acl: bool,
) -> Result<(), HeldTreeError> {
    let collected = collect_fd_xattr_names(fd);
    assess_collected_metadata(fd, path, kind, inspect_acl, &collected)
}

fn assess_collected_metadata<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
    kind: EntryKind,
    inspect_acl: bool,
    collected: &CollectedXattrs,
) -> Result<(), HeldTreeError> {
    match collected {
        CollectedXattrs::Unknown => Err(HeldTreeError::NonDirectoryMetadataUnavailable(
            path.to_path_buf(),
        )),
        CollectedXattrs::Names(names) => {
            let name_refs = names.iter().map(Vec::as_slice).collect::<Vec<_>>();
            // Preserve the former syscall order: a present/uncertain xattr list
            // rejects before the separate ACL probe is attempted.
            let acl = if inspect_acl && names.is_empty() {
                acl_evidence(fd)
            } else {
                Evidence::Absent
            };
            if acl == Evidence::Unknown {
                return Err(HeldTreeError::NonDirectoryMetadataUnavailable(
                    path.to_path_buf(),
                ));
            }
            require_content_admitted(
                EntryFacts {
                    kind,
                    nlink: LinkCount::Known(1),
                    acl,
                    xattr_platform: current_xattr_platform(),
                    xattrs: Xattrs::Names(&name_refs),
                },
                path,
            )
        }
    }
}

fn acl_evidence<Fd: rustix::fd::AsFd>(fd: &Fd) -> Evidence {
    match crate::backend::require_held_fd_acl_absent(fd) {
        Ok(()) => Evidence::Absent,
        Err(CertificationError::AclPresent) => Evidence::Present,
        Err(CertificationError::AclProbeUnknown) => Evidence::Unknown,
        Err(_) => Evidence::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn collect_fd_xattr_names<Fd: rustix::fd::AsFd>(fd: &Fd) -> CollectedXattrs {
    let raw_fd = fd.as_fd().as_raw_fd();
    collect_xattr_names(|buffer, size| {
        // SAFETY: fd is live for the call and buffer is either null for a size
        // query or points to the supplied writable allocation.
        xattr_count_result(unsafe { libc::flistxattr(raw_fd, buffer, size) })
    })
}

#[cfg(target_os = "macos")]
fn collect_fd_xattr_names<Fd: rustix::fd::AsFd>(fd: &Fd) -> CollectedXattrs {
    let raw_fd = fd.as_fd().as_raw_fd();
    collect_xattr_names(|buffer, size| {
        // SAFETY: fd is live for the call and buffer is either null for a size
        // query or points to the supplied writable allocation.
        xattr_count_result(unsafe { libc::flistxattr(raw_fd, buffer, size, 0) })
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_fd_xattr_names<Fd: rustix::fd::AsFd>(_fd: &Fd) -> CollectedXattrs {
    CollectedXattrs::Unknown
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn xattr_count_result(result: libc::ssize_t) -> io::Result<usize> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(result).map_err(|_| io::Error::other("xattr byte count does not fit usize"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collect_xattr_names(
    mut list: impl FnMut(*mut libc::c_char, usize) -> io::Result<usize>,
) -> CollectedXattrs {
    let mut rejection_observed = false;
    for _ in 0..XATTR_LIST_ATTEMPTS {
        let size = match list(std::ptr::null_mut(), 0) {
            Ok(size) => size,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                rejection_observed = true;
                continue;
            }
            Err(_) => return CollectedXattrs::Unknown,
        };
        if size == 0 {
            return if rejection_observed {
                CollectedXattrs::Unknown
            } else {
                CollectedXattrs::Names(Vec::new())
            };
        }
        rejection_observed = true;
        if size > MAX_XATTR_NAME_LIST_BYTES {
            return CollectedXattrs::Unknown;
        }

        let mut bytes = vec![0_u8; size];
        let read = match list(bytes.as_mut_ptr().cast(), bytes.len()) {
            Ok(read) => read,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ERANGE)) => {
                continue;
            }
            Err(_) => return CollectedXattrs::Unknown,
        };
        if read == 0 || read > bytes.len() {
            return CollectedXattrs::Unknown;
        }
        bytes.truncate(read);
        let Some((&0, body)) = bytes.split_last() else {
            return CollectedXattrs::Unknown;
        };
        let mut names = Vec::new();
        for name in body.split(|byte| *byte == 0) {
            if name.is_empty() || names.len() == MAX_XATTR_NAMES {
                return CollectedXattrs::Unknown;
            }
            names.push(name.to_vec());
        }
        return CollectedXattrs::Names(names);
    }
    CollectedXattrs::Unknown
}

#[cfg(target_os = "linux")]
fn require_symlink_metadata_admitted(
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
    let collected = collect_xattr_names(|buffer, size| {
        // SAFETY: proc_path is NUL-terminated and names the symlink through the
        // held parent FD; llistxattr inspects the link itself without following.
        xattr_count_result(unsafe { libc::llistxattr(proc_path.as_ptr(), buffer, size) })
    });
    assess_symlink_xattrs(path, &collected)
}

#[cfg(target_os = "macos")]
fn require_symlink_metadata_admitted(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    use std::os::fd::FromRawFd;
    let name = CString::new(name.as_bytes())
        .map_err(|_| HeldTreeError::UnsupportedContentProof(path.to_path_buf()))?;
    let raw = with_fd(parent, |fd| {
        // SAFETY: parent/name remain live; O_SYMLINK opens the link itself rather
        // than following its target.
        unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
            )
        }
    });
    if raw < 0 {
        return Err(HeldTreeError::Io {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: openat returned a new uniquely-owned descriptor.
    let fd = unsafe { rustix::fd::OwnedFd::from_raw_fd(raw) };
    let collected = collect_fd_xattr_names(&fd);
    assess_symlink_xattrs(path, &collected)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn require_symlink_metadata_admitted(
    _parent: &HeldLocalBackendEvidence,
    _name: &OsStr,
    path: &Path,
) -> Result<(), HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
}

fn assess_symlink_xattrs(path: &Path, collected: &CollectedXattrs) -> Result<(), HeldTreeError> {
    match collected {
        CollectedXattrs::Unknown => Err(HeldTreeError::NonDirectoryMetadataUnavailable(
            path.to_path_buf(),
        )),
        CollectedXattrs::Names(names) => {
            let name_refs = names.iter().map(Vec::as_slice).collect::<Vec<_>>();
            require_content_admitted(
                EntryFacts {
                    kind: EntryKind::Symlink,
                    nlink: LinkCount::Unknown,
                    acl: Evidence::Absent,
                    xattr_platform: current_xattr_platform(),
                    xattrs: Xattrs::Names(&name_refs),
                },
                path,
            )
        }
    }
}

#[cfg(target_os = "linux")]
const fn current_xattr_platform() -> XattrPlatform {
    XattrPlatform::Linux
}

#[cfg(target_os = "macos")]
const fn current_xattr_platform() -> XattrPlatform {
    XattrPlatform::MacOs
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn current_xattr_platform() -> XattrPlatform {
    XattrPlatform::Other
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

fn projected_parent_seal(
    parent: &HeldLocalBackendEvidence,
) -> Result<ProjectedParentSeal, HeldTreeError> {
    let (original_mode, sealed_mode) = match assess_mode_seal(parent) {
        ModeSealAssessment::Candidate {
            original_mode,
            sealed_mode,
        } => (original_mode, sealed_mode),
        ModeSealAssessment::Denied(ModeSealDenial::NotOwner) => {
            return Err(HeldTreeError::ParentPolicyRejected);
        }
        ModeSealAssessment::Denied(ModeSealDenial::EvidenceUnverified) => {
            return Err(HeldTreeError::ParentNotExclusive);
        }
    };
    // Production seals the source parent with owner write/search acquisition.
    let projected_mode = minimal_sealed_mode(sealed_mode | 0o300);
    Ok(ProjectedParentSeal {
        original_mode,
        projected_mode,
    })
}

fn require_parent_admission(
    parent: &HeldLocalBackendEvidence,
    backend: CertifiedLocalBackend,
    admission: ParentAdmission,
) -> Result<(), HeldTreeError> {
    match admission {
        ParentAdmission::CurrentExclusive => require_exclusive_parent(parent, backend),
        ParentAdmission::Projected(projected) => {
            with_fd(parent, |fd| crate::backend::require_held_fd_acl_absent(fd)).map_err(
                |reason| HeldTreeError::Certification {
                    path: PathBuf::new(),
                    reason,
                },
            )?;
            let stat = with_fd(parent, |fd| rustix::fs::fstat(fd))
                .map_err(|error| io_error(Path::new(""), error))?;
            let actual_backend = with_fd(parent, |fd| crate::backend::certify_held_fd_backend(fd))
                .map_err(|reason| HeldTreeError::Certification {
                    path: PathBuf::new(),
                    reason,
                })?;
            let refreshed = projected_parent_seal(parent)?;
            if parent.backend() != backend
                || actual_backend != backend
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || super::raw_mode_u32(stat.st_mode) & 0o7777 != projected.original_mode
                || refreshed.original_mode != projected.original_mode
                || refreshed.projected_mode != projected.projected_mode
                || grants_namespace_write(projected.projected_mode)
            {
                Err(HeldTreeError::ParentNotExclusive)
            } else {
                Ok(())
            }
        }
    }
}

fn require_exclusive_parent(
    parent: &HeldLocalBackendEvidence,
    backend: CertifiedLocalBackend,
) -> Result<(), HeldTreeError> {
    with_fd(parent, |fd| crate::backend::require_held_fd_acl_absent(fd)).map_err(|reason| {
        HeldTreeError::Certification {
            path: PathBuf::new(),
            reason,
        }
    })?;
    let stat = with_fd(parent, |fd| rustix::fs::fstat(fd))
        .map_err(|error| io_error(Path::new(""), error))?;
    let actual_backend = with_fd(parent, |fd| crate::backend::certify_held_fd_backend(fd))
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
        crate::backend::require_held_fd_acl_absent(fd)
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

    fn add_path(&mut self, path: &Path, depth: u32) -> Result<(), HeldTreeError> {
        let path_len = path.as_os_str().as_bytes().len() as u64;
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
