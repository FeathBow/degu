//! Core-private bounded held-FD traversal, sealing, and exact rewalk.
//!
//! Collection and rewalk are authority-neutral. One narrow method can apply
//! minimal directory seals only when given an exact leased staging WAL
//! and descriptor-derived incarnations. This module performs no rename, restore,
//! purge, unlink, or deletion and returns no lifecycle authority token.

use crate::admission::{
    Admission, EntryFacts, EntryKind, Evidence, RejectReason, XattrPlatform, Xattrs,
    assess_content, ordinary_regular_xattr_is_admitted,
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
use crate::seal::sidecar::AuthenticatedTreeManifest;
use crate::seal::wal::{
    DurableTreeManifest, DurableWrite, RECOVERY_MAX_ACTIVE_PERMISSIONS, SealWal,
    StrongObjectIdentity, TransactionId,
};
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
/// Recovery may retain this many active permission operations internally.
/// Tree requests must reserve one operation for the source-parent seal, so the
/// root-inclusive request ceiling is one lower for every schema and traversal.
const HARD_DIRECTORY_CAP: u64 = RECOVERY_MAX_ACTIVE_PERMISSIONS as u64;
pub(crate) const MAX_TREE_DIRECTORIES: u64 = HARD_DIRECTORY_CAP - 1;
const MANIFEST_DOMAIN_V1: &[u8] = b"degu-held-tree-manifest-v1\0";
const MANIFEST_DOMAIN_V2: &[u8] = b"degu-held-tree-manifest-v2-content\0";
const MANIFEST_DOMAIN_V3: &[u8] = b"degu-held-tree-manifest-v3-content-xattr\0";
const LEGACY_CONTENT_PROOF_VERSION: u16 = 2;
const CONTENT_PROOF_VERSION: u16 = 3;
const XATTR_PROOF_DOMAIN_V3: &[u8] = b"degu-regular-xattr-proof-v3\0";
/// A transient EINTR is retried, but every namespace operation remains bounded.
const PURGE_IO_ATTEMPTS: usize = 3;
/// Xattr name enumeration is diagnostic policy input only. Any oversized,
/// unstable, malformed, or unreadable list remains the same fail-closed result.
const XATTR_LIST_ATTEMPTS: usize = 3;
const MAX_XATTR_NAME_LIST_BYTES: usize = 64 * 1024;
const MAX_XATTR_NAMES: usize = 1_024;
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReopenerTestPhase {
    AfterOpenBeforeValidation,
    AfterValidatedHopBeforeNextOperation,
}

#[cfg(test)]
type ReopenerTestCallback = Box<dyn FnMut(ReopenerTestPhase, &Path)>;
#[cfg(test)]
type RegularLinkTestCallback = Box<dyn FnMut(&Path)>;
#[cfg(test)]
type FinalRegularReobservationTestCallback = Box<dyn FnOnce()>;
#[cfg(test)]
type TransientSealTestCallback = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
std::thread_local! {
    pub(crate) static PURGE_FAIL_AFTER_REMOVALS: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    pub(crate) static PURGE_FAIL_PARENT_FSYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static REOPENER_MAX_NON_ROOT_FDS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static REGULAR_CONTENT_BYTES_READ: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    static REGULAR_XATTR_VALUE_BYTES_READ: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    static REOPENER_TEST_CALLBACK: std::cell::RefCell<Option<ReopenerTestCallback>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_TRANSIENT_SEAL: std::cell::RefCell<Option<TransientSealTestCallback>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_REGULAR_LINK_OBSERVATION: std::cell::RefCell<Option<RegularLinkTestCallback>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_FINAL_REGULAR_REOBSERVATION: std::cell::RefCell<Option<FinalRegularReobservationTestCallback>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn reset_regular_content_bytes_read() {
    REGULAR_CONTENT_BYTES_READ.with(|bytes| bytes.set(0));
}

#[cfg(test)]
pub(crate) fn regular_content_bytes_read() -> u64 {
    REGULAR_CONTENT_BYTES_READ.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) struct ReopenerTestHookGuard;

#[cfg(test)]
impl Drop for ReopenerTestHookGuard {
    fn drop(&mut self) {
        REOPENER_TEST_CALLBACK.with(|slot| *slot.borrow_mut() = None);
        AFTER_REGULAR_LINK_OBSERVATION.with(|slot| *slot.borrow_mut() = None);
        BEFORE_FINAL_REGULAR_REOBSERVATION.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn install_transient_seal_test_hook(callback: impl FnOnce(&Path) + 'static) {
    BEFORE_TRANSIENT_SEAL.with(|slot| {
        let previous = slot.borrow_mut().replace(Box::new(callback));
        assert!(
            previous.is_none(),
            "a transient seal test hook is already installed"
        );
    });
}

#[cfg(test)]
fn fire_transient_seal_test_hook(path: &Path) {
    BEFORE_TRANSIENT_SEAL.with(|slot| {
        if let Some(callback) = slot.borrow_mut().take() {
            callback(path);
        }
    });
}

#[cfg(test)]
pub(crate) fn install_regular_link_observation_test_hook(
    callback: impl FnMut(&Path) + 'static,
) -> ReopenerTestHookGuard {
    AFTER_REGULAR_LINK_OBSERVATION.with(|slot| {
        let previous = slot.borrow_mut().replace(Box::new(callback));
        assert!(
            previous.is_none(),
            "a regular-link observation test hook is already installed"
        );
    });
    ReopenerTestHookGuard
}

#[cfg(test)]
fn fire_regular_link_observation_test_hook(path: &Path) {
    let callback = AFTER_REGULAR_LINK_OBSERVATION.with(|slot| slot.borrow_mut().take());
    if let Some(mut callback) = callback {
        callback(path);
        AFTER_REGULAR_LINK_OBSERVATION.with(|slot| {
            let previous = slot.borrow_mut().replace(callback);
            assert!(
                previous.is_none(),
                "regular-link observation hook was replaced"
            );
        });
    }
}

#[cfg(not(test))]
fn fire_regular_link_observation_test_hook(_path: &Path) {}

#[cfg(test)]
pub(crate) fn install_final_regular_reobservation_test_hook(
    callback: impl FnOnce() + 'static,
) -> ReopenerTestHookGuard {
    BEFORE_FINAL_REGULAR_REOBSERVATION.with(|slot| {
        let previous = slot.borrow_mut().replace(Box::new(callback));
        assert!(
            previous.is_none(),
            "a final regular re-observation test hook is already installed"
        );
    });
    ReopenerTestHookGuard
}

#[cfg(test)]
fn fire_final_regular_reobservation_test_hook() {
    BEFORE_FINAL_REGULAR_REOBSERVATION.with(|slot| {
        if let Some(callback) = slot.borrow_mut().take() {
            callback();
        }
    });
}

#[cfg(not(test))]
fn fire_final_regular_reobservation_test_hook() {}

#[cfg(test)]
pub(crate) fn install_reopener_test_hook(
    callback: impl FnMut(ReopenerTestPhase, &Path) + 'static,
) -> ReopenerTestHookGuard {
    REOPENER_TEST_CALLBACK.with(|slot| {
        let previous = slot.borrow_mut().replace(Box::new(callback));
        assert!(
            previous.is_none(),
            "a reopener test hook is already installed"
        );
    });
    ReopenerTestHookGuard
}

#[cfg(test)]
fn fire_reopener_test_hook(phase: ReopenerTestPhase, path: &Path) {
    // Temporarily remove the callback so fixture namespace operations cannot
    // accidentally re-enter a mutably borrowed thread-local hook.
    let callback = REOPENER_TEST_CALLBACK.with(|slot| slot.borrow_mut().take());
    if let Some(mut callback) = callback {
        callback(phase, path);
        REOPENER_TEST_CALLBACK.with(|slot| {
            let previous = slot.borrow_mut().replace(callback);
            assert!(
                previous.is_none(),
                "reopener test hook was replaced while firing"
            );
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreeLimits {
    pub max_entries: u64,
    pub max_directories: u64,
    pub max_depth: u32,
    pub max_path_bytes: u64,
    pub max_manifest_bytes: u64,
    /// Maximum aggregate regular-file and symlink content bytes. `None` is
    /// unbounded (the production default); tests and callers may inject a
    /// finite cap.
    pub max_content_bytes: Option<u64>,
    /// Maximum aggregate ordinary regular-file xattr value bytes read during
    /// one traversal/proof pass.
    pub max_xattr_bytes: u64,
}

impl Default for HeldTreeLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_directories: MAX_TREE_DIRECTORIES,
            max_depth: 128,
            max_path_bytes: 16 * 1024 * 1024,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_content_bytes: None,
            max_xattr_bytes: 1024 * 1024 * 1024,
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
    #[error("directory evidence path contains a non-normal relative component at {0}")]
    InvalidDirectoryPath(PathBuf),
    #[error("requested tree directory limit exceeds 1023 total directories (including the root)")]
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
    #[error("regular file has an external or unenumerated hard link at {0}")]
    ExternalOrUnenumeratedHardLink(PathBuf),
    #[error("non-directory ACL, xattr, or capability is present at {0}")]
    NonDirectoryExtendedMetadata(PathBuf),
    #[error("non-directory ACL or xattr evidence is unavailable at {0}")]
    NonDirectoryMetadataUnavailable(PathBuf),
    #[error("non-directory content proof is unsupported at {0}")]
    UnsupportedContentProof(PathBuf),
    #[error("entry changed while its content was hashed at {0}")]
    ContentChangedDuringHash(PathBuf),
    #[error("ordinary regular-file xattrs changed while proof was collected at {0}")]
    XattrsChangedDuringProof(PathBuf),
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
    #[error("held tree seal validation failed: {0}")]
    Tree(#[from] HeldTreeError),
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NodeKind {
    Directory,
    Regular,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

/// Descriptor-free evidence for one entry's namespace and stable metadata. It
/// deliberately excludes regular-file bytes, xattr values, and their digests;
/// symlink targets remain exact because they are small filesystem metadata. For
/// content-proof schemas it retains the cheap regular-file fields whose drift
/// accompanies byte, xattr, or hardlink changes in the non-root threat model,
/// so a metadata-only rewalk can close the interval after a full content proof
/// without reading the regular payload again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StructureEvidence {
    path: PathBuf,
    identity: NodeIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
    stability: StructureStability,
}

impl StructureEvidence {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn is_directory(&self) -> bool {
        self.identity.kind == NodeKind::Directory
    }

    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }

    pub(crate) fn normalize_directory_mode(&mut self, mode: u32) {
        debug_assert!(self.is_directory());
        self.mode = mode;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StructureStability {
    Legacy,
    Directory,
    Regular {
        size: u64,
        nlink: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        ctime_sec: i64,
        ctime_nsec: u32,
    },
    Symlink {
        target: Vec<u8>,
    },
}

impl ManifestEntry {
    fn structure_evidence(&self) -> StructureEvidence {
        let stability = match &self.content {
            ContentProof::Legacy => StructureStability::Legacy,
            ContentProof::Directory => StructureStability::Directory,
            ContentProof::Regular {
                size,
                nlink,
                mtime_sec,
                mtime_nsec,
                ctime_sec,
                ctime_nsec,
                ..
            } => StructureStability::Regular {
                size: *size,
                nlink: *nlink,
                mtime_sec: *mtime_sec,
                mtime_nsec: *mtime_nsec,
                ctime_sec: *ctime_sec,
                ctime_nsec: *ctime_nsec,
            },
            ContentProof::Symlink { target } => StructureStability::Symlink {
                target: target.clone(),
            },
        };
        StructureEvidence {
            path: self.path.clone(),
            identity: self.identity,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            stability,
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegularXattrProof {
    attribute_count: u64,
    value_bytes: u64,
    sha256: [u8; 32],
}

impl RegularXattrProof {
    fn is_empty(self) -> bool {
        self.attribute_count == 0
    }
}

fn empty_regular_xattr_proof() -> RegularXattrProof {
    let mut digest = Sha256::new();
    digest.update(XATTR_PROOF_DOMAIN_V3);
    digest.update(0_u64.to_be_bytes());
    RegularXattrProof {
        attribute_count: 0,
        value_bytes: 0,
        sha256: digest.finalize().into(),
    }
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
        xattrs: RegularXattrProof,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RegularHardLinkTopology {
    pub(crate) multi_link_groups: u64,
    pub(crate) linked_entries: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RegularXattrTopology {
    pub(crate) entries: u64,
    pub(crate) attributes: u64,
    pub(crate) value_bytes: u64,
}

impl RegularXattrTopology {
    pub(crate) fn contains_xattrs(self) -> bool {
        self.attributes != 0
    }
}

impl RegularHardLinkTopology {
    pub(crate) fn contains_multi_link_group(self) -> bool {
        self.multi_link_groups != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldTreePolicyAssessment {
    pub(crate) entries: u64,
    pub(crate) directories: u64,
    pub(crate) path_bytes: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) content_bytes: u64,
    pub(crate) regular_hard_links: RegularHardLinkTopology,
    pub(crate) regular_xattrs: RegularXattrTopology,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegularFileObservation {
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
    /// Present only for proving traversal. Assessment never reads regular bytes.
    sha256: Option<[u8; 32]>,
    xattrs: RegularXattrProof,
}

#[derive(Clone, Debug)]
struct ProvedEntry {
    manifest: ManifestEntry,
    regular: Option<RegularFileObservation>,
}

#[derive(Clone, Debug)]
struct AssessedEntry {
    path: PathBuf,
    identity: NodeIdentity,
    regular: Option<RegularFileObservation>,
    regular_xattrs: Option<RegularXattrProof>,
}

/// Data-only admission uses the production namespace traversal, admission
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
        CONTENT_PROOF_VERSION,
    )?;
    Ok(HeldTreeAdmissionAssessment::TreePolicyAssessed {
        tree: HeldTreePolicyAssessment {
            entries: walked.budget.entries,
            directories: walked.budget.directories,
            path_bytes: walked.budget.path_bytes,
            manifest_bytes: walked.budget.manifest_bytes,
            content_bytes: walked.budget.content_bytes,
            regular_hard_links: walked.regular_hard_links,
            regular_xattrs: walked.regular_xattrs,
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

/// Descriptor-free evidence for reopening one collected directory from the
/// retained certified root. This is identity evidence only and grants no
/// namespace or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryEvidence {
    relative_path: PathBuf,
    depth: u32,
    identity: NodeIdentity,
    owner_uid: u32,
    group_gid: u32,
    observed_mode: u32,
}

#[derive(Debug)]
struct HeldDirectory {
    held: HeldLocalBackendEvidence,
    evidence: DirectoryEvidence,
}

impl HeldDirectory {
    fn new(
        held: HeldLocalBackendEvidence,
        relative_path: PathBuf,
        depth: u32,
        identity: NodeIdentity,
    ) -> Self {
        let evidence = DirectoryEvidence {
            relative_path,
            depth,
            identity,
            owner_uid: held.owner_uid(),
            group_gid: held.group_gid(),
            observed_mode: held.mode(),
        };
        Self { held, evidence }
    }
}

#[derive(Debug)]
enum ReopenedHeldDirectory<'a> {
    Root(&'a HeldLocalBackendEvidence),
    Descendant(HeldLocalBackendEvidence),
}

#[derive(Debug)]
struct ReopenedDirectory<'a> {
    held: ReopenedHeldDirectory<'a>,
}

impl ReopenedDirectory<'_> {
    fn held(&self) -> &HeldLocalBackendEvidence {
        match &self.held {
            ReopenedHeldDirectory::Root(held) => held,
            ReopenedHeldDirectory::Descendant(held) => held,
        }
    }
}

/// Private bounded inventory retaining the source parent and tree root as
/// reopen anchors. Descendant directories are data-only evidence; transient
/// certified descriptors provide exact rewalk, sealing, and purge authority.
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
    regular_hard_links: RegularHardLinkTopology,
    regular_xattrs: RegularXattrTopology,
    /// Prevalidated lookup evidence. `directories` remains in BFS order for
    /// deterministic mutation ordering; it contains no retained descriptors.
    /// The separately retained `root` is the only tree-directory authority.
    directory_index: BTreeMap<PathBuf, usize>,
    directories: Vec<DirectoryEvidence>,
    root: HeldDirectory,
    manifest: Vec<ManifestEntry>,
}

/// Fixed-size commitment to the exact post-seal manifest expected from a
/// consumed pre-seal inventory. Consuming the inventory lets forward staging
/// release its complete manifest before collecting the second full proof.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PostSealManifestExpectation {
    root_identity: NodeIdentity,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    fingerprint: HeldTreeFingerprint,
}

impl PostSealManifestExpectation {
    pub(crate) fn verify(
        self,
        post: &StreamedV3Inventory,
    ) -> Result<HeldTreeFingerprint, HeldTreeError> {
        if self.backend != post.context.backend
            || self.mount_id != post.context.mount_id
            || self.root_identity != post.context.root_identity
        {
            return Err(HeldTreeError::RootBindingChanged);
        }
        let actual = post.fingerprint();
        if self.fingerprint != actual {
            return Err(HeldTreeError::PostChanged(PathBuf::new()));
        }
        Ok(actual)
    }
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

#[derive(Clone, Copy)]
struct TraversalConfiguration {
    parent_admission: ParentAdmission,
    manifest_schema: u16,
    retain_entries: bool,
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
        schema_version: u16,
    ) -> Result<Self::Entry, HeldTreeError>;
    fn path(entry: &Self::Entry) -> &Path;
    fn manifest_entry(entry: &Self::Entry) -> Option<&ManifestEntry>;
    fn identity(entry: &Self::Entry) -> NodeIdentity;
    fn regular_observation(entry: &Self::Entry) -> Option<RegularFileObservation>;
    fn regular_xattr_proof(entry: &Self::Entry) -> Option<RegularXattrProof>;
    fn reobserve_regular_xattrs<Fd: rustix::fd::AsFd>(
        fd: &Fd,
        path: &Path,
        schema_version: u16,
        expected: RegularXattrProof,
        xattr_limit: u64,
    ) -> Result<RegularXattrProof, HeldTreeError>;
}

struct ProveTraversal;
struct AssessTraversal;

impl V2Traversal for ProveTraversal {
    type Entry = ProvedEntry;

    fn make_root(inspected: Inspection) -> Self::Entry {
        ProvedEntry {
            manifest: inspected.into_manifest(PathBuf::new(), ContentProof::Directory),
            regular: None,
        }
    }

    fn inspect_entry(
        parent: &HeldLocalBackendEvidence,
        name: &OsStr,
        path: &Path,
        inspected: &Inspection,
        budget: &mut Budget,
        schema_version: u16,
    ) -> Result<Self::Entry, HeldTreeError> {
        let content = inspect_content_at(parent, name, path, inspected, budget, schema_version)?;
        let (sha256, xattrs) = match &content {
            ContentProof::Regular { sha256, xattrs, .. } => (Some(*sha256), *xattrs),
            _ => (None, empty_regular_xattr_proof()),
        };
        Ok(ProvedEntry {
            manifest: inspected.clone().into_manifest(path.to_path_buf(), content),
            regular: inspected.regular_file_observation(sha256, xattrs),
        })
    }

    fn path(entry: &Self::Entry) -> &Path {
        &entry.manifest.path
    }

    fn manifest_entry(entry: &Self::Entry) -> Option<&ManifestEntry> {
        Some(&entry.manifest)
    }

    fn identity(entry: &Self::Entry) -> NodeIdentity {
        entry.manifest.identity
    }

    fn regular_observation(entry: &Self::Entry) -> Option<RegularFileObservation> {
        entry.regular
    }

    fn regular_xattr_proof(entry: &Self::Entry) -> Option<RegularXattrProof> {
        match &entry.manifest.content {
            ContentProof::Regular { xattrs, .. } => Some(*xattrs),
            _ => None,
        }
    }

    fn reobserve_regular_xattrs<Fd: rustix::fd::AsFd>(
        fd: &Fd,
        path: &Path,
        schema_version: u16,
        expected: RegularXattrProof,
        xattr_limit: u64,
    ) -> Result<RegularXattrProof, HeldTreeError> {
        collect_regular_xattr_proof(
            fd,
            path,
            schema_version,
            XattrReadBudget::new(expected.value_bytes, xattr_limit),
        )
    }
}

impl V2Traversal for AssessTraversal {
    type Entry = AssessedEntry;

    fn make_root(inspected: Inspection) -> Self::Entry {
        AssessedEntry {
            path: PathBuf::new(),
            identity: inspected.identity,
            regular: None,
            regular_xattrs: None,
        }
    }

    fn inspect_entry(
        parent: &HeldLocalBackendEvidence,
        name: &OsStr,
        path: &Path,
        inspected: &Inspection,
        budget: &mut Budget,
        _schema_version: u16,
    ) -> Result<Self::Entry, HeldTreeError> {
        let regular_xattrs = inspect_content_admission(parent, name, path, inspected, budget)?;
        Ok(AssessedEntry {
            path: path.to_path_buf(),
            identity: inspected.identity,
            regular: inspected.regular_file_observation(
                None,
                regular_xattrs.unwrap_or_else(empty_regular_xattr_proof),
            ),
            regular_xattrs,
        })
    }

    fn path(entry: &Self::Entry) -> &Path {
        &entry.path
    }

    fn manifest_entry(_entry: &Self::Entry) -> Option<&ManifestEntry> {
        None
    }

    fn identity(entry: &Self::Entry) -> NodeIdentity {
        entry.identity
    }

    fn regular_observation(entry: &Self::Entry) -> Option<RegularFileObservation> {
        entry.regular
    }

    fn regular_xattr_proof(entry: &Self::Entry) -> Option<RegularXattrProof> {
        entry.regular_xattrs
    }

    fn reobserve_regular_xattrs<Fd: rustix::fd::AsFd>(
        fd: &Fd,
        path: &Path,
        _schema_version: u16,
        expected: RegularXattrProof,
        xattr_limit: u64,
    ) -> Result<RegularXattrProof, HeldTreeError> {
        collect_regular_xattr_assessment(
            fd,
            path,
            XattrReadBudget::new(expected.value_bytes, xattr_limit),
        )
    }
}

#[derive(Debug)]
struct WalkDirectory {
    evidence: DirectoryEvidence,
}

struct V2Walk<M: V2Traversal> {
    parent: HeldLocalBackendEvidence,
    root_name: OsString,
    root_identity: NodeIdentity,
    root: HeldDirectory,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    manifest_schema: u16,
    directory_index: BTreeMap<PathBuf, DirectoryEvidence>,
    directories: Vec<WalkDirectory>,
    entries: Vec<M::Entry>,
    budget: Budget,
    regular_hard_links: RegularHardLinkTopology,
    regular_xattrs: RegularXattrTopology,
}

/// Fixed-size/root-bounded live context for production v3 after the directory
/// seal. Descendant directory evidence is reconstructed only as an active
/// ancestor stack while an authenticated manifest is folded; it is never kept
/// for the complete tree.
struct ForwardV3Context {
    parent: HeldLocalBackendEvidence,
    root_name: OsString,
    root_identity: NodeIdentity,
    root: HeldDirectory,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
}

/// Post-seal production inventory whose complete v3 manifest remains only in
/// the authenticated sidecar. It retains only the root reopen anchor, fixed
/// commitments, and aggregate topology; descendant evidence and inode groups
/// are bounded/private fold state and unpublished scratch respectively.
pub(crate) struct StreamedV3Inventory {
    context: ForwardV3Context,
    regular_hard_links: RegularHardLinkTopology,
    regular_xattrs: RegularXattrTopology,
    manifest: HeldTreeFingerprint,
}

#[derive(Debug)]
enum TraversalSinkError<E> {
    Tree(HeldTreeError),
    Emit(E),
}

impl<E> From<HeldTreeError> for TraversalSinkError<E> {
    fn from(error: HeldTreeError) -> Self {
        Self::Tree(error)
    }
}

#[derive(Debug)]
pub(crate) enum HeldTreeV3CollectError<E> {
    Tree(HeldTreeError),
    Codec(ManifestV3CodecError),
    Emit(E),
}

/// Post-seal-only v3 traversal state. Records have been admitted, budgeted,
/// emitted to the caller's authority-neutral sink, and root-bound without
/// retaining a resident manifest. Regular paths have not yet received their
/// final metadata and xattr reobservation. It carries no WAL or scratch-file
/// authority.
pub(crate) struct PendingV3Inventory {
    context: ForwardV3Context,
    entry_count: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct HardlinkScratchObservation<'a> {
    pub(crate) path: &'a [u8],
    observation: RegularFileObservation,
}

struct StreamedRegularGroup {
    first_path: PathBuf,
    observation: RegularFileObservation,
    enumerated: u64,
}

/// Bounded fold state for identity-sorted private hardlink scratch. Only the
/// current group and deterministic error candidates remain resident.
pub(crate) struct HardlinkTopologyFold {
    current: Option<StreamedRegularGroup>,
    current_identity: Option<NodeIdentity>,
    first_mismatch: Option<(PathBuf, PathBuf)>,
    first_count_failure: Option<(PathBuf, bool)>,
    topology: RegularHardLinkTopology,
}

/// Owned fold state for authenticated sorted manifest records. Directory
/// evidence is limited to the current ancestor chain; every final regular
/// observation is emitted immediately to authority-neutral identity scratch.
pub(crate) struct PendingV3Finalizer {
    context: ForwardV3Context,
    expected_manifest: HeldTreeFingerprint,
    observed_entries: u64,
    active_directories: Vec<DirectoryEvidence>,
    hardlink_record: Vec<u8>,
    regular_xattrs: RegularXattrTopology,
}

fn validate_v2_inputs(
    root_name: &OsStr,
    protected_names: &[OsString],
    limits: HeldTreeLimits,
) -> Result<(), HeldTreeError> {
    require_one_component(root_name)?;
    validate_policy(protected_names)?;
    if limits.max_directories > MAX_TREE_DIRECTORIES {
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
    manifest_schema: u16,
) -> Result<HeldTreeInventory, HeldTreeError> {
    let walked = traverse_v2::<ProveTraversal>(
        parent,
        root_name,
        protected_names,
        limits,
        ParentAdmission::CurrentExclusive,
        manifest_schema,
    )?;
    debug_assert_eq!(walked.manifest_schema, manifest_schema);
    inventory_from_proven_walk(walked)
}

fn inventory_from_proven_walk(
    walked: V2Walk<ProveTraversal>,
) -> Result<HeldTreeInventory, HeldTreeError> {
    let root = walked.root;
    let directories = walked
        .directories
        .into_iter()
        .map(|directory| directory.evidence)
        .collect::<Vec<_>>();
    let directory_index = build_directory_index(&directories)?;
    Ok(HeldTreeInventory {
        parent: walked.parent,
        root_name: walked.root_name,
        root_identity: walked.root_identity,
        backend: walked.backend,
        mount_id: walked.mount_id,
        protected_names: walked.protected_names,
        limits: walked.limits,
        manifest_schema: walked.manifest_schema,
        regular_hard_links: walked.regular_hard_links,
        regular_xattrs: walked.regular_xattrs,
        directory_index,
        directories,
        root,
        manifest: walked
            .entries
            .into_iter()
            .map(|entry| entry.manifest)
            .collect(),
    })
}

fn traverse_v2_with_sink<M: V2Traversal, E>(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    configuration: TraversalConfiguration,
    mut emit_entry: impl FnMut(&ManifestEntry) -> Result<(), E>,
) -> Result<V2Walk<M>, TraversalSinkError<E>> {
    validate_v2_inputs(root_name, &protected_names, limits)?;
    let backend = parent.backend();
    require_parent_admission(&parent, backend, configuration.parent_admission)?;
    let euid = rustix::process::geteuid().as_raw();
    let root_path = PathBuf::new();
    let inspected = with_fd(&parent, |fd| inspect_at(fd, root_name, &root_path))?;
    if inspected.identity.kind != NodeKind::Directory {
        return Err(HeldTreeError::RootNotDirectory.into());
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
        return Err(HeldTreeError::BackendBoundary(root_path).into());
    }
    let root_identity = opened.identity;
    let parent_mount_id = held.mount_id();
    let root_entry = M::make_root(opened);
    let mut budget = Budget::new(limits, configuration.manifest_schema);
    budget.add_path(M::path(&root_entry), 0)?;
    budget.add_directory()?;
    if let Some(entry) = M::manifest_entry(&root_entry) {
        emit_entry(entry).map_err(TraversalSinkError::Emit)?;
    }
    let root = HeldDirectory::new(held, PathBuf::new(), 0, root_identity);
    let root_evidence = root.evidence.clone();
    let mut directory_index = BTreeMap::new();
    directory_index.insert(PathBuf::new(), root_evidence.clone());
    let mut walked = V2Walk::<M> {
        parent,
        root_name: root_name.to_os_string(),
        root_identity,
        root,
        backend,
        mount_id: parent_mount_id,
        protected_names,
        limits,
        manifest_schema: configuration.manifest_schema,
        directory_index,
        directories: vec![WalkDirectory {
            evidence: root_evidence,
        }],
        entries: if configuration.retain_entries {
            vec![root_entry]
        } else {
            Vec::new()
        },
        budget,
        regular_hard_links: RegularHardLinkTopology::default(),
        regular_xattrs: RegularXattrTopology::default(),
    };
    let mut index = 0;
    while index < walked.directories.len() {
        read_v2_children_with_sink::<M, E>(
            &mut walked,
            index,
            configuration.retain_entries,
            &mut emit_entry,
        )?;
        index += 1;
    }
    walked
        .entries
        .sort_unstable_by(|left, right| M::path(left).cmp(M::path(right)));
    require_parent_admission(
        &walked.parent,
        walked.backend,
        configuration.parent_admission,
    )?;
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
        return Err(HeldTreeError::RootBindingChanged.into());
    }
    Ok(walked)
}

fn traverse_v2<M: V2Traversal>(
    parent: HeldLocalBackendEvidence,
    root_name: &OsStr,
    protected_names: Vec<OsString>,
    limits: HeldTreeLimits,
    parent_admission: ParentAdmission,
    manifest_schema: u16,
) -> Result<V2Walk<M>, HeldTreeError> {
    let walked = match traverse_v2_with_sink::<M, std::convert::Infallible>(
        parent,
        root_name,
        protected_names,
        limits,
        TraversalConfiguration {
            parent_admission,
            manifest_schema,
            retain_entries: true,
        },
        |_| Ok(()),
    ) {
        Ok(walked) => walked,
        Err(TraversalSinkError::Tree(error)) => return Err(error),
        Err(TraversalSinkError::Emit(never)) => match never {},
    };
    finalize_v2_walk(walked)
}

fn finalize_v2_walk<M: V2Traversal>(mut walked: V2Walk<M>) -> Result<V2Walk<M>, HeldTreeError> {
    fire_final_regular_reobservation_test_hook();
    let regular_files = final_reobserve_regular_files(&walked)?;
    // A same-UID writer can still create an alias after a path's final check.
    // Without retaining one FD per inode or excluding that writer, this is the
    // narrow residual race; classification deliberately uses the last bounded
    // no-follow observations rather than the earlier traversal snapshots.
    walked.regular_hard_links = classify_regular_file_topology(&regular_files)?;
    walked.regular_xattrs = summarize_regular_xattrs::<M>(&walked.entries)?;
    Ok(walked)
}

fn summarize_regular_xattrs<M: V2Traversal>(
    entries: &[M::Entry],
) -> Result<RegularXattrTopology, HeldTreeError> {
    let mut topology = RegularXattrTopology::default();
    for entry in entries {
        let Some(proof) = M::regular_xattr_proof(entry) else {
            continue;
        };
        if proof.is_empty() {
            continue;
        }
        topology.entries = topology
            .entries
            .checked_add(1)
            .ok_or_else(|| HeldTreeError::XattrsChangedDuringProof(M::path(entry).to_path_buf()))?;
        topology.attributes = topology
            .attributes
            .checked_add(proof.attribute_count)
            .ok_or_else(|| HeldTreeError::XattrsChangedDuringProof(M::path(entry).to_path_buf()))?;
        topology.value_bytes = topology
            .value_bytes
            .checked_add(proof.value_bytes)
            .ok_or_else(|| HeldTreeError::XattrsChangedDuringProof(M::path(entry).to_path_buf()))?;
    }
    Ok(topology)
}

#[derive(Clone, Copy)]
struct RegularFileReobservation<'a> {
    path: &'a Path,
    observation: RegularFileObservation,
}

#[derive(Clone, Copy)]
struct RegularFileGroup<'a> {
    first_path: &'a Path,
    observation: RegularFileObservation,
    enumerated: u64,
}

/// Reopen every recorded regular path from the retained root capability. This
/// pass is metadata-only: it neither charges content budget again nor reads file
/// bytes, and it retains only the bounded parent/file descriptors for one path.
fn final_reobserve_regular_files<'a, M: V2Traversal>(
    walked: &'a V2Walk<M>,
) -> Result<Vec<RegularFileReobservation<'a>>, HeldTreeError> {
    let mut regular_files = Vec::new();
    for entry in &walked.entries {
        let Some(recorded) = M::regular_observation(entry) else {
            continue;
        };
        let path = M::path(entry);
        let observation = final_reobserve_regular_record::<M>(walked, path, recorded)?;
        regular_files.push(RegularFileReobservation { path, observation });
    }
    Ok(regular_files)
}

/// Reopens and revalidates one recorded regular path. This is shared by the
/// resident legacy finalizer and the authenticated sorted-scratch finalizer;
/// neither path reads regular payload bytes or grants mutation authority.
struct RegularReopenContext<'a> {
    root: &'a HeldDirectory,
    parent: &'a HeldLocalBackendEvidence,
    root_name: &'a OsStr,
    root_identity: NodeIdentity,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    manifest_schema: u16,
    limits: HeldTreeLimits,
}

fn final_reobserve_regular_record<M: V2Traversal>(
    walked: &V2Walk<M>,
    path: &Path,
    recorded: RegularFileObservation,
) -> Result<RegularFileObservation, HeldTreeError> {
    let context = RegularReopenContext {
        root: &walked.root,
        parent: &walked.parent,
        root_name: &walked.root_name,
        root_identity: walked.root_identity,
        backend: walked.backend,
        mount_id: walked.mount_id,
        manifest_schema: walked.manifest_schema,
        limits: walked.limits,
    };
    final_reobserve_regular_record_with::<M>(
        &context,
        |candidate| walked.directory_index.get(candidate),
        path,
        recorded,
    )
}

fn final_reobserve_regular_record_from_context(
    context: &ForwardV3Context,
    active_directories: &[DirectoryEvidence],
    path: &Path,
    recorded: RegularFileObservation,
) -> Result<RegularFileObservation, HeldTreeError> {
    let reopen = RegularReopenContext {
        root: &context.root,
        parent: &context.parent,
        root_name: &context.root_name,
        root_identity: context.root_identity,
        backend: context.backend,
        mount_id: context.mount_id,
        manifest_schema: CONTENT_PROOF_VERSION,
        limits: context.limits,
    };
    final_reobserve_regular_record_with::<ProveTraversal>(
        &reopen,
        |candidate| {
            active_directories
                .iter()
                .find(|directory| directory.relative_path == candidate)
        },
        path,
        recorded,
    )
}

fn final_reobserve_regular_record_with<'e, M: V2Traversal>(
    context: &RegularReopenContext<'_>,
    directory_evidence: impl Fn(&Path) -> Option<&'e DirectoryEvidence>,
    path: &Path,
    recorded: RegularFileObservation,
) -> Result<RegularFileObservation, HeldTreeError> {
    let euid = rustix::process::geteuid().as_raw();
    let parent_path = path
        .parent()
        .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(path.to_path_buf()))?;
    let name = path
        .file_name()
        .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(path.to_path_buf()))?;
    let reopened = reopen_directory_from_root(
        context.root,
        parent_path,
        |candidate| directory_evidence(candidate),
        context.backend,
        context.mount_id,
        || {
            verify_root_binding_fields(
                context.parent,
                context.root_name,
                context.root_identity,
                context.mount_id,
                context.backend,
            )
        },
        false,
    )?;
    let parent = reopened.held();

    let before = with_fd(parent, |fd| inspect_at(fd, name, path))?;
    require_owner(path, before.uid, euid)?;
    require_boundary(path, context.backend, context.mount_id, &before)?;
    if before.regular_file_observation(recorded.sha256, recorded.xattrs) != Some(recorded) {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }

    let fd = with_fd(parent, |parent_fd| {
        rustix::fs::openat(
            parent_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })
    .map_err(|error| io_error(path, error))?;
    let fresh_backend = crate::backend::certify_held_fd_backend(&fd).map_err(|reason| {
        HeldTreeError::Certification {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    if fresh_backend != context.backend {
        return Err(HeldTreeError::BackendBoundary(path.to_path_buf()));
    }
    let opened_xattrs = M::reobserve_regular_xattrs(
        &fd,
        path,
        context.manifest_schema,
        recorded.xattrs,
        context.limits.max_xattr_bytes,
    )?;
    if opened_xattrs != recorded.xattrs {
        return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()));
    }
    let opened = inspect_raw_fd(&fd, fresh_backend, path)?;
    require_owner(path, opened.uid, euid)?;
    require_boundary(path, context.backend, context.mount_id, &opened)?;
    if opened.regular_file_observation(recorded.sha256, recorded.xattrs) != Some(recorded) {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }

    let final_xattrs = M::reobserve_regular_xattrs(
        &fd,
        path,
        context.manifest_schema,
        recorded.xattrs,
        context.limits.max_xattr_bytes,
    )?;
    if final_xattrs != recorded.xattrs {
        return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()));
    }
    let final_fd = inspect_raw_fd(&fd, fresh_backend, path)?;
    require_owner(path, final_fd.uid, euid)?;
    require_boundary(path, context.backend, context.mount_id, &final_fd)?;
    let final_observation = final_fd
        .regular_file_observation(recorded.sha256, recorded.xattrs)
        .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(path.to_path_buf()))?;
    if final_observation != recorded {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }

    let rebound = with_fd(parent, |parent_fd| inspect_at(parent_fd, name, path))?;
    require_owner(path, rebound.uid, euid)?;
    require_boundary(path, context.backend, context.mount_id, &rebound)?;
    if rebound.regular_file_observation(recorded.sha256, recorded.xattrs) != Some(final_observation)
    {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(final_observation)
}

/// Classify topology only after traversal, budget enforcement, source-parent
/// revalidation, root-binding revalidation, and deterministic path sorting are
/// complete. The existing strong identity is sufficient as the group key:
/// every entry has already been confined to one certified backend and mount,
/// while `NodeIdentity` binds device, inode, incarnation, and regular-file kind.
fn classify_regular_file_topology(
    regular_files: &[RegularFileReobservation<'_>],
) -> Result<RegularHardLinkTopology, HeldTreeError> {
    // This holds at most one fixed-size, data-only value per already-budgeted
    // entry and borrows its representative path from the bounded entry vector.
    let mut groups = BTreeMap::<NodeIdentity, RegularFileGroup<'_>>::new();
    for regular in regular_files {
        let observation = regular.observation;
        let path = regular.path;
        match groups.entry(observation.identity) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(RegularFileGroup {
                    first_path: path,
                    observation,
                    enumerated: 1,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let group = slot.get_mut();
                if group.observation != observation {
                    return Err(HeldTreeError::ContentChangedDuringHash(
                        group.first_path.to_path_buf(),
                    ));
                }
                group.enumerated = group.enumerated.checked_add(1).ok_or_else(|| {
                    HeldTreeError::ContentChangedDuringHash(group.first_path.to_path_buf())
                })?;
            }
        }
    }

    // Entries are path-sorted, so this preserves deterministic error selection
    // without changing manifest ordering or retaining any per-inode descriptor.
    let mut topology = RegularHardLinkTopology::default();
    for regular in regular_files {
        let observation = regular.observation;
        let group = groups
            .get(&observation.identity)
            .expect("every regular observation was grouped");
        match group.enumerated.cmp(&observation.nlink) {
            std::cmp::Ordering::Equal if group.enumerated == 1 => {}
            std::cmp::Ordering::Equal => {
                // Count each complete internal group once, while retaining only
                // aggregate data in the inventory/assessment boundary.
                if regular.path == group.first_path {
                    topology.multi_link_groups =
                        topology.multi_link_groups.checked_add(1).ok_or_else(|| {
                            HeldTreeError::ContentChangedDuringHash(group.first_path.to_path_buf())
                        })?;
                    topology.linked_entries = topology
                        .linked_entries
                        .checked_add(group.enumerated)
                        .ok_or_else(|| {
                            HeldTreeError::ContentChangedDuringHash(group.first_path.to_path_buf())
                        })?;
                }
            }
            std::cmp::Ordering::Less => {
                return Err(HeldTreeError::ExternalOrUnenumeratedHardLink(
                    group.first_path.to_path_buf(),
                ));
            }
            std::cmp::Ordering::Greater => {
                return Err(HeldTreeError::ContentChangedDuringHash(
                    group.first_path.to_path_buf(),
                ));
            }
        }
    }
    Ok(topology)
}

fn read_v2_children_with_sink<M: V2Traversal, E>(
    walked: &mut V2Walk<M>,
    index: usize,
    retain_entries: bool,
    emit_entry: &mut impl FnMut(&ManifestEntry) -> Result<(), E>,
) -> Result<(), TraversalSinkError<E>> {
    let parent_path = walked.directories[index].evidence.relative_path.clone();
    let parent_depth = walked.directories[index].evidence.depth;
    let reopened = if index == 0 {
        require_directory_current(&walked.root, walked.backend, walked.mount_id)?;
        ReopenedDirectory {
            held: ReopenedHeldDirectory::Root(&walked.root.held),
        }
    } else {
        reopen_directory_from_root(
            &walked.root,
            &parent_path,
            |path| walked.directory_index.get(path),
            walked.backend,
            walked.mount_id,
            || {
                verify_root_binding_fields(
                    &walked.parent,
                    &walked.root_name,
                    walked.root_identity,
                    walked.mount_id,
                    walked.backend,
                )
            },
            false,
        )?
    };
    let parent = reopened.held();
    let fresh = with_fd(parent, |fd| {
        rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
    })
    .map_err(|error| io_error(&parent_path, error))?;
    let entries = Dir::new(fresh).map_err(|error| io_error(&parent_path, error))?;
    let mut new_entries = Vec::new();
    let mut new_directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(&parent_path, error))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        let path = parent_path.join(name);
        require_unprotected(&walked.protected_names, name, &path)?;
        let inspected = with_fd(parent, |fd| inspect_at(fd, name, &path))?;
        require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
        require_boundary(&path, walked.backend, walked.mount_id, &inspected)?;
        let depth = parent_depth.saturating_add(1);
        let child = if inspected.identity.kind == NodeKind::Directory {
            let fd = with_fd(parent, |parent_fd| {
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
                return Err(HeldTreeError::BackendBoundary(path).into());
            }
            Some(held)
        } else {
            None
        };
        let result = M::inspect_entry(
            parent,
            name,
            &path,
            &inspected,
            &mut walked.budget,
            walked.manifest_schema,
        )?;
        if M::regular_observation(&result).is_some() {
            fire_regular_link_observation_test_hook(&path);
        }
        walked.budget.add_path(M::path(&result), depth)?;
        if child.is_some() {
            walked.budget.add_directory()?;
        }
        if let Some(entry) = M::manifest_entry(&result) {
            emit_entry(entry).map_err(TraversalSinkError::Emit)?;
        }
        let directory_identity = M::identity(&result);
        if retain_entries {
            new_entries.push(result);
        }
        if let Some(held) = child {
            let evidence = DirectoryEvidence {
                relative_path: path,
                depth,
                identity: directory_identity,
                owner_uid: held.owner_uid(),
                group_gid: held.group_gid(),
                observed_mode: held.mode(),
            };
            drop(held);
            new_directories.push(WalkDirectory { evidence });
        }
    }
    drop(reopened);
    walked.entries.extend(new_entries);
    for directory in new_directories {
        let path = directory.evidence.relative_path.clone();
        if walked
            .directory_index
            .insert(path.clone(), directory.evidence.clone())
            .is_some()
        {
            return Err(HeldTreeError::IdentityChanged(path).into());
        }
        walked.directories.push(directory);
    }
    Ok(())
}

fn emit_forward_v3_record<E>(
    entry: &ManifestEntry,
    record: &mut Vec<u8>,
    emit_record: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), HeldTreeV3CollectError<E>> {
    let record_len = manifest_entry_v3_len(entry).map_err(HeldTreeV3CollectError::Codec)?;
    if record_len > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
        return Err(HeldTreeV3CollectError::Codec(
            ManifestV3CodecError::RecordTooLarge,
        ));
    }
    record.clear();
    emit_manifest_entry_v3(entry, |bytes| record.extend_from_slice(bytes));
    debug_assert_eq!(record.len(), record_len);
    emit_record(record).map_err(HeldTreeV3CollectError::Emit)
}

struct ForwardV3TraversalState<'a> {
    backend: CertifiedLocalBackend,
    mount_id: u64,
    protected_names: &'a [OsString],
    budget: &'a mut Budget,
    record: &'a mut Vec<u8>,
}

fn duplicate_held_directory(
    held: &HeldLocalBackendEvidence,
    path: &Path,
) -> Result<HeldLocalBackendEvidence, HeldTreeError> {
    let fd = with_fd(held, |fd| {
        rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
    })
    .map_err(|error| io_error(path, error))?;
    certify_held_fd(fd).map_err(|reason| HeldTreeError::Certification {
        path: path.to_path_buf(),
        reason,
    })
}

fn certify_directory_stream(
    stream: &Dir,
    path: &Path,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<HeldLocalBackendEvidence, HeldTreeError> {
    let fd = stream
        .fd()
        .and_then(rustix::io::dup)
        .map_err(|error| io_error(path, error))?;
    let held = certify_held_fd(fd).map_err(|reason| HeldTreeError::Certification {
        path: path.to_path_buf(),
        reason,
    })?;
    if held.backend() != backend || held.mount_id() != mount_id {
        return Err(HeldTreeError::BackendBoundary(path.to_path_buf()));
    }
    Ok(held)
}

fn traverse_forward_v3_directory<E>(
    directory: HeldLocalBackendEvidence,
    relative_path: &Path,
    depth: u32,
    state: &mut ForwardV3TraversalState<'_>,
    emit_record: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), HeldTreeV3CollectError<E>> {
    let mut entries = Dir::new(directory.into_authority_fd())
        .map_err(|error| HeldTreeV3CollectError::Tree(io_error(relative_path, error)))?;
    let mut parent =
        certify_directory_stream(&entries, relative_path, state.backend, state.mount_id)
            .map_err(HeldTreeV3CollectError::Tree)?;
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|error| HeldTreeV3CollectError::Tree(io_error(relative_path, error)))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        let path = relative_path.join(name);
        require_unprotected(state.protected_names, name, &path)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let inspected = with_fd(&parent, |fd| inspect_at(fd, name, &path))
            .map_err(HeldTreeV3CollectError::Tree)?;
        require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())
            .map_err(HeldTreeV3CollectError::Tree)?;
        require_boundary(&path, state.backend, state.mount_id, &inspected)
            .map_err(HeldTreeV3CollectError::Tree)?;

        let child = if inspected.identity.kind == NodeKind::Directory {
            let fd = with_fd(&parent, |parent_fd| {
                rustix::fs::openat(parent_fd, name, OPEN_DIRECTORY, Mode::empty())
            })
            .map_err(|error| HeldTreeV3CollectError::Tree(io_error(&path, error)))?;
            let child = certify_held_fd(fd).map_err(|reason| {
                HeldTreeV3CollectError::Tree(HeldTreeError::Certification {
                    path: path.clone(),
                    reason,
                })
            })?;
            let opened = inspect_held(&child, &path).map_err(HeldTreeV3CollectError::Tree)?;
            require_same_identity(&path, inspected.identity, opened.identity)
                .map_err(HeldTreeV3CollectError::Tree)?;
            require_owner(&path, opened.uid, rustix::process::geteuid().as_raw())
                .map_err(HeldTreeV3CollectError::Tree)?;
            require_boundary(&path, state.backend, state.mount_id, &opened)
                .map_err(HeldTreeV3CollectError::Tree)?;
            if !inspected.stable_content_fields_equal(&opened) {
                return Err(HeldTreeV3CollectError::Tree(
                    HeldTreeError::IdentityChanged(path),
                ));
            }
            Some(child)
        } else {
            None
        };

        let proved = ProveTraversal::inspect_entry(
            &parent,
            name,
            &path,
            &inspected,
            state.budget,
            CONTENT_PROOF_VERSION,
        )
        .map_err(HeldTreeV3CollectError::Tree)?;
        if proved.regular.is_some() {
            fire_regular_link_observation_test_hook(&path);
        }
        let child_depth = depth.saturating_add(1);
        state
            .budget
            .add_path(&proved.manifest.path, child_depth)
            .map_err(HeldTreeV3CollectError::Tree)?;
        if child.is_some() {
            state
                .budget
                .add_directory()
                .map_err(HeldTreeV3CollectError::Tree)?;
        }
        emit_forward_v3_record(&proved.manifest, state.record, emit_record)?;
        if let Some(child) = child {
            drop(entry);
            drop(parent);
            traverse_forward_v3_directory(
                child,
                &proved.manifest.path,
                child_depth,
                state,
                emit_record,
            )?;
            parent =
                certify_directory_stream(&entries, relative_path, state.backend, state.mount_id)
                    .map_err(HeldTreeV3CollectError::Tree)?;
        }
    }
    Ok(())
}

impl PendingV3Inventory {
    /// Traverses production schema v3 depth-first, retaining only the certified
    /// root and the active descriptor stack. Records may arrive in filesystem
    /// enumeration order; unpublished scratch owns canonical sorting.
    pub(crate) fn collect<E>(
        parent: HeldLocalBackendEvidence,
        root_name: &OsStr,
        protected_names: Vec<OsString>,
        limits: HeldTreeLimits,
        mut emit_record: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Self, HeldTreeV3CollectError<E>> {
        validate_v2_inputs(root_name, &protected_names, limits)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let backend = parent.backend();
        require_parent_admission(&parent, backend, ParentAdmission::CurrentExclusive)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let root_path = PathBuf::new();
        let inspected = with_fd(&parent, |fd| inspect_at(fd, root_name, &root_path))
            .map_err(HeldTreeV3CollectError::Tree)?;
        if inspected.identity.kind != NodeKind::Directory {
            return Err(HeldTreeV3CollectError::Tree(
                HeldTreeError::RootNotDirectory,
            ));
        }
        require_owner(
            &root_path,
            inspected.uid,
            rustix::process::geteuid().as_raw(),
        )
        .map_err(HeldTreeV3CollectError::Tree)?;
        require_boundary(&root_path, backend, parent.mount_id(), &inspected)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let fd = with_fd(&parent, |parent_fd| {
            rustix::fs::openat(parent_fd, root_name, OPEN_DIRECTORY, Mode::empty())
        })
        .map_err(|error| HeldTreeV3CollectError::Tree(io_error(&root_path, error)))?;
        let held = certify_held_fd(fd).map_err(|reason| {
            HeldTreeV3CollectError::Tree(HeldTreeError::Certification {
                path: root_path.clone(),
                reason,
            })
        })?;
        let opened = inspect_held(&held, &root_path).map_err(HeldTreeV3CollectError::Tree)?;
        require_same_identity(&root_path, inspected.identity, opened.identity)
            .map_err(HeldTreeV3CollectError::Tree)?;
        require_owner(&root_path, opened.uid, rustix::process::geteuid().as_raw())
            .map_err(HeldTreeV3CollectError::Tree)?;
        if held.backend() != backend || held.mount_id() != parent.mount_id() {
            return Err(HeldTreeV3CollectError::Tree(
                HeldTreeError::BackendBoundary(root_path),
            ));
        }
        let root_identity = opened.identity;
        let root_entry = ProveTraversal::make_root(opened);
        let mut budget = Budget::new(limits, CONTENT_PROOF_VERSION);
        budget
            .add_path(&root_entry.manifest.path, 0)
            .and_then(|()| budget.add_directory())
            .map_err(HeldTreeV3CollectError::Tree)?;
        let root = HeldDirectory::new(held, PathBuf::new(), 0, root_identity);
        let mount_id = root.held.mount_id();
        let mut record = Vec::with_capacity(MANIFEST_V3_MAX_SEGMENT_PAYLOAD);
        emit_forward_v3_record(&root_entry.manifest, &mut record, &mut emit_record)?;
        {
            let mut traversal = ForwardV3TraversalState {
                backend,
                mount_id,
                protected_names: &protected_names,
                budget: &mut budget,
                record: &mut record,
            };
            let root_stream = duplicate_held_directory(&root.held, Path::new(""))
                .map_err(HeldTreeV3CollectError::Tree)?;
            traverse_forward_v3_directory(
                root_stream,
                Path::new(""),
                0,
                &mut traversal,
                &mut emit_record,
            )?;
        }
        require_parent_admission(&parent, backend, ParentAdmission::CurrentExclusive)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let rebound = with_fd(&parent, |fd| inspect_at(fd, root_name, Path::new("")))
            .map_err(|_| HeldTreeV3CollectError::Tree(HeldTreeError::RootBindingChanged))?;
        if !root_binding_matches(root_identity, mount_id, backend, &rebound) {
            return Err(HeldTreeV3CollectError::Tree(
                HeldTreeError::RootBindingChanged,
            ));
        }
        Ok(Self {
            context: ForwardV3Context {
                parent,
                root_name: root_name.to_os_string(),
                root_identity,
                root,
                backend,
                mount_id,
                protected_names,
                limits,
            },
            entry_count: budget.entries,
        })
    }

    pub(crate) fn entry_count(&self) -> u64 {
        self.entry_count
    }

    #[cfg(test)]
    pub(crate) fn resident_manifest_entries_for_test(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(crate) fn resident_directory_entries_for_test(&self) -> usize {
        0
    }

    pub(crate) fn into_finalizer(
        self,
        expected_manifest: DurableTreeManifest,
    ) -> Result<PendingV3Finalizer, HeldTreeError> {
        if self.entry_count != expected_manifest.entry_count {
            return Err(HeldTreeError::PostChanged(PathBuf::new()));
        }
        fire_final_regular_reobservation_test_hook();
        Ok(PendingV3Finalizer {
            expected_manifest: HeldTreeFingerprint {
                schema_version: expected_manifest.schema_version,
                entry_count: expected_manifest.entry_count,
                sha256: expected_manifest.sha256,
            },
            context: self.context,
            observed_entries: 0,
            active_directories: Vec::new(),
            hardlink_record: Vec::with_capacity(MANIFEST_V3_MAX_SEGMENT_PAYLOAD),
            regular_xattrs: RegularXattrTopology::default(),
        })
    }
}

fn path_is_beneath(directory: &Path, path: &Path) -> bool {
    if directory.as_os_str().is_empty() {
        return !path.as_os_str().is_empty();
    }
    path.strip_prefix(directory)
        .is_ok_and(|suffix| suffix.components().count() > 0)
}

impl PendingV3Finalizer {
    /// Reobserves one typed canonical record and emits every final regular-file
    /// observation directly to identity-sorted private scratch.
    pub(crate) fn observe<E>(
        &mut self,
        record: ManifestV3Record<'_>,
        emit_hardlink: &mut dyn FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), HeldTreeV3CollectError<E>> {
        self.observe_with_directory_mode(record, None, emit_hardlink)
    }

    /// Recovery may verify a tree after its durable inverse modes were already
    /// applied. The authenticated record retains the sealed manifest mode, while
    /// reopen evidence must use the freshly checked current mode. Forward and
    /// pre-inverse callers pass `None` and therefore retain the byte-identical
    /// sealed-mode behavior.
    pub(crate) fn observe_with_directory_mode<E>(
        &mut self,
        record: ManifestV3Record<'_>,
        observed_directory_mode: Option<u32>,
        emit_hardlink: &mut dyn FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), HeldTreeV3CollectError<E>> {
        self.observed_entries =
            self.observed_entries
                .checked_add(1)
                .ok_or(HeldTreeV3CollectError::Tree(HeldTreeError::Limit {
                    kind: HeldTreeLimit::Entries,
                    limit: self.context.limits.max_entries,
                }))?;
        let path = Path::new(OsStr::from_bytes(record.path));
        while self
            .active_directories
            .last()
            .is_some_and(|directory| !path_is_beneath(&directory.relative_path, path))
        {
            self.active_directories.pop();
        }

        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        if !path.as_os_str().is_empty()
            && self
                .active_directories
                .last()
                .is_none_or(|directory| directory.relative_path != parent)
        {
            return Err(HeldTreeV3CollectError::Tree(HeldTreeError::PostChanged(
                path.to_path_buf(),
            )));
        }

        if record.kind == ManifestV3RecordKind::Directory {
            let evidence = DirectoryEvidence {
                relative_path: path.to_path_buf(),
                depth: u32::try_from(path.components().count()).map_err(|_| {
                    HeldTreeV3CollectError::Tree(HeldTreeError::Limit {
                        kind: HeldTreeLimit::Depth,
                        limit: u64::from(self.context.limits.max_depth),
                    })
                })?,
                identity: NodeIdentity {
                    kind: NodeKind::Directory,
                    device: record.device,
                    inode: record.inode,
                    incarnation: record.incarnation,
                },
                owner_uid: record.uid,
                group_gid: record.gid,
                observed_mode: observed_directory_mode.unwrap_or(record.mode),
            };
            if path.as_os_str().is_empty() && evidence != self.context.root.evidence {
                return Err(HeldTreeV3CollectError::Tree(HeldTreeError::PostChanged(
                    PathBuf::new(),
                )));
            }
            self.active_directories.push(evidence);
            return Ok(());
        }

        let ManifestV3RecordContent::Regular {
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            sha256,
            xattr_count,
            xattr_value_bytes,
            xattr_sha256,
        } = record.content
        else {
            return Ok(());
        };
        let xattrs = RegularXattrProof {
            attribute_count: xattr_count,
            value_bytes: xattr_value_bytes,
            sha256: xattr_sha256,
        };
        let recorded = RegularFileObservation {
            identity: NodeIdentity {
                kind: NodeKind::Regular,
                device: record.device,
                inode: record.inode,
                incarnation: record.incarnation,
            },
            uid: record.uid,
            gid: record.gid,
            mode: record.mode,
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            sha256: Some(sha256),
            xattrs,
        };
        let observation = final_reobserve_regular_record_from_context(
            &self.context,
            &self.active_directories,
            path,
            recorded,
        )
        .map_err(HeldTreeV3CollectError::Tree)?;
        if !xattrs.is_empty() {
            self.regular_xattrs.entries =
                self.regular_xattrs.entries.checked_add(1).ok_or_else(|| {
                    HeldTreeV3CollectError::Tree(HeldTreeError::XattrsChangedDuringProof(
                        path.to_path_buf(),
                    ))
                })?;
            self.regular_xattrs.attributes = self
                .regular_xattrs
                .attributes
                .checked_add(xattrs.attribute_count)
                .ok_or_else(|| {
                    HeldTreeV3CollectError::Tree(HeldTreeError::XattrsChangedDuringProof(
                        path.to_path_buf(),
                    ))
                })?;
            self.regular_xattrs.value_bytes = self
                .regular_xattrs
                .value_bytes
                .checked_add(xattrs.value_bytes)
                .ok_or_else(|| {
                    HeldTreeV3CollectError::Tree(HeldTreeError::XattrsChangedDuringProof(
                        path.to_path_buf(),
                    ))
                })?;
        }
        encode_hardlink_scratch_record(path, observation, &mut self.hardlink_record)
            .map_err(HeldTreeV3CollectError::Codec)?;
        emit_hardlink(&self.hardlink_record).map_err(HeldTreeV3CollectError::Emit)
    }

    pub(crate) fn finish(
        self,
        authenticated: AuthenticatedTreeManifest,
        regular_hard_links: RegularHardLinkTopology,
    ) -> Result<StreamedV3Inventory, HeldTreeError> {
        let authenticated = authenticated.manifest();
        if authenticated.schema_version != self.expected_manifest.schema_version
            || authenticated.entry_count != self.expected_manifest.entry_count
            || authenticated.sha256 != self.expected_manifest.sha256
            || self.observed_entries != self.expected_manifest.entry_count
        {
            return Err(HeldTreeError::PostChanged(PathBuf::new()));
        }
        Ok(StreamedV3Inventory {
            context: self.context,
            regular_hard_links,
            regular_xattrs: self.regular_xattrs,
            manifest: self.expected_manifest,
        })
    }
}

impl HardlinkTopologyFold {
    pub(crate) fn new() -> Self {
        Self {
            current: None,
            current_identity: None,
            first_mismatch: None,
            first_count_failure: None,
            topology: RegularHardLinkTopology::default(),
        }
    }

    pub(crate) fn observe(
        &mut self,
        record: HardlinkScratchObservation<'_>,
    ) -> Result<(), HeldTreeError> {
        let identity = record.observation.identity;
        if self.current_identity != Some(identity) {
            self.finish_current()?;
            self.current_identity = Some(identity);
            self.current = Some(StreamedRegularGroup {
                first_path: Path::new(OsStr::from_bytes(record.path)).to_path_buf(),
                observation: record.observation,
                enumerated: 1,
            });
            return Ok(());
        }
        let group = self.current.as_mut().expect("identity has a current group");
        if group.observation != record.observation {
            let detection = Path::new(OsStr::from_bytes(record.path)).to_path_buf();
            if self
                .first_mismatch
                .as_ref()
                .is_none_or(|(current, _)| detection < *current)
            {
                self.first_mismatch = Some((detection, group.first_path.clone()));
            }
        }
        group.enumerated = group
            .enumerated
            .checked_add(1)
            .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(group.first_path.clone()))?;
        Ok(())
    }

    fn finish_current(&mut self) -> Result<(), HeldTreeError> {
        let Some(group) = self.current.take() else {
            return Ok(());
        };
        match group.enumerated.cmp(&group.observation.nlink) {
            std::cmp::Ordering::Equal if group.enumerated == 1 => {}
            std::cmp::Ordering::Equal => {
                self.topology.multi_link_groups = self
                    .topology
                    .multi_link_groups
                    .checked_add(1)
                    .ok_or_else(|| {
                        HeldTreeError::ContentChangedDuringHash(group.first_path.clone())
                    })?;
                self.topology.linked_entries = self
                    .topology
                    .linked_entries
                    .checked_add(group.enumerated)
                    .ok_or_else(|| {
                        HeldTreeError::ContentChangedDuringHash(group.first_path.clone())
                    })?;
            }
            ordering => {
                let external = ordering == std::cmp::Ordering::Less;
                if self
                    .first_count_failure
                    .as_ref()
                    .is_none_or(|(path, _)| group.first_path < *path)
                {
                    self.first_count_failure = Some((group.first_path, external));
                }
            }
        }
        self.current_identity = None;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<RegularHardLinkTopology, HeldTreeError> {
        self.finish_current()?;
        if let Some((_, path)) = self.first_mismatch {
            return Err(HeldTreeError::ContentChangedDuringHash(path));
        }
        if let Some((path, true)) = self.first_count_failure {
            return Err(HeldTreeError::ExternalOrUnenumeratedHardLink(path));
        }
        if let Some((path, false)) = self.first_count_failure {
            return Err(HeldTreeError::ContentChangedDuringHash(path));
        }
        Ok(self.topology)
    }
}

fn traverse_forward_structure_directory<E>(
    directory: HeldLocalBackendEvidence,
    relative_path: &Path,
    depth: u32,
    context: &ForwardV3Context,
    budget: &mut Budget,
    encoded: &mut Vec<u8>,
    emit_record: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), HeldTreeV3CollectError<E>> {
    let mut entries = Dir::new(directory.into_authority_fd())
        .map_err(|error| HeldTreeV3CollectError::Tree(io_error(relative_path, error)))?;
    let mut parent =
        certify_directory_stream(&entries, relative_path, context.backend, context.mount_id)
            .map_err(HeldTreeV3CollectError::Tree)?;
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|error| HeldTreeV3CollectError::Tree(io_error(relative_path, error)))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        let path = relative_path.join(name);
        require_unprotected(&context.protected_names, name, &path)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let inspected = with_fd(&parent, |fd| inspect_at(fd, name, &path))
            .map_err(HeldTreeV3CollectError::Tree)?;
        require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())
            .map_err(HeldTreeV3CollectError::Tree)?;
        require_boundary(&path, context.backend, context.mount_id, &inspected)
            .map_err(HeldTreeV3CollectError::Tree)?;
        let child = if inspected.identity.kind == NodeKind::Directory {
            let fd = with_fd(&parent, |parent_fd| {
                rustix::fs::openat(parent_fd, name, OPEN_DIRECTORY, Mode::empty())
            })
            .map_err(|error| HeldTreeV3CollectError::Tree(io_error(&path, error)))?;
            let child = certify_held_fd(fd).map_err(|reason| {
                HeldTreeV3CollectError::Tree(HeldTreeError::Certification {
                    path: path.clone(),
                    reason,
                })
            })?;
            let opened = inspect_held(&child, &path).map_err(HeldTreeV3CollectError::Tree)?;
            require_same_identity(&path, inspected.identity, opened.identity)
                .map_err(HeldTreeV3CollectError::Tree)?;
            require_owner(&path, opened.uid, rustix::process::geteuid().as_raw())
                .map_err(HeldTreeV3CollectError::Tree)?;
            require_boundary(&path, context.backend, context.mount_id, &opened)
                .map_err(HeldTreeV3CollectError::Tree)?;
            if !inspected.stable_content_fields_equal(&opened) {
                return Err(HeldTreeV3CollectError::Tree(
                    HeldTreeError::IdentityChanged(path),
                ));
            }
            Some(child)
        } else {
            None
        };
        let value = if inspected.identity.kind == NodeKind::Symlink {
            let content = inspect_symlink_content(&parent, name, &path, &inspected, budget)
                .map_err(HeldTreeV3CollectError::Tree)?;
            inspected
                .clone()
                .into_manifest(path.clone(), content)
                .structure_evidence()
        } else {
            inspected
                .structure_evidence(path.clone(), CONTENT_PROOF_VERSION)
                .map_err(HeldTreeV3CollectError::Tree)?
        };
        let child_depth = depth.saturating_add(1);
        budget
            .add_path(&value.path, child_depth)
            .map_err(HeldTreeV3CollectError::Tree)?;
        if child.is_some() {
            budget
                .add_directory()
                .map_err(HeldTreeV3CollectError::Tree)?;
        }
        emit_structure_record(&value, encoded, emit_record)?;
        if let Some(child) = child {
            drop(entry);
            drop(parent);
            traverse_forward_structure_directory(
                child,
                &value.path,
                child_depth,
                context,
                budget,
                encoded,
                emit_record,
            )?;
            parent = certify_directory_stream(
                &entries,
                relative_path,
                context.backend,
                context.mount_id,
            )
            .map_err(HeldTreeV3CollectError::Tree)?;
        }
    }
    Ok(())
}

impl StreamedV3Inventory {
    pub(crate) fn fingerprint(&self) -> HeldTreeFingerprint {
        self.manifest
    }

    pub(crate) fn regular_hard_link_topology(&self) -> RegularHardLinkTopology {
        self.regular_hard_links
    }

    pub(crate) fn regular_xattr_topology(&self) -> RegularXattrTopology {
        self.regular_xattrs
    }

    /// Reobserves the current tree depth-first and emits private structure
    /// records while retaining only the active descriptor chain.
    pub(crate) fn stream_structure_records<E>(
        &self,
        mut emit_record: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), HeldTreeV3CollectError<E>> {
        self.verify_root_binding()
            .map_err(HeldTreeV3CollectError::Tree)?;
        let mut budget = Budget::new(self.context.limits, CONTENT_PROOF_VERSION);
        let mut encoded = Vec::with_capacity(MANIFEST_V3_MAX_SEGMENT_PAYLOAD);
        let root = inspect_held(&self.context.root.held, Path::new(""))
            .map_err(HeldTreeV3CollectError::Tree)?
            .structure_evidence(PathBuf::new(), CONTENT_PROOF_VERSION)
            .map_err(HeldTreeV3CollectError::Tree)?;
        budget
            .add_path(&root.path, 0)
            .and_then(|()| budget.add_directory())
            .map_err(HeldTreeV3CollectError::Tree)?;
        emit_structure_record(&root, &mut encoded, &mut emit_record)?;
        let root_stream = duplicate_held_directory(&self.context.root.held, Path::new(""))
            .map_err(HeldTreeV3CollectError::Tree)?;
        traverse_forward_structure_directory(
            root_stream,
            Path::new(""),
            0,
            &self.context,
            &mut budget,
            &mut encoded,
            &mut emit_record,
        )?;
        self.verify_root_binding()
            .map_err(HeldTreeV3CollectError::Tree)
    }

    pub(crate) fn finish_streamed_structure_rewalk(&self) -> Result<(), HeldTreeError> {
        self.verify_root_binding()
    }

    fn verify_root_binding(&self) -> Result<(), HeldTreeError> {
        require_exclusive_parent(&self.context.parent, self.context.backend)?;
        verify_root_binding_fields(
            &self.context.parent,
            &self.context.root_name,
            self.context.root_identity,
            self.context.mount_id,
            self.context.backend,
        )
    }
}

const STRUCTURE_SCRATCH_RECORD_MAGIC: &[u8; 4] = b"DHS1";

pub(crate) fn hardlink_scratch_sentinel_record() -> &'static [u8] {
    &[0, 0, 0, 0, 0, 0, 0, 1, 0]
}

fn encode_hardlink_scratch_record(
    path: &Path,
    observation: RegularFileObservation,
    encoded: &mut Vec<u8>,
) -> Result<(), ManifestV3CodecError> {
    let path = path.as_os_str().as_bytes();
    let key_len = 25_usize
        .checked_add(path.len())
        .ok_or(ManifestV3CodecError::LengthOverflow)?;
    let record_len = 8_usize
        .checked_add(key_len)
        .and_then(|length| length.checked_add(132))
        .ok_or(ManifestV3CodecError::LengthOverflow)?;
    if record_len > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
        return Err(ManifestV3CodecError::RecordTooLarge);
    }
    let sha256 = observation
        .sha256
        .ok_or(ManifestV3CodecError::KindContentMismatch)?;
    encoded.clear();
    encoded.reserve(record_len);
    encoded.extend_from_slice(&(key_len as u64).to_be_bytes());
    encoded.push(1);
    encoded.extend_from_slice(&observation.identity.device.to_be_bytes());
    encoded.extend_from_slice(&observation.identity.inode.to_be_bytes());
    encoded.extend_from_slice(&observation.identity.incarnation.to_be_bytes());
    encoded.extend_from_slice(path);
    encoded.extend_from_slice(&observation.uid.to_be_bytes());
    encoded.extend_from_slice(&observation.gid.to_be_bytes());
    encoded.extend_from_slice(&observation.mode.to_be_bytes());
    encoded.extend_from_slice(&observation.size.to_be_bytes());
    encoded.extend_from_slice(&observation.nlink.to_be_bytes());
    encoded.extend_from_slice(&observation.mtime_sec.to_be_bytes());
    encoded.extend_from_slice(&observation.mtime_nsec.to_be_bytes());
    encoded.extend_from_slice(&observation.ctime_sec.to_be_bytes());
    encoded.extend_from_slice(&observation.ctime_nsec.to_be_bytes());
    encoded.extend_from_slice(&sha256);
    encoded.extend_from_slice(&observation.xattrs.attribute_count.to_be_bytes());
    encoded.extend_from_slice(&observation.xattrs.value_bytes.to_be_bytes());
    encoded.extend_from_slice(&observation.xattrs.sha256);
    debug_assert_eq!(encoded.len(), record_len);
    Ok(())
}

pub(crate) fn decode_hardlink_scratch_record(
    mut record: &[u8],
) -> Result<Option<HardlinkScratchObservation<'_>>, ManifestV3CodecError> {
    let key_len = usize::try_from(take_u64(&mut record)?)
        .map_err(|_| ManifestV3CodecError::LengthOverflow)?;
    let key = take(&mut record, key_len)?;
    if key == [0] {
        if record.is_empty() {
            return Ok(None);
        }
        return Err(ManifestV3CodecError::TrailingBytes);
    }
    if key.len() < 25 || key[0] != 1 {
        return Err(ManifestV3CodecError::InvalidPath);
    }
    let path = &key[25..];
    if path.is_empty() {
        return Err(ManifestV3CodecError::InvalidPath);
    }
    validate_manifest_path(path, HeldTreeLimits::default().max_depth)?;
    let identity = NodeIdentity {
        kind: NodeKind::Regular,
        device: u64::from_be_bytes(key[1..9].try_into().unwrap()),
        inode: u64::from_be_bytes(key[9..17].try_into().unwrap()),
        incarnation: u64::from_be_bytes(key[17..25].try_into().unwrap()),
    };
    let fields = take(&mut record, 132)?;
    if !record.is_empty() {
        return Err(ManifestV3CodecError::TrailingBytes);
    }
    let mode = u32::from_be_bytes(fields[8..12].try_into().unwrap());
    if mode & !0o7777 != 0 {
        return Err(ManifestV3CodecError::InvalidMode);
    }
    let mtime_nsec = u32::from_be_bytes(fields[36..40].try_into().unwrap());
    let ctime_nsec = u32::from_be_bytes(fields[48..52].try_into().unwrap());
    if mtime_nsec >= 1_000_000_000 || ctime_nsec >= 1_000_000_000 {
        return Err(ManifestV3CodecError::InvalidNanoseconds);
    }
    Ok(Some(HardlinkScratchObservation {
        path,
        observation: RegularFileObservation {
            identity,
            uid: u32::from_be_bytes(fields[0..4].try_into().unwrap()),
            gid: u32::from_be_bytes(fields[4..8].try_into().unwrap()),
            mode,
            size: u64::from_be_bytes(fields[12..20].try_into().unwrap()),
            nlink: u64::from_be_bytes(fields[20..28].try_into().unwrap()),
            mtime_sec: i64::from_be_bytes(fields[28..36].try_into().unwrap()),
            mtime_nsec,
            ctime_sec: i64::from_be_bytes(fields[40..48].try_into().unwrap()),
            ctime_nsec,
            sha256: Some(fields[52..84].try_into().unwrap()),
            xattrs: RegularXattrProof {
                attribute_count: u64::from_be_bytes(fields[84..92].try_into().unwrap()),
                value_bytes: u64::from_be_bytes(fields[92..100].try_into().unwrap()),
                sha256: fields[100..132].try_into().unwrap(),
            },
        },
    }))
}

fn emit_structure_record<E>(
    evidence: &StructureEvidence,
    encoded: &mut Vec<u8>,
    emit_record: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), HeldTreeV3CollectError<E>> {
    let path = evidence.path.as_os_str().as_bytes();
    let path_len = u64::try_from(path.len())
        .map_err(|_| HeldTreeV3CollectError::Codec(ManifestV3CodecError::LengthOverflow))?;
    encoded.clear();
    encoded.extend_from_slice(&path_len.to_be_bytes());
    encoded.extend_from_slice(path);
    encoded.extend_from_slice(STRUCTURE_SCRATCH_RECORD_MAGIC);
    encoded.push(match evidence.identity.kind {
        NodeKind::Directory => 0,
        NodeKind::Regular => 1,
        NodeKind::Symlink => 2,
        NodeKind::Other => 3,
    });
    encoded.extend_from_slice(&evidence.identity.device.to_be_bytes());
    encoded.extend_from_slice(&evidence.identity.inode.to_be_bytes());
    encoded.extend_from_slice(&evidence.identity.incarnation.to_be_bytes());
    encoded.extend_from_slice(&evidence.uid.to_be_bytes());
    encoded.extend_from_slice(&evidence.gid.to_be_bytes());
    encoded.extend_from_slice(&evidence.mode.to_be_bytes());
    match &evidence.stability {
        StructureStability::Directory => {}
        StructureStability::Regular {
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        } => {
            encoded.extend_from_slice(&size.to_be_bytes());
            encoded.extend_from_slice(&nlink.to_be_bytes());
            encoded.extend_from_slice(&mtime_sec.to_be_bytes());
            encoded.extend_from_slice(&mtime_nsec.to_be_bytes());
            encoded.extend_from_slice(&ctime_sec.to_be_bytes());
            encoded.extend_from_slice(&ctime_nsec.to_be_bytes());
        }
        StructureStability::Symlink { target } => {
            let target_len = u64::try_from(target.len())
                .map_err(|_| HeldTreeV3CollectError::Codec(ManifestV3CodecError::LengthOverflow))?;
            encoded.extend_from_slice(&target_len.to_be_bytes());
            encoded.extend_from_slice(target);
        }
        StructureStability::Legacy => {
            return Err(HeldTreeV3CollectError::Codec(
                ManifestV3CodecError::KindContentMismatch,
            ));
        }
    }
    if encoded.len() > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
        return Err(HeldTreeV3CollectError::Codec(
            ManifestV3CodecError::RecordTooLarge,
        ));
    }
    emit_record(encoded).map_err(HeldTreeV3CollectError::Emit)
}

pub(crate) fn decode_structure_record(
    record: &[u8],
) -> Result<StructureEvidence, ManifestV3CodecError> {
    if record.len() > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
        return Err(ManifestV3CodecError::RecordTooLarge);
    }
    let mut input = record;
    let path_len =
        usize::try_from(take_u64(&mut input)?).map_err(|_| ManifestV3CodecError::LengthOverflow)?;
    let path = take(&mut input, path_len)?;
    validate_manifest_path(path, HeldTreeLimits::default().max_depth)?;
    if take(&mut input, STRUCTURE_SCRATCH_RECORD_MAGIC.len())? != STRUCTURE_SCRATCH_RECORD_MAGIC {
        return Err(ManifestV3CodecError::InvalidTag);
    }
    let kind = match take(&mut input, 1)?[0] {
        0 => NodeKind::Directory,
        1 => NodeKind::Regular,
        2 => NodeKind::Symlink,
        _ => return Err(ManifestV3CodecError::InvalidTag),
    };
    let identity = NodeIdentity {
        kind,
        device: take_u64(&mut input)?,
        inode: take_u64(&mut input)?,
        incarnation: take_u64(&mut input)?,
    };
    let uid = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap());
    let gid = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap());
    let mode = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap());
    if mode > 0o7777 {
        return Err(ManifestV3CodecError::InvalidMode);
    }
    let stability = match kind {
        NodeKind::Directory => StructureStability::Directory,
        NodeKind::Regular => {
            let size = take_u64(&mut input)?;
            let nlink = take_u64(&mut input)?;
            let mtime_sec = i64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
            let mtime_nsec = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap());
            let ctime_sec = i64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
            let ctime_nsec = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap());
            if mtime_nsec >= 1_000_000_000 || ctime_nsec >= 1_000_000_000 {
                return Err(ManifestV3CodecError::InvalidNanoseconds);
            }
            StructureStability::Regular {
                size,
                nlink,
                mtime_sec,
                mtime_nsec,
                ctime_sec,
                ctime_nsec,
            }
        }
        NodeKind::Symlink => {
            let target_len = usize::try_from(take_u64(&mut input)?)
                .map_err(|_| ManifestV3CodecError::LengthOverflow)?;
            StructureStability::Symlink {
                target: take(&mut input, target_len)?.to_vec(),
            }
        }
        NodeKind::Other => return Err(ManifestV3CodecError::InvalidTag),
    };
    if !input.is_empty() {
        return Err(ManifestV3CodecError::TrailingBytes);
    }
    Ok(StructureEvidence {
        path: PathBuf::from(OsStr::from_bytes(path)),
        identity,
        uid,
        gid,
        mode,
        stability,
    })
}

pub(crate) fn structure_evidence_from_v3_record(record: ManifestV3Record<'_>) -> StructureEvidence {
    let kind = match record.kind {
        ManifestV3RecordKind::Directory => NodeKind::Directory,
        ManifestV3RecordKind::Regular => NodeKind::Regular,
        ManifestV3RecordKind::Symlink => NodeKind::Symlink,
    };
    let stability = match record.content {
        ManifestV3RecordContent::Directory => StructureStability::Directory,
        ManifestV3RecordContent::Regular {
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            ..
        } => StructureStability::Regular {
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        },
        ManifestV3RecordContent::Symlink { target } => StructureStability::Symlink {
            target: target.to_vec(),
        },
    };
    StructureEvidence {
        path: PathBuf::from(OsStr::from_bytes(record.path)),
        identity: NodeIdentity {
            kind,
            device: record.device,
            inode: record.inode,
            incarnation: record.incarnation,
        },
        uid: record.uid,
        gid: record.gid,
        mode: record.mode,
        stability,
    }
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
    /// Schema 1 certifies each discovered directory immediately, never reads
    /// file content, and imposes no v2 hardlink/xattr/content-budget constraints.
    pub(crate) fn collect_for_schema(
        parent: HeldLocalBackendEvidence,
        root_name: &OsStr,
        protected_names: Vec<OsString>,
        limits: HeldTreeLimits,
        manifest_schema: u16,
    ) -> Result<Self, HeldTreeError> {
        if matches!(
            manifest_schema,
            LEGACY_CONTENT_PROOF_VERSION | CONTENT_PROOF_VERSION
        ) {
            return collect_proven_v2(parent, root_name, protected_names, limits, manifest_schema);
        }
        if manifest_schema != 1 {
            return Err(HeldTreeError::UnsupportedContentProof(PathBuf::new()));
        }
        require_one_component(root_name)?;
        validate_policy(&protected_names)?;
        if limits.max_directories > MAX_TREE_DIRECTORIES {
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
        let root = HeldDirectory::new(held, PathBuf::new(), 0, root_identity);
        let root_evidence = root.evidence.clone();
        let mut tree = Self {
            parent,
            root_name: root_name.to_os_string(),
            root_identity,
            backend,
            mount_id: root.held.mount_id(),
            protected_names,
            limits,
            manifest_schema,
            regular_hard_links: RegularHardLinkTopology::default(),
            regular_xattrs: RegularXattrTopology::default(),
            directory_index: BTreeMap::from([(PathBuf::new(), 0)]),
            directories: vec![root_evidence],
            root,
            manifest: vec![root_entry],
        };
        let mut index = 0;
        while index < tree.directories.len() {
            tree.read_children(index, &mut budget)?;
            index += 1;
        }
        tree.manifest
            .sort_unstable_by(|left, right| left.path.cmp(&right.path));
        tree.directory_index = build_directory_index(&tree.directories)?;
        tree.verify_root_binding()?;
        Ok(tree)
    }

    pub(crate) fn entry_count(&self) -> u64 {
        self.manifest.len() as u64
    }

    pub(crate) fn regular_hard_link_topology(&self) -> RegularHardLinkTopology {
        self.regular_hard_links
    }

    /// Hashes the complete, already-sorted manifest using a fixed binary codec.
    /// Raw path bytes and fixed-width big-endian fields avoid display, UTF-8,
    /// serde, native-endian, and map-order ambiguity.
    pub(crate) fn fingerprint(&self) -> HeldTreeFingerprint {
        debug_assert_eq!(self.manifest_schema, CONTENT_PROOF_VERSION);
        fingerprint_manifest_v3(&self.manifest)
    }

    /// Streams the same per-entry bytes used by `fingerprint`, retaining one
    /// reusable segment buffer and never splitting a manifest record.
    pub(crate) fn stream_manifest_v3_segments<E>(
        &self,
        emit_segment: impl FnMut(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), ManifestV3StreamError<E>> {
        debug_assert_eq!(self.manifest_schema, CONTENT_PROOF_VERSION);
        stream_manifest_v3_segments(
            &self.manifest,
            MANIFEST_V3_MAX_SEGMENT_PAYLOAD,
            emit_segment,
        )
    }

    /// Emits one complete encoded v3 record at a time through a single reused
    /// bounded buffer. The borrowed bytes remain authority-neutral and are
    /// intended for the private unpublished external-sort spool.
    pub(crate) fn stream_manifest_v3_records<E>(
        &self,
        emit_record: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ManifestV3StreamError<E>> {
        debug_assert_eq!(self.manifest_schema, CONTENT_PROOF_VERSION);
        stream_manifest_v3_records(&self.manifest, emit_record)
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
            LEGACY_CONTENT_PROOF_VERSION => Some(fingerprint_manifest_v2(&self.manifest)),
            CONTENT_PROOF_VERSION => Some(fingerprint_manifest_v3(&self.manifest)),
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
        if self.manifest_schema == CONTENT_PROOF_VERSION {
            let mut digest = Sha256::new();
            digest.update(MANIFEST_DOMAIN_V3);
            digest.update((self.manifest.len() as u64).to_be_bytes());
            let mut seen = 0_usize;
            for entry in &self.manifest {
                let mode = if entry.identity.kind == NodeKind::Directory {
                    seen = seen
                        .checked_add(1)
                        .ok_or_else(|| HeldTreeError::IdentityChanged(entry.path.clone()))?;
                    modes
                        .get(&entry.path)
                        .copied()
                        .ok_or_else(|| HeldTreeError::IdentityChanged(entry.path.clone()))?
                } else {
                    entry.mode
                };
                emit_manifest_entry_v3_with_mode(entry, mode, |bytes| digest.update(bytes));
            }
            if seen != modes.len() {
                return Err(HeldTreeError::IdentityChanged(PathBuf::new()));
            }
            return Ok(HeldTreeFingerprint {
                schema_version: CONTENT_PROOF_VERSION,
                entry_count: self.manifest.len() as u64,
                sha256: digest.finalize().into(),
            });
        }

        // Legacy recovery remains byte-for-byte compatible. Only v3 is the
        // production streaming path; old schemas keep their existing clone.
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
        self.fingerprint_manifest_for_inventory(&manifest)
    }

    fn fingerprint_manifest_for_inventory(
        &self,
        manifest: &[ManifestEntry],
    ) -> Result<HeldTreeFingerprint, HeldTreeError> {
        match self.manifest_schema {
            1 => Ok(fingerprint_manifest_v1(manifest)),
            LEGACY_CONTENT_PROOF_VERSION => Ok(fingerprint_manifest_v2(manifest)),
            CONTENT_PROOF_VERSION => Ok(fingerprint_manifest_v3(manifest)),
            _ => Err(HeldTreeError::UnsupportedContentProof(PathBuf::new())),
        }
    }

    pub(crate) fn regular_xattr_topology(&self) -> RegularXattrTopology {
        self.regular_xattrs
    }

    pub(crate) fn directories_deepest_first(
        &self,
    ) -> impl Iterator<Item = HeldDirectoryOrder> + '_ {
        self.directories
            .iter()
            .rev()
            .map(|directory| HeldDirectoryOrder {
                relative_path: directory.relative_path.clone(),
                depth: directory.depth,
                device: directory.identity.device,
                inode: directory.identity.inode,
                incarnation: directory.identity.incarnation,
                observed_mode: directory.observed_mode,
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
    /// root-relative transient directory descriptors. Every non-directory is
    /// revalidated (including content, one-link policy, ownership, type and strong
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
        entries.sort_unstable_by(|left, right| {
            right
                .path
                .components()
                .count()
                .cmp(&left.path.components().count())
                .then_with(|| right.path.cmp(&left.path))
        });
        let mut content_budget = Budget::new(self.limits, self.manifest_schema);
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
            let reopened = self.reopen_directory(parent_path)?;
            let parent = reopened.held();
            let before = with_fd(parent, |fd| inspect_at(fd, name, &expected.path))?;
            require_owner(
                &expected.path,
                before.uid,
                rustix::process::geteuid().as_raw(),
            )?;
            require_boundary(&expected.path, self.backend, self.mount_id, &before)?;
            let content = inspect_content_at(
                parent,
                name,
                &expected.path,
                &before,
                &mut content_budget,
                self.manifest_schema,
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
            retry_interrupted(|| with_fd(parent, |fd| rustix::fs::unlinkat(fd, name, flags)))
                .map_err(|error| io_error(&expected.path, error))?;
            drop(reopened);
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
        let held_root = inspect_held(&self.root.held, Path::new(""))?;
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
        for position in (0..self.directories.len()).rev() {
            let evidence = self.directories[position].clone();
            let relative_path = source_root.join(&evidence.relative_path);
            let path = evidence.relative_path.clone();
            let result = if position == 0 {
                execute_staging_local_mode_mutation(
                    wal,
                    &mut self.root.held,
                    LocalModeMutationRequest {
                        transaction,
                        mutation_id,
                        locator: RecoveryLocator::held_staging(
                            relative_path,
                            filesystem_id.to_owned(),
                            evidence.identity.incarnation,
                        ),
                        transform: LocalModeTransform::Seal {
                            acquire_owner_write_search: false,
                        },
                    },
                )
            } else {
                let mut reopened =
                    self.reopen_directory_for_transient_seal(&evidence.relative_path)?;
                let held = match &mut reopened.held {
                    ReopenedHeldDirectory::Descendant(held) => held,
                    ReopenedHeldDirectory::Root(_) => {
                        return Err(HeldTreeSealError::Mutation {
                            path,
                            source: LocalModeExecutionError::InvalidRequest(
                                "reopener returned retained root unexpectedly",
                            ),
                        });
                    }
                };
                execute_staging_local_mode_mutation(
                    wal,
                    held,
                    LocalModeMutationRequest {
                        transaction,
                        mutation_id,
                        locator: RecoveryLocator::held_staging(
                            relative_path,
                            filesystem_id.to_owned(),
                            evidence.identity.incarnation,
                        ),
                        transform: LocalModeTransform::Seal {
                            acquire_owner_write_search: false,
                        },
                    },
                )
            }
            .map_err(|source| HeldTreeSealError::Mutation {
                path: evidence.relative_path.clone(),
                source,
            })?;
            let applied_mode = match result {
                LocalModeMutationResult::Applied { applied_mode, .. } => applied_mode,
                LocalModeMutationResult::ConfirmedNotApplied => {
                    return Err(HeldTreeSealError::ConfirmedNotApplied(
                        evidence.relative_path.clone(),
                    ));
                }
            };
            // Only the executor's WAL-bound, verified Applied result advances
            // inventory evidence. Error and unknown outcomes return above and
            // can never synthesize a post-mutation mode from stale evidence.
            self.directories[position].observed_mode = applied_mode;
            mutation_id = mutation_id
                .checked_add(1)
                .ok_or(HeldTreeSealError::MutationIdExhausted)?;
        }
        Ok(mutation_id)
    }

    /// Consumes the pre-seal inventory into a fixed-size commitment after its
    /// directory evidence has been updated by WAL-bound chmod results. The v3
    /// codec is hashed with those exact sealed directory modes and unchanged
    /// non-directory records. Returning consumes and drops the complete
    /// pre-seal manifest before the caller can collect a post-seal inventory.
    pub(crate) fn into_post_seal_expectation(
        self,
    ) -> Result<PostSealManifestExpectation, HeldTreeError> {
        if self.manifest_schema != CONTENT_PROOF_VERSION {
            return Err(HeldTreeError::UnsupportedContentProof(PathBuf::new()));
        }
        let mut digest = Sha256::new();
        digest.update(MANIFEST_DOMAIN_V3);
        digest.update((self.manifest.len() as u64).to_be_bytes());
        for entry in &self.manifest {
            let mode = if entry.identity.kind == NodeKind::Directory {
                let position = self
                    .directory_index
                    .get(&entry.path)
                    .copied()
                    .ok_or_else(|| HeldTreeError::PostChanged(entry.path.clone()))?;
                self.directories
                    .get(position)
                    .filter(|directory| directory.relative_path == entry.path)
                    .map(|directory| directory.observed_mode)
                    .ok_or_else(|| HeldTreeError::PostChanged(entry.path.clone()))?
            } else {
                entry.mode
            };
            emit_manifest_entry_v3_with_mode(entry, mode, |bytes| digest.update(bytes));
        }
        Ok(PostSealManifestExpectation {
            root_identity: self.root_identity,
            backend: self.backend,
            mount_id: self.mount_id,
            fingerprint: HeldTreeFingerprint {
                schema_version: CONTENT_PROOF_VERSION,
                entry_count: self.manifest.len() as u64,
                sha256: digest.finalize().into(),
            },
        })
    }

    /// Performs a bounded second walk of namespace and stable metadata only.
    /// This is authority-neutral evidence: it does not read regular-file bytes
    /// or xattr values, recompute a regular-file content digest, or mint a
    /// lifecycle token. Content-proof schemas compare size, link count, mtime,
    /// and ctime so non-root regular-file drift after the preceding full proof
    /// is rejected without repeating payload I/O. Symlink targets and no-follow
    /// link metadata are re-read because target length alone is not exact proof.
    pub(crate) fn rewalk_structure(&self) -> Result<(), HeldTreeError> {
        self.verify_root_binding()?;
        // The resident manifest is already canonical and sorted. Retain only
        // one vector of fresh observations; cloning the whole baseline into a
        // second path map would double path and symlink-target memory.
        let mut actual = Vec::new();
        let mut budget = Budget::new(self.limits, self.manifest_schema);
        let reopened_root = self.reopen_directory(Path::new(""))?;
        let root = inspect_held(reopened_root.held(), Path::new(""))?;
        let root = root.structure_evidence(PathBuf::new(), self.manifest_schema)?;
        budget.add_path(&root.path, 0)?;
        budget.add_directory()?;
        actual.push(root);

        for directory in &self.directories {
            let reopened = self.reopen_directory(&directory.relative_path)?;
            let held = reopened.held();
            let fresh = with_fd(held, |fd| {
                rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
            })
            .map_err(|error| io_error(&directory.relative_path, error))?;
            let entries =
                Dir::new(fresh).map_err(|error| io_error(&directory.relative_path, error))?;
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&directory.relative_path, error))?;
                if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = OsStr::from_bytes(entry.file_name().to_bytes());
                let path = directory.relative_path.join(name);
                require_unprotected(&self.protected_names, name, &path)?;
                let inspected = with_fd(held, |fd| inspect_at(fd, name, &path))?;
                require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
                require_boundary(&path, self.backend, self.mount_id, &inspected)?;
                let value =
                    if self.manifest_schema != 1 && inspected.identity.kind == NodeKind::Symlink {
                        // Symlink targets are small filesystem metadata, not regular-file
                        // payload. Re-read the target and re-run no-follow link metadata
                        // admission so the optimized rewalk cannot move a link whose
                        // target or link-self xattrs changed after the full proof.
                        let content =
                            inspect_symlink_content(held, name, &path, &inspected, &mut budget)?;
                        inspected
                            .clone()
                            .into_manifest(path.clone(), content)
                            .structure_evidence()
                    } else {
                        inspected.structure_evidence(path.clone(), self.manifest_schema)?
                    };
                budget.add_path(&value.path, directory.depth.saturating_add(1))?;
                if value.identity.kind == NodeKind::Directory {
                    budget.add_directory()?;
                }
                actual.push(value);
            }
        }
        actual.sort_unstable_by(|left, right| left.path.cmp(&right.path));
        let mut actual = actual.into_iter();
        for entry in &self.manifest {
            let expected = entry.structure_evidence();
            let Some(found) = actual.next() else {
                return Err(HeldTreeError::PostRemoved(expected.path));
            };
            match expected.path.cmp(&found.path) {
                std::cmp::Ordering::Less => {
                    return Err(HeldTreeError::PostRemoved(expected.path));
                }
                std::cmp::Ordering::Greater => {
                    return Err(HeldTreeError::PostAdded(found.path));
                }
                std::cmp::Ordering::Equal if expected != found => {
                    return Err(HeldTreeError::PostChanged(expected.path));
                }
                std::cmp::Ordering::Equal => {}
            }
        }
        if let Some(extra) = actual.next() {
            return Err(HeldTreeError::PostAdded(extra.path));
        }
        self.verify_root_binding()
    }

    /// Performs a complete second walk under the identical policy and limits.
    /// It only validates; success does not mint any lifecycle token. Production
    /// uses `rewalk_structure` after a preceding full proof; this complete pass
    /// remains as a regression oracle for tests.
    #[cfg(test)]
    pub(crate) fn rewalk_exact(&self) -> Result<(), HeldTreeError> {
        self.verify_root_binding()?;
        let baseline = self
            .manifest
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut actual = BTreeMap::new();
        let mut budget = Budget::new(self.limits, self.manifest_schema);
        let root_content = if self.manifest_schema == 1 {
            ContentProof::Legacy
        } else {
            ContentProof::Directory
        };
        let reopened_root = self.reopen_directory(Path::new(""))?;
        let root = inspect_held(reopened_root.held(), Path::new(""))?
            .into_manifest(PathBuf::new(), root_content);
        budget.add_path(&root.path, 0)?;
        budget.add_directory()?;
        actual.insert(PathBuf::new(), root);
        for directory in &self.directories {
            let reopened = self.reopen_directory(&directory.relative_path)?;
            let held = reopened.held();
            let fresh = with_fd(held, |fd| {
                rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
            })
            .map_err(|error| io_error(&directory.relative_path, error))?;
            let entries =
                Dir::new(fresh).map_err(|error| io_error(&directory.relative_path, error))?;
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&directory.relative_path, error))?;
                if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = OsStr::from_bytes(entry.file_name().to_bytes());
                let path = directory.relative_path.join(name);
                require_unprotected(&self.protected_names, name, &path)?;
                let inspected = with_fd(held, |fd| inspect_at(fd, name, &path))?;
                require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
                require_boundary(&path, self.backend, self.mount_id, &inspected)?;
                let content = inspect_content_for_schema(
                    self.manifest_schema,
                    held,
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

    /// Reopens one recorded directory from the retained certified root. Only
    /// literal normal relative components are accepted. Each next component is
    /// opened and fully certified before the prior non-root descriptor is
    /// dropped, so any depth uses at most two transient non-root descriptors.
    fn reopen_directory(
        &self,
        relative_path: &Path,
    ) -> Result<ReopenedDirectory<'_>, HeldTreeError> {
        reopen_directory_from_root(
            &self.root,
            relative_path,
            |path| self.directory_evidence(path),
            self.backend,
            self.mount_id,
            || self.verify_root_binding(),
            false,
        )
    }

    fn reopen_directory_for_transient_seal(
        &self,
        relative_path: &Path,
    ) -> Result<ReopenedDirectory<'_>, HeldTreeError> {
        reopen_directory_from_root(
            &self.root,
            relative_path,
            |path| self.directory_evidence(path),
            self.backend,
            self.mount_id,
            || self.verify_root_binding(),
            true,
        )
    }

    fn directory_evidence(&self, relative_path: &Path) -> Option<&DirectoryEvidence> {
        let position = *self.directory_index.get(relative_path)?;
        let evidence = self.directories.get(position)?;
        (evidence.relative_path == relative_path).then_some(evidence)
    }

    fn read_children(&mut self, index: usize, budget: &mut Budget) -> Result<(), HeldTreeError> {
        let parent_path = self.directories[index].relative_path.clone();
        let parent_depth = self.directories[index].depth;
        let reopened = self.reopen_directory(&parent_path)?;
        let parent = reopened.held();
        let fresh = with_fd(parent, |fd| {
            rustix::fs::openat(fd, c".", OPEN_DIRECTORY, Mode::empty())
        })
        .map_err(|error| io_error(&parent_path, error))?;
        let entries = Dir::new(fresh).map_err(|error| io_error(&parent_path, error))?;
        let mut children = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&parent_path, error))?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            let path = parent_path.join(name);
            require_unprotected(&self.protected_names, name, &path)?;
            let inspected = with_fd(parent, |fd| inspect_at(fd, name, &path))?;
            require_owner(&path, inspected.uid, rustix::process::geteuid().as_raw())?;
            require_boundary(&path, self.backend, self.mount_id, &inspected)?;
            let depth = parent_depth.saturating_add(1);
            let child = if inspected.identity.kind == NodeKind::Directory {
                // Preserve schema-v1's immediate directory certification and
                // error ordering while retaining the descriptor only for this
                // entry's collection. Later traversal reopens from the root.
                let fd = with_fd(parent, |parent_fd| {
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
                parent,
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
            let evidence = child.as_ref().map(|held| DirectoryEvidence {
                relative_path: path.clone(),
                depth,
                identity: manifest.identity,
                owner_uid: held.owner_uid(),
                group_gid: held.group_gid(),
                observed_mode: held.mode(),
            });
            children.push((manifest, evidence));
        }
        drop(reopened);
        for (manifest, evidence) in children {
            self.manifest.push(manifest);
            if let Some(evidence) = evidence {
                self.directory_index
                    .insert(evidence.relative_path.clone(), self.directories.len());
                self.directories.push(evidence);
            }
        }
        Ok(())
    }

    fn verify_root_binding(&self) -> Result<(), HeldTreeError> {
        require_exclusive_parent(&self.parent, self.backend)?;
        verify_root_binding_fields(
            &self.parent,
            &self.root_name,
            self.root_identity,
            self.mount_id,
            self.backend,
        )
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
    fn regular_file_observation(
        &self,
        sha256: Option<[u8; 32]>,
        xattrs: RegularXattrProof,
    ) -> Option<RegularFileObservation> {
        (self.identity.kind == NodeKind::Regular && self.content_fields_available).then_some(
            RegularFileObservation {
                identity: self.identity,
                uid: self.uid,
                gid: self.gid,
                mode: self.mode,
                size: self.size,
                nlink: self.nlink,
                mtime_sec: self.mtime_sec,
                mtime_nsec: self.mtime_nsec,
                ctime_sec: self.ctime_sec,
                ctime_nsec: self.ctime_nsec,
                sha256,
                xattrs,
            },
        )
    }

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

    fn structure_evidence(
        &self,
        path: PathBuf,
        manifest_schema: u16,
    ) -> Result<StructureEvidence, HeldTreeError> {
        let stability = match manifest_schema {
            1 => StructureStability::Legacy,
            LEGACY_CONTENT_PROOF_VERSION | CONTENT_PROOF_VERSION => match self.identity.kind {
                NodeKind::Directory => StructureStability::Directory,
                NodeKind::Regular if self.content_fields_available => StructureStability::Regular {
                    size: self.size,
                    nlink: self.nlink,
                    mtime_sec: self.mtime_sec,
                    mtime_nsec: self.mtime_nsec,
                    ctime_sec: self.ctime_sec,
                    ctime_nsec: self.ctime_nsec,
                },
                NodeKind::Regular => {
                    return Err(HeldTreeError::ContentChangedDuringHash(path));
                }
                NodeKind::Symlink => {
                    // Callers must re-read the no-follow target and link-self
                    // metadata; length alone cannot preserve exact admission.
                    return Err(HeldTreeError::UnsupportedContentProof(path));
                }
                NodeKind::Other => {
                    return Err(HeldTreeError::UnsupportedContentProof(path));
                }
            },
            _ => return Err(HeldTreeError::UnsupportedContentProof(path)),
        };
        Ok(StructureEvidence {
            path,
            identity: self.identity,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            stability,
        })
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
        LEGACY_CONTENT_PROOF_VERSION | CONTENT_PROOF_VERSION => {
            inspect_content_at(parent, name, path, before, budget, schema_version)
        }
        _ => Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf())),
    }
}

fn inspect_content_at(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
    schema_version: u16,
) -> Result<ContentProof, HeldTreeError> {
    if !before.content_fields_available {
        return Err(if before.identity.kind == NodeKind::Regular {
            HeldTreeError::ContentChangedDuringHash(path.to_path_buf())
        } else {
            HeldTreeError::UnsupportedContentProof(path.to_path_buf())
        });
    }
    match before.identity.kind {
        NodeKind::Directory => {
            require_content_admitted(
                EntryFacts {
                    kind: EntryKind::Directory,
                    acl: Evidence::Unknown,
                    xattr_platform: current_xattr_platform(),
                    xattrs: Xattrs::Unknown,
                },
                path,
            )?;
            Ok(ContentProof::Directory)
        }
        NodeKind::Regular => {
            inspect_regular_content(parent, name, path, before, budget, schema_version)
        }
        NodeKind::Symlink => inspect_symlink_content(parent, name, path, before, budget),
        NodeKind::Other => {
            require_content_admitted(
                EntryFacts {
                    kind: EntryKind::Other,
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
) -> Result<Option<RegularXattrProof>, HeldTreeError> {
    if !before.content_fields_available {
        return Err(if before.identity.kind == NodeKind::Regular {
            HeldTreeError::ContentChangedDuringHash(path.to_path_buf())
        } else {
            HeldTreeError::UnsupportedContentProof(path.to_path_buf())
        });
    }
    match before.identity.kind {
        NodeKind::Directory => Ok(None),
        NodeKind::Regular => assess_regular_content(parent, name, path, before, budget).map(Some),
        NodeKind::Symlink => {
            assess_symlink_content(parent, name, path, before, budget)?;
            Ok(None)
        }
        NodeKind::Other => Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf())),
    }
}

fn assess_regular_content(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    path: &Path,
    before: &Inspection,
    budget: &mut Budget,
) -> Result<RegularXattrProof, HeldTreeError> {
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
    let xattrs = collect_regular_xattr_assessment(&fd, path, budget.xattr_read_budget())?;
    budget.add_xattrs(xattrs.value_bytes)?;
    let opened = inspect_raw_fd(&fd, parent.backend(), path)?;
    if !before.stable_content_fields_equal(&opened) || opened.identity.kind != NodeKind::Regular {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    let final_xattrs = collect_regular_xattr_assessment(
        &fd,
        path,
        XattrReadBudget::new(xattrs.value_bytes, budget.limits.max_xattr_bytes),
    )?;
    let final_inspection = inspect_raw_fd(&fd, parent.backend(), path)?;
    if xattrs != final_xattrs {
        return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()));
    }
    if !opened.stable_content_fields_equal(&final_inspection) {
        return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
    }
    Ok(xattrs)
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
    schema_version: u16,
) -> Result<ContentProof, HeldTreeError> {
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
    let xattrs =
        collect_regular_xattr_proof(&fd, path, schema_version, budget.xattr_read_budget())?;
    budget.add_xattrs(xattrs.value_bytes)?;
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
        #[cfg(test)]
        REGULAR_CONTENT_BYTES_READ.with(|bytes| {
            bytes.set(bytes.get().saturating_add(read as u64));
        });
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| HeldTreeError::ContentChangedDuringHash(path.to_path_buf()))?;
        if total > before.size {
            return Err(HeldTreeError::ContentChangedDuringHash(path.to_path_buf()));
        }
        digest.update(&buffer[..read]);
    }
    let after = inspect_raw_fd(&file, parent.backend(), path)?;
    let final_xattrs = collect_regular_xattr_proof(
        &file,
        path,
        schema_version,
        XattrReadBudget::new(xattrs.value_bytes, budget.limits.max_xattr_bytes),
    )?;
    let final_inspection = inspect_raw_fd(&file, parent.backend(), path)?;
    if xattrs != final_xattrs {
        return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()));
    }
    if total != before.size
        || !before.stable_content_fields_equal(&after)
        || !opened.stable_content_fields_equal(&after)
        || !after.stable_content_fields_equal(&final_inspection)
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
        xattrs,
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
            RejectReason::UnsupportedEntryKind => {
                HeldTreeError::UnsupportedContentProof(path.to_path_buf())
            }
            RejectReason::AclPresent | RejectReason::ExtendedAttributePresent { .. } => {
                HeldTreeError::NonDirectoryExtendedMetadata(path.to_path_buf())
            }
            RejectReason::AclUnknown | RejectReason::ExtendedAttributesUnknown => {
                HeldTreeError::NonDirectoryMetadataUnavailable(path.to_path_buf())
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

#[derive(Clone, Copy)]
struct XattrReadBudget {
    remaining_bytes: u64,
    content_limit: u64,
}

impl XattrReadBudget {
    fn new(remaining_bytes: u64, content_limit: u64) -> Self {
        Self {
            remaining_bytes,
            content_limit,
        }
    }

    fn charge(&mut self, bytes: u64) -> Result<(), HeldTreeError> {
        self.remaining_bytes =
            self.remaining_bytes
                .checked_sub(bytes)
                .ok_or(HeldTreeError::Limit {
                    kind: HeldTreeLimit::ContentBytes,
                    limit: self.content_limit,
                })?;
        Ok(())
    }
}

fn admitted_regular_xattr_names<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
) -> Result<Vec<Vec<u8>>, HeldTreeError> {
    // ACL authority is a separate fact. It must be probed even when ordinary
    // xattrs are present; xattr classification is never allowed to mask it.
    match acl_evidence(fd) {
        Evidence::Absent => {}
        Evidence::Present => {
            return Err(HeldTreeError::NonDirectoryExtendedMetadata(
                path.to_path_buf(),
            ));
        }
        Evidence::Unknown => {
            return Err(HeldTreeError::NonDirectoryMetadataUnavailable(
                path.to_path_buf(),
            ));
        }
    }

    let mut names = match collect_fd_xattr_names(fd) {
        CollectedXattrs::Names(names) => names,
        CollectedXattrs::Unknown => {
            return Err(HeldTreeError::NonDirectoryMetadataUnavailable(
                path.to_path_buf(),
            ));
        }
    };
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()));
    }
    if names
        .iter()
        .any(|name| !ordinary_regular_xattr_is_admitted(current_xattr_platform(), name))
    {
        return Err(HeldTreeError::NonDirectoryExtendedMetadata(
            path.to_path_buf(),
        ));
    }
    Ok(names)
}

fn collect_regular_xattr_assessment<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
    mut budget: XattrReadBudget,
) -> Result<RegularXattrProof, HeldTreeError> {
    let names = admitted_regular_xattr_names(fd, path)?;
    let mut digest = Sha256::new();
    digest.update(XATTR_PROOF_DOMAIN_V3);
    digest.update((names.len() as u64).to_be_bytes());
    let mut value_bytes = 0_u64;
    for name in &names {
        let value_len = size_fd_xattr_value(fd.as_fd().as_raw_fd(), name, path)?;
        budget.charge(value_len)?;
        value_bytes = value_bytes
            .checked_add(value_len)
            .ok_or_else(|| HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()))?;
        // This assessment digest is transient equality evidence only. Durable
        // proof below additionally commits the value bytes themselves.
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update(value_len.to_be_bytes());
    }
    Ok(RegularXattrProof {
        attribute_count: names.len() as u64,
        value_bytes,
        sha256: digest.finalize().into(),
    })
}

fn collect_regular_xattr_proof<Fd: rustix::fd::AsFd>(
    fd: &Fd,
    path: &Path,
    schema_version: u16,
    mut budget: XattrReadBudget,
) -> Result<RegularXattrProof, HeldTreeError> {
    if schema_version == LEGACY_CONTENT_PROOF_VERSION {
        require_fd_metadata_admitted(fd, path, EntryKind::Regular, true)?;
        return Ok(empty_regular_xattr_proof());
    }
    if schema_version != CONTENT_PROOF_VERSION {
        return Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()));
    }

    let names = admitted_regular_xattr_names(fd, path)?;
    let mut digest = Sha256::new();
    digest.update(XATTR_PROOF_DOMAIN_V3);
    digest.update((names.len() as u64).to_be_bytes());
    let mut value_bytes = 0_u64;
    for name in &names {
        let value = read_fd_xattr_value(
            fd.as_fd().as_raw_fd(),
            name,
            path,
            budget.remaining_bytes,
            budget.content_limit,
        )?;
        let value_len = value.len() as u64;
        budget.charge(value_len)?;
        value_bytes = value_bytes
            .checked_add(value_len)
            .ok_or_else(|| HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()))?;
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update(value_len.to_be_bytes());
        digest.update(&value);
    }
    Ok(RegularXattrProof {
        attribute_count: names.len() as u64,
        value_bytes,
        sha256: digest.finalize().into(),
    })
}

#[cfg(target_os = "linux")]
fn size_fd_xattr_value(fd: libc::c_int, name: &[u8], path: &Path) -> Result<u64, HeldTreeError> {
    let name = CString::new(name)
        .map_err(|_| HeldTreeError::NonDirectoryMetadataUnavailable(path.to_path_buf()))?;
    size_xattr_value(path, || {
        // SAFETY: fd and name remain live; a null buffer requests only size.
        xattr_count_result(unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) })
    })
}

#[cfg(target_os = "macos")]
fn size_fd_xattr_value(fd: libc::c_int, name: &[u8], path: &Path) -> Result<u64, HeldTreeError> {
    let name = CString::new(name)
        .map_err(|_| HeldTreeError::NonDirectoryMetadataUnavailable(path.to_path_buf()))?;
    size_xattr_value(path, || {
        // SAFETY: fd and name remain live; a null buffer requests only size.
        xattr_count_result(unsafe {
            libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0)
        })
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn size_fd_xattr_value(_fd: libc::c_int, _name: &[u8], path: &Path) -> Result<u64, HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn size_xattr_value(
    path: &Path,
    mut get_size: impl FnMut() -> io::Result<usize>,
) -> Result<u64, HeldTreeError> {
    for _ in 0..XATTR_LIST_ATTEMPTS {
        match get_size() {
            Ok(size) => return Ok(size as u64),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => {
                return Err(HeldTreeError::NonDirectoryMetadataUnavailable(
                    path.to_path_buf(),
                ));
            }
        }
    }
    Err(HeldTreeError::NonDirectoryMetadataUnavailable(
        path.to_path_buf(),
    ))
}

#[cfg(target_os = "linux")]
fn read_fd_xattr_value(
    fd: libc::c_int,
    name: &[u8],
    path: &Path,
    maximum_value_bytes: u64,
    content_limit: u64,
) -> Result<Vec<u8>, HeldTreeError> {
    let name = CString::new(name)
        .map_err(|_| HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()))?;
    read_xattr_value(path, maximum_value_bytes, content_limit, |buffer, size| {
        // SAFETY: fd and name are live; buffer is null for a size query or
        // points to the supplied writable allocation.
        xattr_count_result(unsafe { libc::fgetxattr(fd, name.as_ptr(), buffer.cast(), size) })
    })
}

#[cfg(target_os = "macos")]
fn read_fd_xattr_value(
    fd: libc::c_int,
    name: &[u8],
    path: &Path,
    maximum_value_bytes: u64,
    content_limit: u64,
) -> Result<Vec<u8>, HeldTreeError> {
    let name = CString::new(name)
        .map_err(|_| HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()))?;
    read_xattr_value(path, maximum_value_bytes, content_limit, |buffer, size| {
        // SAFETY: fd and name are live; buffer is null for a size query or
        // points to the supplied writable allocation.
        xattr_count_result(unsafe { libc::fgetxattr(fd, name.as_ptr(), buffer.cast(), size, 0, 0) })
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_fd_xattr_value(
    _fd: libc::c_int,
    _name: &[u8],
    path: &Path,
    _maximum_value_bytes: u64,
    _content_limit: u64,
) -> Result<Vec<u8>, HeldTreeError> {
    Err(HeldTreeError::UnsupportedContentProof(path.to_path_buf()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_xattr_value(
    path: &Path,
    maximum_value_bytes: u64,
    content_limit: u64,
    mut get: impl FnMut(*mut libc::c_void, usize) -> io::Result<usize>,
) -> Result<Vec<u8>, HeldTreeError> {
    for _ in 0..XATTR_LIST_ATTEMPTS {
        let size = match get(std::ptr::null_mut(), 0) {
            Ok(size) => size,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf())),
        };
        // Bound allocation independently of caller-supplied limits. The normal
        // aggregate content budget applies immediately after this read.
        if size as u64 > maximum_value_bytes {
            return Err(HeldTreeError::Limit {
                kind: HeldTreeLimit::ContentBytes,
                limit: content_limit,
            });
        }
        let mut value = vec![0_u8; size];
        let read = match get(value.as_mut_ptr().cast(), value.len()) {
            Ok(read) => read,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ERANGE)) => {
                continue;
            }
            Err(_) => return Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf())),
        };
        if read != size {
            continue;
        }
        #[cfg(test)]
        REGULAR_XATTR_VALUE_BYTES_READ.with(|bytes| {
            bytes.set(bytes.get().saturating_add(read as u64));
        });
        return Ok(value);
    }
    Err(HeldTreeError::XattrsChangedDuringProof(path.to_path_buf()))
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

fn verify_root_binding_fields(
    parent: &HeldLocalBackendEvidence,
    root_name: &OsStr,
    root_identity: NodeIdentity,
    mount_id: u64,
    backend: CertifiedLocalBackend,
) -> Result<(), HeldTreeError> {
    let inspected = with_fd(parent, |fd| inspect_at(fd, root_name, Path::new("")))
        .map_err(|_| HeldTreeError::RootBindingChanged)?;
    if root_binding_matches(root_identity, mount_id, backend, &inspected) {
        Ok(())
    } else {
        Err(HeldTreeError::RootBindingChanged)
    }
}

/// Opens a recorded directory strictly beneath the retained root descriptor.
/// Every component is NOFOLLOW-opened and certified against data-only evidence
/// before traversal advances; only the current and next non-root FDs overlap.
fn reopen_directory_from_root<'root, 'e>(
    root: &'root HeldDirectory,
    relative_path: &Path,
    directory_evidence: impl Fn(&Path) -> Option<&'e DirectoryEvidence>,
    backend: CertifiedLocalBackend,
    mount_id: u64,
    verify_root_binding: impl FnOnce() -> Result<(), HeldTreeError>,
    transient_seal_final_validation: bool,
) -> Result<ReopenedDirectory<'root>, HeldTreeError> {
    let components = normal_relative_components(relative_path)?;
    let component_count = components.len();
    let target = directory_evidence(relative_path)
        .ok_or_else(|| HeldTreeError::IdentityChanged(relative_path.to_path_buf()))?;
    if usize::try_from(target.depth).ok() != Some(components.len()) {
        return Err(HeldTreeError::InvalidDirectoryPath(
            relative_path.to_path_buf(),
        ));
    }
    if !root.evidence.relative_path.as_os_str().is_empty() || root.evidence.depth != 0 {
        return Err(HeldTreeError::InvalidDirectoryPath(PathBuf::new()));
    }
    validate_reopened_directory(&root.held, &root.evidence, backend, mount_id)?;
    #[cfg(test)]
    fire_reopener_test_hook(
        ReopenerTestPhase::AfterValidatedHopBeforeNextOperation,
        Path::new(""),
    );
    verify_root_binding()?;
    if components.is_empty() {
        return Ok(ReopenedDirectory {
            held: ReopenedHeldDirectory::Root(&root.held),
        });
    }

    let mut prefix = PathBuf::new();
    let mut current: Option<HeldLocalBackendEvidence> = None;
    let mut live_non_root = 0_usize;
    for (index, component) in components.into_iter().enumerate() {
        prefix.push(component);
        let expected = directory_evidence(&prefix)
            .ok_or_else(|| HeldTreeError::IdentityChanged(prefix.clone()))?;
        if usize::try_from(expected.depth).ok() != Some(index + 1) {
            return Err(HeldTreeError::InvalidDirectoryPath(prefix));
        }
        let parent = current.as_ref().unwrap_or(&root.held);
        let fd = with_fd(parent, |parent_fd| {
            rustix::fs::openat(parent_fd, component, OPEN_DIRECTORY, Mode::empty())
        })
        .map_err(|error| io_error(&prefix, error))?;
        #[cfg(test)]
        fire_reopener_test_hook(ReopenerTestPhase::AfterOpenBeforeValidation, &prefix);
        let next = certify_held_fd(fd).map_err(|reason| HeldTreeError::Certification {
            path: prefix.clone(),
            reason,
        })?;
        live_non_root += 1;
        note_reopener_live_non_root_fds(live_non_root);
        validate_reopened_directory(&next, expected, backend, mount_id)?;
        #[cfg(test)]
        fire_reopener_test_hook(
            ReopenerTestPhase::AfterValidatedHopBeforeNextOperation,
            &prefix,
        );
        validate_reopened_name(parent, component, expected, backend, mount_id)?;
        if transient_seal_final_validation && index + 1 == component_count {
            // Tests may inject a race here, but the validation itself is the
            // unconditional production path immediately before the caller can
            // append a WAL intent or invoke fchmod.
            #[cfg(test)]
            fire_transient_seal_test_hook(&prefix);
            validate_reopened_directory(&next, expected, backend, mount_id)?;
            validate_reopened_name(parent, component, expected, backend, mount_id)?;
        }

        let previous = current.replace(next);
        if previous.is_some() {
            drop(previous);
            live_non_root -= 1;
        }
    }

    Ok(ReopenedDirectory {
        held: ReopenedHeldDirectory::Descendant(
            current.ok_or_else(|| HeldTreeError::IdentityChanged(relative_path.to_path_buf()))?,
        ),
    })
}

fn build_directory_index(
    directories: &[DirectoryEvidence],
) -> Result<BTreeMap<PathBuf, usize>, HeldTreeError> {
    let mut index = BTreeMap::new();
    for (position, directory) in directories.iter().enumerate() {
        let path = &directory.relative_path;
        let components = normal_relative_components(path)?;
        if usize::try_from(directory.depth).ok() != Some(components.len()) {
            return Err(HeldTreeError::InvalidDirectoryPath(path.clone()));
        }
        if index.insert(path.clone(), position).is_some() {
            return Err(HeldTreeError::IdentityChanged(path.clone()));
        }
    }
    if index.get(Path::new("")) != Some(&0) {
        return Err(HeldTreeError::InvalidDirectoryPath(PathBuf::new()));
    }
    Ok(index)
}

fn normal_relative_components(path: &Path) -> Result<Vec<&OsStr>, HeldTreeError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in bytes.split(|byte| *byte == b'/') {
        if component.is_empty() || matches!(component, b"." | b"..") {
            return Err(HeldTreeError::InvalidDirectoryPath(path.to_path_buf()));
        }
        components.push(OsStr::from_bytes(component));
    }
    Ok(components)
}

fn validate_reopened_name(
    parent: &HeldLocalBackendEvidence,
    name: &OsStr,
    expected: &DirectoryEvidence,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<(), HeldTreeError> {
    let inspected = with_fd(parent, |fd| inspect_at(fd, name, &expected.relative_path))?;
    require_same_identity(
        &expected.relative_path,
        expected.identity,
        inspected.identity,
    )?;
    require_owner(&expected.relative_path, inspected.uid, expected.owner_uid)?;
    require_owner(
        &expected.relative_path,
        expected.owner_uid,
        rustix::process::geteuid().as_raw(),
    )?;
    if inspected.gid != expected.group_gid || inspected.mode != expected.observed_mode {
        return Err(HeldTreeError::IdentityChanged(
            expected.relative_path.clone(),
        ));
    }
    require_boundary(&expected.relative_path, backend, mount_id, &inspected)
}

fn validate_reopened_directory(
    held: &HeldLocalBackendEvidence,
    expected: &DirectoryEvidence,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<(), HeldTreeError> {
    with_fd(held, |fd| crate::backend::require_held_fd_acl_absent(fd)).map_err(|reason| {
        HeldTreeError::Certification {
            path: expected.relative_path.clone(),
            reason,
        }
    })?;
    let fresh_backend =
        with_fd(held, |fd| crate::backend::certify_held_fd_backend(fd)).map_err(|reason| {
            HeldTreeError::Certification {
                path: expected.relative_path.clone(),
                reason,
            }
        })?;
    let inspected = inspect_held(held, &expected.relative_path)?;
    require_same_identity(
        &expected.relative_path,
        expected.identity,
        inspected.identity,
    )?;
    require_owner(&expected.relative_path, inspected.uid, expected.owner_uid)?;
    require_owner(
        &expected.relative_path,
        expected.owner_uid,
        rustix::process::geteuid().as_raw(),
    )?;
    if inspected.gid != expected.group_gid || inspected.mode != expected.observed_mode {
        return Err(HeldTreeError::IdentityChanged(
            expected.relative_path.clone(),
        ));
    }
    if held.backend() != backend || fresh_backend != backend || held.mount_id() != mount_id {
        return Err(HeldTreeError::BackendBoundary(
            expected.relative_path.clone(),
        ));
    }
    require_boundary(&expected.relative_path, backend, mount_id, &inspected)
}

#[cfg(test)]
fn note_reopener_live_non_root_fds(live: usize) {
    REOPENER_MAX_NON_ROOT_FDS.with(|maximum| maximum.set(maximum.get().max(live)));
}

#[cfg(not(test))]
fn note_reopener_live_non_root_fds(_live: usize) {}

fn require_directory_current(
    directory: &HeldDirectory,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<(), HeldTreeError> {
    require_directory_evidence_current(&directory.held, &directory.evidence, backend, mount_id)
}

fn require_directory_evidence_current(
    held: &HeldLocalBackendEvidence,
    evidence: &DirectoryEvidence,
    backend: CertifiedLocalBackend,
    mount_id: u64,
) -> Result<(), HeldTreeError> {
    with_fd(held, |fd| crate::backend::require_held_fd_acl_absent(fd)).map_err(|reason| {
        HeldTreeError::Certification {
            path: evidence.relative_path.clone(),
            reason,
        }
    })?;
    let inspected = inspect_held(held, &evidence.relative_path)?;
    require_owner(
        &evidence.relative_path,
        inspected.uid,
        rustix::process::geteuid().as_raw(),
    )?;
    if inspected.gid != evidence.group_gid || inspected.mode != evidence.observed_mode {
        return Err(HeldTreeError::IdentityChanged(
            evidence.relative_path.clone(),
        ));
    }
    require_boundary(&evidence.relative_path, backend, mount_id, &inspected)
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

const MANIFEST_V3_MAX_SEGMENT_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum ManifestV3CodecError {
    #[error("one v3 manifest record exceeds the 1 MiB segment payload limit")]
    RecordTooLarge,
    #[error("v3 manifest aggregate or record length overflow")]
    LengthOverflow,
    #[error("v3 manifest segment record count does not match its payload")]
    RecordCountMismatch,
    #[error("v3 manifest segment contains trailing bytes")]
    TrailingBytes,
    #[error("v3 manifest contains an invalid kind or content tag")]
    InvalidTag,
    #[error("v3 manifest kind and content proof do not match")]
    KindContentMismatch,
    #[error("v3 manifest contains invalid timestamp nanoseconds")]
    InvalidNanoseconds,
    #[error("v3 manifest contains an invalid mode")]
    InvalidMode,
    #[error("v3 manifest path is not a canonical confined root-relative path")]
    InvalidPath,
    #[error("v3 manifest paths are not in strict canonical order")]
    InvalidOrder,
    #[error("v3 manifest does not begin with its directory root")]
    InvalidRoot,
    #[error("v3 manifest entry has no committed directory parent")]
    MissingParent,
    #[error("v3 manifest exceeds its existing held-tree {0:?} limit")]
    Limit(HeldTreeLimit),
    #[error("v3 manifest total record count does not match the declared count")]
    EntryCountMismatch,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ManifestV3StreamError<E> {
    Codec(ManifestV3CodecError),
    Emit(E),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ManifestV3VisitError<E> {
    Codec(ManifestV3CodecError),
    Visit(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestV3RecordKind {
    Directory,
    Regular,
    Symlink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestV3RecordContent<'a> {
    Directory,
    Regular {
        size: u64,
        nlink: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        ctime_sec: i64,
        ctime_nsec: u32,
        sha256: [u8; 32],
        xattr_count: u64,
        xattr_value_bytes: u64,
        xattr_sha256: [u8; 32],
    },
    Symlink {
        target: &'a [u8],
    },
}

/// One fully validated, allocation-free view into a bounded v3 segment.
/// Borrowed bytes cannot outlive the segment callback and carry no filesystem
/// or recovery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestV3Record<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) kind: ManifestV3RecordKind,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) incarnation: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
    pub(crate) content: ManifestV3RecordContent<'a>,
}

/// Incremental decoder for the exact v3 fingerprint record stream. It retains
/// one previous path plus offsets for its active directory ancestor chain,
/// rather than every decoded directory path.
/// Counters and digest state grant no filesystem or recovery authority.
pub(crate) struct ManifestV3Decoder {
    expected_entries: u64,
    decoded_entries: u64,
    limits: HeldTreeLimits,
    path_bytes: u64,
    manifest_bytes: u64,
    xattr_bytes: u64,
    decoded_directories: u64,
    directory_ancestor_ends: Vec<usize>,
    previous_path: Option<Vec<u8>>,
    digest: Sha256,
}

impl ManifestV3Decoder {
    pub(crate) fn new(expected_entries: u64) -> Result<Self, ManifestV3CodecError> {
        Self::with_limits(expected_entries, HeldTreeLimits::default())
    }

    fn with_limits(
        expected_entries: u64,
        limits: HeldTreeLimits,
    ) -> Result<Self, ManifestV3CodecError> {
        if expected_entries == 0 {
            return Err(ManifestV3CodecError::InvalidRoot);
        }
        if expected_entries > limits.max_entries {
            return Err(ManifestV3CodecError::Limit(HeldTreeLimit::Entries));
        }
        let mut digest = Sha256::new();
        digest.update(MANIFEST_DOMAIN_V3);
        digest.update(expected_entries.to_be_bytes());
        Ok(Self {
            expected_entries,
            decoded_entries: 0,
            limits,
            path_bytes: 0,
            manifest_bytes: 0,
            xattr_bytes: 0,
            decoded_directories: 0,
            directory_ancestor_ends: Vec::new(),
            previous_path: None,
            digest,
        })
    }

    /// Consumes exactly `record_count` complete records and rejects any bytes
    /// left in this segment. Records therefore cannot straddle segments.
    pub(crate) fn push_segment(
        &mut self,
        record_count: u64,
        payload: &[u8],
    ) -> Result<(), ManifestV3CodecError> {
        match self.push_segment_with(record_count, payload, |_| {
            Ok::<(), std::convert::Infallible>(())
        }) {
            Ok(()) => Ok(()),
            Err(ManifestV3VisitError::Codec(error)) => Err(error),
            Err(ManifestV3VisitError::Visit(never)) => match never {},
        }
    }

    /// Visits each complete validated record without allocating its path,
    /// symlink target, or content fields. A visitor error consumes partial
    /// decoder state, so callers must discard the decoder on error. The visitor
    /// must remain authority-neutral: the enclosing sidecar fold returns its
    /// accumulator only after aggregate counts, root commitment, and EOF pass.
    pub(crate) fn push_segment_with<E>(
        &mut self,
        record_count: u64,
        payload: &[u8],
        mut visit: impl FnMut(ManifestV3Record<'_>) -> Result<(), E>,
    ) -> Result<(), ManifestV3VisitError<E>> {
        if record_count == 0 {
            return Err(ManifestV3VisitError::Codec(
                ManifestV3CodecError::RecordCountMismatch,
            ));
        }
        if payload.len() > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
            return Err(ManifestV3VisitError::Codec(
                ManifestV3CodecError::RecordTooLarge,
            ));
        }
        let mut input = payload;
        for _ in 0..record_count {
            let record = self
                .decode_record(&mut input)
                .map_err(ManifestV3VisitError::Codec)?;
            visit(record).map_err(ManifestV3VisitError::Visit)?;
        }
        if !input.is_empty() {
            return Err(ManifestV3VisitError::Codec(
                ManifestV3CodecError::TrailingBytes,
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<DurableTreeManifest, ManifestV3CodecError> {
        if self.decoded_entries != self.expected_entries {
            return Err(ManifestV3CodecError::EntryCountMismatch);
        }
        Ok(DurableTreeManifest {
            schema_version: CONTENT_PROOF_VERSION,
            entry_count: self.decoded_entries,
            sha256: self.digest.finalize().into(),
        })
    }

    /// Path/component ordering keeps a directory subtree contiguous. Ancestor
    /// offsets refer to `previous_path`; pop completed subtrees until the direct
    /// parent is the stack top. The surviving prefix bytes are identical in the
    /// current path, so a directory record can append its end offset before the
    /// previous-path buffer is replaced.
    fn retain_directory_parent(&mut self, parent: &[u8]) -> bool {
        let previous = self
            .previous_path
            .as_deref()
            .expect("non-root records always have one previous path");
        while let Some(end) = self.directory_ancestor_ends.last().copied() {
            if previous.get(..end) == Some(parent) {
                return true;
            }
            self.directory_ancestor_ends.pop();
        }
        false
    }

    fn decode_record<'a>(
        &mut self,
        input: &mut &'a [u8],
    ) -> Result<ManifestV3Record<'a>, ManifestV3CodecError> {
        let encoded_record = *input;
        if self.decoded_entries >= self.expected_entries {
            return Err(ManifestV3CodecError::EntryCountMismatch);
        }
        let path_len = take_u64(input)?;
        let path_len =
            usize::try_from(path_len).map_err(|_| ManifestV3CodecError::LengthOverflow)?;
        let path = take(input, path_len)?;
        validate_manifest_path(path, self.limits.max_depth)?;
        if self.decoded_entries == 0 {
            if !path.is_empty() {
                return Err(ManifestV3CodecError::InvalidRoot);
            }
        } else {
            if path.is_empty() {
                return Err(ManifestV3CodecError::InvalidRoot);
            }
            if self.previous_path.as_deref().is_some_and(|previous| {
                compare_manifest_paths(previous, path) != std::cmp::Ordering::Less
            }) {
                return Err(ManifestV3CodecError::InvalidOrder);
            }
            let parent = path_parent_bytes(path).ok_or(ManifestV3CodecError::InvalidPath)?;
            if !self.retain_directory_parent(parent) {
                return Err(ManifestV3CodecError::MissingParent);
            }
        }

        let kind_tag = *take(input, 1)?.first().unwrap();
        if kind_tag > 3 {
            return Err(ManifestV3CodecError::InvalidTag);
        }
        let fixed = take(input, 24 + 4 + 4 + 4)?;
        let device = u64::from_be_bytes(fixed[0..8].try_into().unwrap());
        let inode = u64::from_be_bytes(fixed[8..16].try_into().unwrap());
        let incarnation = u64::from_be_bytes(fixed[16..24].try_into().unwrap());
        let uid = u32::from_be_bytes(fixed[24..28].try_into().unwrap());
        let gid = u32::from_be_bytes(fixed[28..32].try_into().unwrap());
        let mode = u32::from_be_bytes(fixed[32..36].try_into().unwrap());
        if mode & !0o7777 != 0 {
            return Err(ManifestV3CodecError::InvalidMode);
        }
        let content_tag = *take(input, 1)?.first().unwrap();
        if kind_tag == 3 {
            return Err(if content_tag <= 2 {
                ManifestV3CodecError::KindContentMismatch
            } else {
                ManifestV3CodecError::InvalidTag
            });
        }
        let kind = match kind_tag {
            0 => ManifestV3RecordKind::Directory,
            1 => ManifestV3RecordKind::Regular,
            2 => ManifestV3RecordKind::Symlink,
            _ => unreachable!("kind tag 3 returned above"),
        };
        let content = match (kind, content_tag) {
            (ManifestV3RecordKind::Directory, 0) => ManifestV3RecordContent::Directory,
            (ManifestV3RecordKind::Regular, 1) => {
                let fields = take(input, 8 + 8 + 8 + 4 + 8 + 4 + 32 + 8 + 8 + 32)?;
                let mtime_nsec = u32::from_be_bytes(fields[24..28].try_into().unwrap());
                let ctime_nsec = u32::from_be_bytes(fields[36..40].try_into().unwrap());
                if mtime_nsec >= 1_000_000_000 || ctime_nsec >= 1_000_000_000 {
                    return Err(ManifestV3CodecError::InvalidNanoseconds);
                }
                let xattr_value_bytes = u64::from_be_bytes(fields[80..88].try_into().unwrap());
                self.xattr_bytes = self
                    .xattr_bytes
                    .checked_add(xattr_value_bytes)
                    .ok_or(ManifestV3CodecError::LengthOverflow)?;
                if self.xattr_bytes > self.limits.max_xattr_bytes {
                    return Err(ManifestV3CodecError::Limit(HeldTreeLimit::ContentBytes));
                }
                ManifestV3RecordContent::Regular {
                    size: u64::from_be_bytes(fields[0..8].try_into().unwrap()),
                    nlink: u64::from_be_bytes(fields[8..16].try_into().unwrap()),
                    mtime_sec: i64::from_be_bytes(fields[16..24].try_into().unwrap()),
                    mtime_nsec,
                    ctime_sec: i64::from_be_bytes(fields[28..36].try_into().unwrap()),
                    ctime_nsec,
                    sha256: fields[40..72].try_into().unwrap(),
                    xattr_count: u64::from_be_bytes(fields[72..80].try_into().unwrap()),
                    xattr_value_bytes,
                    xattr_sha256: fields[88..120].try_into().unwrap(),
                }
            }
            (ManifestV3RecordKind::Symlink, 2) => {
                let target_len = take_u64(input)?;
                let target_len = usize::try_from(target_len)
                    .map_err(|_| ManifestV3CodecError::LengthOverflow)?;
                ManifestV3RecordContent::Symlink {
                    target: take(input, target_len)?,
                }
            }
            (_, 0..=2) => return Err(ManifestV3CodecError::KindContentMismatch),
            (_, _) => return Err(ManifestV3CodecError::InvalidTag),
        };

        let path_len_u64 =
            u64::try_from(path.len()).map_err(|_| ManifestV3CodecError::LengthOverflow)?;
        self.path_bytes = self
            .path_bytes
            .checked_add(path_len_u64)
            .ok_or(ManifestV3CodecError::LengthOverflow)?;
        if self.path_bytes > self.limits.max_path_bytes {
            return Err(ManifestV3CodecError::Limit(HeldTreeLimit::PathBytes));
        }
        self.manifest_bytes = self
            .manifest_bytes
            .checked_add(std::mem::size_of::<ManifestEntry>() as u64)
            .and_then(|value| value.checked_add(path_len_u64))
            .ok_or(ManifestV3CodecError::LengthOverflow)?;
        if self.manifest_bytes > self.limits.max_manifest_bytes {
            return Err(ManifestV3CodecError::Limit(HeldTreeLimit::ManifestBytes));
        }
        if kind == ManifestV3RecordKind::Directory {
            if self.decoded_directories >= self.limits.max_directories {
                return Err(ManifestV3CodecError::Limit(HeldTreeLimit::Directories));
            }
            self.decoded_directories = self
                .decoded_directories
                .checked_add(1)
                .ok_or(ManifestV3CodecError::LengthOverflow)?;
            debug_assert!(
                self.directory_ancestor_ends
                    .last()
                    .is_none_or(|end| *end < path.len() || path.is_empty())
            );
            self.directory_ancestor_ends.push(path.len());
        }
        if self.decoded_entries == 0 && kind != ManifestV3RecordKind::Directory {
            return Err(ManifestV3CodecError::InvalidRoot);
        }
        let consumed = encoded_record.len() - input.len();
        self.digest.update(&encoded_record[..consumed]);
        match &mut self.previous_path {
            Some(previous) => {
                previous.clear();
                previous.extend_from_slice(path);
            }
            None => self.previous_path = Some(path.to_vec()),
        }
        self.decoded_entries += 1;
        Ok(ManifestV3Record {
            path,
            kind,
            device,
            inode,
            incarnation,
            uid,
            gid,
            mode,
            content,
        })
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], ManifestV3CodecError> {
    if input.len() < length {
        return Err(ManifestV3CodecError::RecordCountMismatch);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn take_u64(input: &mut &[u8]) -> Result<u64, ManifestV3CodecError> {
    Ok(u64::from_be_bytes(take(input, 8)?.try_into().unwrap()))
}

/// Historical schema-v3 ordering is Rust `Path`/component ordering over raw
/// Unix component bytes. Encoding uses raw bytes, but comparing the entire
/// encoded path slice would change durable fingerprints for prefix siblings.
pub(crate) fn compare_manifest_paths(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    Path::new(OsStr::from_bytes(left)).cmp(Path::new(OsStr::from_bytes(right)))
}

fn validate_manifest_path(path: &[u8], max_depth: u32) -> Result<(), ManifestV3CodecError> {
    if path.contains(&0) {
        return Err(ManifestV3CodecError::InvalidPath);
    }
    if path.is_empty() {
        return Ok(());
    }
    let mut depth = 0_u32;
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || matches!(component, b"." | b"..") {
            return Err(ManifestV3CodecError::InvalidPath);
        }
        depth = depth
            .checked_add(1)
            .ok_or(ManifestV3CodecError::LengthOverflow)?;
    }
    if depth > max_depth {
        return Err(ManifestV3CodecError::Limit(HeldTreeLimit::Depth));
    }
    Ok(())
}

fn path_parent_bytes(path: &[u8]) -> Option<&[u8]> {
    path.iter()
        .rposition(|byte| *byte == b'/')
        .map_or(Some(&[][..]), |position| Some(&path[..position]))
}

fn emit_manifest_entry_v3(entry: &ManifestEntry, emit: impl FnMut(&[u8])) {
    emit_manifest_entry_v3_with_mode(entry, entry.mode, emit);
}

fn emit_manifest_entry_v3_with_mode(entry: &ManifestEntry, mode: u32, mut emit: impl FnMut(&[u8])) {
    let path = entry.path.as_os_str().as_bytes();
    emit(&(path.len() as u64).to_be_bytes());
    emit(path);
    emit(&[match entry.identity.kind {
        NodeKind::Directory => 0,
        NodeKind::Regular => 1,
        NodeKind::Symlink => 2,
        NodeKind::Other => 3,
    }]);
    emit(&entry.identity.device.to_be_bytes());
    emit(&entry.identity.inode.to_be_bytes());
    emit(&entry.identity.incarnation.to_be_bytes());
    emit(&entry.uid.to_be_bytes());
    emit(&entry.gid.to_be_bytes());
    emit(&mode.to_be_bytes());
    match &entry.content {
        ContentProof::Legacy => emit(&[0xff]),
        ContentProof::Directory => emit(&[0]),
        ContentProof::Regular {
            size,
            nlink,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            sha256,
            xattrs,
        } => {
            emit(&[1]);
            emit(&size.to_be_bytes());
            emit(&nlink.to_be_bytes());
            emit(&mtime_sec.to_be_bytes());
            emit(&mtime_nsec.to_be_bytes());
            emit(&ctime_sec.to_be_bytes());
            emit(&ctime_nsec.to_be_bytes());
            emit(sha256);
            emit(&xattrs.attribute_count.to_be_bytes());
            emit(&xattrs.value_bytes.to_be_bytes());
            emit(&xattrs.sha256);
        }
        ContentProof::Symlink { target } => {
            emit(&[2]);
            emit(&(target.len() as u64).to_be_bytes());
            emit(target);
        }
    }
}

fn manifest_entry_v3_len(entry: &ManifestEntry) -> Result<usize, ManifestV3CodecError> {
    let mut length = Some(0_usize);
    emit_manifest_entry_v3(entry, |bytes| {
        length = length.and_then(|current| current.checked_add(bytes.len()));
    });
    length.ok_or(ManifestV3CodecError::LengthOverflow)
}

/// Emits each complete canonical v3 record from one reused buffer. This is the
/// unsplit record seam consumed by the unpublished external-sort spool.
fn stream_manifest_v3_records<E>(
    manifest: &[ManifestEntry],
    mut emit_record: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), ManifestV3StreamError<E>> {
    let mut record = Vec::with_capacity(MANIFEST_V3_MAX_SEGMENT_PAYLOAD);
    for entry in manifest {
        let record_len = manifest_entry_v3_len(entry).map_err(ManifestV3StreamError::Codec)?;
        if record_len > MANIFEST_V3_MAX_SEGMENT_PAYLOAD {
            return Err(ManifestV3StreamError::Codec(
                ManifestV3CodecError::RecordTooLarge,
            ));
        }
        record.clear();
        emit_manifest_entry_v3(entry, |bytes| record.extend_from_slice(bytes));
        debug_assert_eq!(record.len(), record_len);
        emit_record(&record).map_err(ManifestV3StreamError::Emit)?;
    }
    Ok(())
}

/// Emits complete canonical v3 records in segments no larger than 1 MiB. The
/// single reusable `Vec` is flushed before a record that would cross the bound.
fn stream_manifest_v3_segments<E>(
    manifest: &[ManifestEntry],
    max_payload: usize,
    mut emit_segment: impl FnMut(u64, &[u8]) -> Result<(), E>,
) -> Result<(), ManifestV3StreamError<E>> {
    let max_payload = max_payload.min(MANIFEST_V3_MAX_SEGMENT_PAYLOAD);
    let mut payload = Vec::with_capacity(max_payload);
    let mut records = 0_u64;
    for entry in manifest {
        let record_len = manifest_entry_v3_len(entry).map_err(ManifestV3StreamError::Codec)?;
        if record_len > max_payload {
            return Err(ManifestV3StreamError::Codec(
                ManifestV3CodecError::RecordTooLarge,
            ));
        }
        if records != 0 && payload.len() + record_len > max_payload {
            emit_segment(records, &payload).map_err(ManifestV3StreamError::Emit)?;
            payload.clear();
            records = 0;
        }
        emit_manifest_entry_v3(entry, |bytes| payload.extend_from_slice(bytes));
        debug_assert!(payload.len() <= max_payload);
        records = records.checked_add(1).ok_or(ManifestV3StreamError::Codec(
            ManifestV3CodecError::LengthOverflow,
        ))?;
    }
    if records != 0 {
        emit_segment(records, &payload).map_err(ManifestV3StreamError::Emit)?;
    }
    Ok(())
}

fn fingerprint_manifest_v1(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    fingerprint_manifest(manifest, 1)
}

fn fingerprint_manifest_v2(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    fingerprint_manifest(manifest, LEGACY_CONTENT_PROOF_VERSION)
}

fn fingerprint_manifest_v3(manifest: &[ManifestEntry]) -> HeldTreeFingerprint {
    let mut digest = Sha256::new();
    digest.update(MANIFEST_DOMAIN_V3);
    digest.update((manifest.len() as u64).to_be_bytes());
    for entry in manifest {
        emit_manifest_entry_v3(entry, |bytes| digest.update(bytes));
    }
    HeldTreeFingerprint {
        schema_version: CONTENT_PROOF_VERSION,
        entry_count: manifest.len() as u64,
        sha256: digest.finalize().into(),
    }
}

fn fingerprint_manifest(manifest: &[ManifestEntry], schema_version: u16) -> HeldTreeFingerprint {
    if schema_version == CONTENT_PROOF_VERSION {
        return fingerprint_manifest_v3(manifest);
    }
    let mut digest = Sha256::new();
    digest.update(match schema_version {
        1 => MANIFEST_DOMAIN_V1,
        LEGACY_CONTENT_PROOF_VERSION => MANIFEST_DOMAIN_V2,
        _ => {
            debug_assert!(false, "unsupported held-tree fingerprint schema");
            b"degu-held-tree-manifest-unsupported\0"
        }
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
        if schema_version != 1 {
            match &entry.content {
                ContentProof::Legacy => {
                    debug_assert!(false, "content fingerprint requires content proof");
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
                    ..
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
    /// Regular-file and symlink bytes plus ordinary xattr value bytes. This
    /// preserves the existing metadata assessment/reporting definition.
    content_bytes: u64,
    /// Regular-file and symlink bytes only. The production default is
    /// unbounded, but tests may inject a finite cap.
    payload_bytes: u64,
    /// Ordinary regular-file xattr value bytes only. These remain bounded
    /// independently because values are materialized while proof hashes them.
    xattr_bytes: u64,
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
            payload_bytes: 0,
            xattr_bytes: 0,
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

    fn remaining_xattr_bytes(&self) -> u64 {
        self.limits.max_xattr_bytes.saturating_sub(self.xattr_bytes)
    }

    fn xattr_read_budget(&self) -> XattrReadBudget {
        XattrReadBudget::new(self.remaining_xattr_bytes(), self.limits.max_xattr_bytes)
    }

    fn add_content(&mut self, bytes: u64) -> Result<(), HeldTreeError> {
        self.content_bytes = checked_content_add(self.content_bytes, bytes)?;
        self.payload_bytes = checked_content_add(self.payload_bytes, bytes)?;
        if let Some(limit) = self.limits.max_content_bytes {
            check(self.payload_bytes, limit, HeldTreeLimit::ContentBytes)?;
        }
        Ok(())
    }

    fn add_xattrs(&mut self, bytes: u64) -> Result<(), HeldTreeError> {
        self.content_bytes = checked_content_add(self.content_bytes, bytes)?;
        self.xattr_bytes = checked_content_add(self.xattr_bytes, bytes)?;
        check(
            self.xattr_bytes,
            self.limits.max_xattr_bytes,
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

fn checked_content_add(current: u64, bytes: u64) -> Result<u64, HeldTreeError> {
    current.checked_add(bytes).ok_or(HeldTreeError::Limit {
        kind: HeldTreeLimit::ContentBytes,
        limit: u64::MAX,
    })
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
