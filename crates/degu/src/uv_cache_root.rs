//! Descriptor-bound authority for one explicitly selected uv cache root.
//!
//! This module proves only the filesystem scope audited for `uv 0.12.3 cache
//! prune`. It neither declares nor executes an action. The command owner must
//! supply one lexical root selection; discovery roots and quota-observation
//! paths cannot construct this proof.

use crate::uv_executable::{AUDITED_UV_PRUNE_VERSION, ProbedUvExecutable, UvVersion};
use degu_adapters::RegisteredAdapter;
use degu_core::ecosystem::DetectCtx;
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const MAX_ROOT_PATH_BYTES: usize = 4096;
const MAX_VERIFIED_ENTRIES: usize = 1_000_000;
const MAX_TRAVERSAL_DEPTH: usize = 256;
const SHARED_WRITE_MASK: u32 = 0o022;
const REQUIRED_DIRECTORY_MODE: u32 = 0o700;
const MAX_ACL_XATTR_LIST_BYTES: usize = 64 * 1024;

/// Exact `CacheBucket::to_str` values at uv commit
/// `507230998c9541d67814b57463ac00e454ff6991` (tag `0.12.3`). A present
/// current bucket must be a real, private directory even when ordinary prune
/// does not descend into that particular bucket.
const KNOWN_BUCKETS: [&str; 12] = [
    "sdists-v9",
    "flat-index-v4",
    "git-v0",
    "interpreter-v4",
    "simple-v24",
    "wheels-v6",
    "archive-v0",
    "builds-v0",
    "environments-v2",
    "python-v0",
    "binaries-v0",
    "osv-v0",
];

/// Ordinary, non-`--ci` prune descends into these buckets: source pruning and
/// reference collection walk sdists/wheels; prune directly reads environments
/// and archives. The remaining known buckets are recognized but not traversed.
const TRAVERSED_BUCKETS: [&str; 4] = ["sdists-v9", "wheels-v6", "archive-v0", "environments-v2"];

const SKIPPED_TOP_LEVEL_ENTRIES: [&str; 4] = ["CACHEDIR.TAG", ".gitignore", ".git", ".lock"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UvCacheRootSelection(PathBuf);

impl UvCacheRootSelection {
    /// Lexical policy only. Filesystem authority is minted exclusively by
    /// [`seal_uv_cache_root`].
    pub(crate) fn explicit(path: PathBuf) -> Result<Self, UvCacheRootSealError> {
        if path.as_os_str().as_bytes().len() > MAX_ROOT_PATH_BYTES {
            return Err(UvCacheRootSealError::SelectionTooLarge);
        }
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(UvCacheRootSealError::SelectionNotAbsolute);
        }
        let Some(Component::Normal(_)) = components.next() else {
            return Err(UvCacheRootSealError::SelectionNotNormalized);
        };
        if !components.all(|component| matches!(component, Component::Normal(_)))
            || path.as_os_str().as_bytes().contains(&0)
        {
            return Err(UvCacheRootSealError::SelectionNotNormalized);
        }
        Ok(Self(path))
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Private, non-cloneable proof for one exact root object and its audited
/// top-level bucket attachments. Held descriptors prevent inode reuse while the
/// proof exists. Revalidation repeats the full traversed-namespace check before
/// a future spawn.
pub(crate) struct SealedUvCacheRoot {
    selection: UvCacheRootSelection,
    version: UvVersion,
    canonical_path: PathBuf,
    root: OwnedFd,
    identity: DirectoryIdentity,
    mount: degu_walk::mount::MountIdentity,
    buckets: Vec<BucketSeal>,
    tag: EntrySeal,
    lock: EntrySeal,
}

impl SealedUvCacheRoot {
    pub(crate) fn selection(&self) -> &UvCacheRootSelection {
        &self.selection
    }

    pub(crate) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn revalidate_for_executable(
        &self,
        executable: &ProbedUvExecutable,
    ) -> Result<(), UvCacheRootSealError> {
        self.require_version(executable.version())?;
        self.revalidate()
    }

    fn require_version(&self, version: UvVersion) -> Result<(), UvCacheRootSealError> {
        if version == self.version && version == AUDITED_UV_PRUNE_VERSION {
            Ok(())
        } else {
            Err(UvCacheRootSealError::ExecutableVersionMismatch)
        }
    }

    /// Revalidate both path attachment and every namespace uv 0.12.3 ordinary
    /// prune can traverse. A failure is a pre-spawn refusal, not permission to
    /// fall back to an unsealed path.
    pub(crate) fn revalidate(&self) -> Result<(), UvCacheRootSealError> {
        let opened = open_selected_root(&self.selection)?;
        if opened.canonical_path != self.canonical_path
            || opened.identity != self.identity
            || opened.mount != self.mount
        {
            return Err(UvCacheRootSealError::RootChanged);
        }
        let held = rustix::fs::fstat(&self.root)
            .map_err(|source| inspect(&self.canonical_path, io::Error::from(source)))?;
        require_identity(&held, self.identity, &self.canonical_path)?;
        require_private_directory(&self.root, &held, &self.canonical_path)?;
        let held_mount = degu_walk::mount::identity_for_fd(&self.root, &self.canonical_path)
            .map_err(|source| inspect(&self.canonical_path, source))?;
        if held_mount != self.mount {
            return Err(UvCacheRootSealError::RootChanged);
        }
        revalidate_fixed_entries(
            &self.root,
            &self.canonical_path,
            &self.mount,
            &self.buckets,
            &self.tag,
            &self.lock,
        )?;
        verify_prune_namespace(&self.root, &self.canonical_path, &self.mount)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

struct OpenedRoot {
    canonical_path: PathBuf,
    root: OwnedFd,
    identity: DirectoryIdentity,
    mount: degu_walk::mount::MountIdentity,
}

struct BucketSeal {
    name: &'static str,
    entry: EntrySeal,
}

enum EntrySeal {
    Missing,
    Present {
        object: OwnedFd,
        identity: DirectoryIdentity,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UvCacheRootSealError {
    #[error("uv cache root selection exceeds the 4096-byte bound")]
    SelectionTooLarge,
    #[error("uv cache root selection is not absolute")]
    SelectionNotAbsolute,
    #[error("uv cache root selection is not lexically normalized")]
    SelectionNotNormalized,
    #[error("cache-root proof requires the uv adapter, not {0:?}")]
    NonUvAdapter(&'static str),
    #[error("uv root discovery was incomplete or truncated; refusing mutation authority")]
    IncompleteDiscovery,
    #[error("uv root discovery resolved {0} roots; exactly one existing root is required")]
    AmbiguousDiscovery(usize),
    #[error("explicit uv cache-root selection does not name the uniquely discovered uv root")]
    SelectionMismatch,
    #[error("uv cache root contains HOME and would let prune delete user state")]
    ContainsHome,
    #[error("uv cache root lacks the uv 0.12.3 `sdists-v9` scaffold")]
    MissingUvScaffold,
    #[error("uv cache-root proof is not paired with the executable version that minted it")]
    ExecutableVersionMismatch,
    #[error("uv {found} is not the exact prune layout audited by this build ({audited})")]
    UnsupportedVersion {
        found: UvVersion,
        audited: UvVersion,
    },
    #[error("failed to inspect uv cache root at {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("uv cache root is unsafe at {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: &'static str },
    #[error("failed to inspect filesystem ACLs at {path}: {source}")]
    AclInspection {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("selected uv cache root or one of its namespace attachments changed")]
    RootChanged,
    #[error("uv cache bucket {name:?} changed after it was sealed")]
    BucketChanged { name: &'static str },
    #[error("uv cache lock entry changed after it was sealed")]
    LockChanged,
    #[error("uv prune namespace exceeds the {MAX_VERIFIED_ENTRIES}-entry verification bound")]
    EntryLimitExceeded,
    #[error("uv prune namespace exceeds the {MAX_TRAVERSAL_DEPTH}-directory depth bound")]
    DepthLimitExceeded,
}

pub(crate) fn seal_uv_cache_root(
    registration: &RegisteredAdapter,
    ctx: &DetectCtx,
    selection: UvCacheRootSelection,
    executable: &ProbedUvExecutable,
) -> Result<SealedUvCacheRoot, UvCacheRootSealError> {
    let discovered = require_unique_discovered_root(registration, ctx)?;
    reject_selected_root_containing_home(ctx, &selection)?;
    let sealed = seal_uv_cache_root_for_version(selection, executable.version())?;
    require_selection_matches_discovery(&discovered, &sealed)?;
    reject_root_containing_home(ctx, &sealed)?;
    Ok(sealed)
}

fn reject_selected_root_containing_home(
    ctx: &DetectCtx,
    selection: &UvCacheRootSelection,
) -> Result<(), UvCacheRootSealError> {
    let selected = std::fs::canonicalize(selection.as_path())
        .map_err(|source| inspect(selection.as_path(), source))?;
    let home = std::fs::canonicalize(&ctx.home).map_err(|source| inspect(&ctx.home, source))?;
    if home.starts_with(selected) {
        Err(UvCacheRootSealError::ContainsHome)
    } else {
        Ok(())
    }
}

fn reject_root_containing_home(
    ctx: &DetectCtx,
    sealed: &SealedUvCacheRoot,
) -> Result<(), UvCacheRootSealError> {
    let home = std::fs::canonicalize(&ctx.home).map_err(|source| inspect(&ctx.home, source))?;
    if home.starts_with(&sealed.canonical_path) {
        return Err(UvCacheRootSealError::ContainsHome);
    }
    // `canonicalize` does not collapse Linux bind-mount aliases. Compare the
    // held root object with HOME and every physical ancestor so `/mnt/cache`
    // cannot mint authority when it is another attachment of HOME or `/home`.
    if identity_matches_home_or_ancestor(sealed.identity, &home)? {
        Err(UvCacheRootSealError::ContainsHome)
    } else {
        Ok(())
    }
}

fn identity_matches_home_or_ancestor(
    root: DirectoryIdentity,
    canonical_home: &Path,
) -> Result<bool, UvCacheRootSealError> {
    for ancestor in canonical_home.ancestors() {
        let directory = open_directory(rustix::fs::CWD, ancestor, ancestor)?;
        let stat = rustix::fs::fstat(&directory)
            .map_err(|source| inspect(ancestor, io::Error::from(source)))?;
        if directory_identity(&stat, ancestor)? == root {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_selection_matches_discovery(
    discovered: &Path,
    sealed: &SealedUvCacheRoot,
) -> Result<(), UvCacheRootSealError> {
    let canonical =
        std::fs::canonicalize(discovered).map_err(|source| inspect(discovered, source))?;
    if canonical == sealed.canonical_path {
        Ok(())
    } else {
        Err(UvCacheRootSealError::SelectionMismatch)
    }
}

fn require_unique_discovered_root(
    registration: &RegisteredAdapter,
    ctx: &DetectCtx,
) -> Result<PathBuf, UvCacheRootSealError> {
    if registration.id() != "uv" {
        return Err(UvCacheRootSealError::NonUvAdapter(registration.id()));
    }
    let outcome = registration.ecosystem().roots(ctx);
    if outcome.incomplete || outcome.truncated || !outcome.failures.is_empty() {
        return Err(UvCacheRootSealError::IncompleteDiscovery);
    }
    if outcome.roots.len() != 1 {
        return Err(UvCacheRootSealError::AmbiguousDiscovery(
            outcome.roots.len(),
        ));
    }
    Ok(outcome
        .roots
        .into_iter()
        .next()
        .expect("one root was required")
        .path)
}

fn seal_uv_cache_root_for_version(
    selection: UvCacheRootSelection,
    version: UvVersion,
) -> Result<SealedUvCacheRoot, UvCacheRootSealError> {
    if version != AUDITED_UV_PRUNE_VERSION {
        return Err(UvCacheRootSealError::UnsupportedVersion {
            found: version,
            audited: AUDITED_UV_PRUNE_VERSION,
        });
    }
    let opened = open_selected_root(&selection)?;
    let buckets = seal_buckets(&opened.root, &opened.canonical_path, &opened.mount)?;
    if !buckets.iter().any(|bucket| {
        bucket.name == "sdists-v9" && matches!(&bucket.entry, EntrySeal::Present { .. })
    }) {
        return Err(UvCacheRootSealError::MissingUvScaffold);
    }
    let tag = seal_cache_tag(&opened.root, &opened.canonical_path)?;
    let lock = seal_lock(&opened.root, &opened.canonical_path)?;
    verify_prune_namespace(&opened.root, &opened.canonical_path, &opened.mount)?;
    Ok(SealedUvCacheRoot {
        selection,
        version,
        canonical_path: opened.canonical_path,
        root: opened.root,
        identity: opened.identity,
        mount: opened.mount,
        buckets,
        tag,
        lock,
    })
}

#[cfg(test)]
pub(crate) fn seal_uv_cache_root_for_test(
    path: PathBuf,
) -> Result<SealedUvCacheRoot, UvCacheRootSealError> {
    seal_uv_cache_root_for_version(
        UvCacheRootSelection::explicit(path)?,
        AUDITED_UV_PRUNE_VERSION,
    )
}

fn open_selected_root(
    selection: &UvCacheRootSelection,
) -> Result<OpenedRoot, UvCacheRootSealError> {
    let selected = selection.as_path();
    validate_namespace_chain(selected, false)?;
    let canonical_path =
        std::fs::canonicalize(selected).map_err(|source| inspect(selected, source))?;
    if canonical_path.as_os_str().as_bytes().len() > MAX_ROOT_PATH_BYTES {
        return Err(unsafe_path(
            &canonical_path,
            "canonical cache root exceeds the 4096-byte bound",
        ));
    }
    validate_namespace_chain(&canonical_path, true)?;
    let root = open_directory(rustix::fs::CWD, &canonical_path, &canonical_path)?;
    let stat = rustix::fs::fstat(&root)
        .map_err(|source| inspect(&canonical_path, io::Error::from(source)))?;
    require_private_directory(&root, &stat, &canonical_path)?;
    let selected_metadata =
        std::fs::metadata(selected).map_err(|source| inspect(selected, source))?;
    let identity = directory_identity(&stat, &canonical_path)?;
    if selected_metadata.dev() != identity.device || selected_metadata.ino() != identity.inode {
        return Err(UvCacheRootSealError::RootChanged);
    }
    let mount = degu_walk::mount::identity_for_fd(&root, &canonical_path)
        .map_err(|source| inspect(&canonical_path, source))?;
    Ok(OpenedRoot {
        canonical_path,
        root,
        identity,
        mount,
    })
}

fn seal_buckets(
    root: &OwnedFd,
    root_path: &Path,
    root_mount: &degu_walk::mount::MountIdentity,
) -> Result<Vec<BucketSeal>, UvCacheRootSealError> {
    KNOWN_BUCKETS
        .into_iter()
        .map(|name| {
            Ok(BucketSeal {
                name,
                entry: seal_directory_entry(root, root_path, name, root_mount)?,
            })
        })
        .collect()
}

fn seal_directory_entry(
    root: &OwnedFd,
    root_path: &Path,
    name: &'static str,
    root_mount: &degu_walk::mount::MountIdentity,
) -> Result<EntrySeal, UvCacheRootSealError> {
    let path = root_path.join(name);
    let inspected = match rustix::fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(EntrySeal::Missing),
        Err(source) => return Err(inspect(&path, io::Error::from(source))),
    };
    if FileType::from_raw_mode(inspected.st_mode) != FileType::Directory {
        return Err(unsafe_path(
            &path,
            "known uv bucket is a symlink or non-directory",
        ));
    }
    let object = open_directory(root, name, &path)?;
    let opened =
        rustix::fs::fstat(&object).map_err(|source| inspect(&path, io::Error::from(source)))?;
    require_same_object(&inspected, &opened, &path)?;
    require_private_directory(&object, &opened, &path)?;
    let mount = degu_walk::mount::identity_for_fd(&object, &path)
        .map_err(|source| inspect(&path, source))?;
    if &mount != root_mount {
        return Err(unsafe_path(
            &path,
            "known uv bucket crosses into a different mount",
        ));
    }
    Ok(EntrySeal::Present {
        identity: directory_identity(&opened, &path)?,
        object,
    })
}

fn seal_cache_tag(root: &OwnedFd, root_path: &Path) -> Result<EntrySeal, UvCacheRootSealError> {
    const NAME: &str = "CACHEDIR.TAG";
    let path = root_path.join(NAME);
    let inspected = rustix::fs::statat(root, NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|source| inspect(&path, io::Error::from(source)))?;
    if FileType::from_raw_mode(inspected.st_mode) != FileType::RegularFile
        || inspected.st_uid != rustix::process::geteuid().as_raw()
        || inspected.st_nlink != 1
        || raw_mode_u32(inspected.st_mode) & SHARED_WRITE_MASK != 0
    {
        return Err(unsafe_path(
            &path,
            "CACHEDIR.TAG is not a private, singly linked regular file",
        ));
    }
    let object = rustix::fs::openat(
        root,
        NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| inspect(&path, io::Error::from(source)))?;
    let opened =
        rustix::fs::fstat(&object).map_err(|source| inspect(&path, io::Error::from(source)))?;
    require_same_object(&inspected, &opened, &path)?;
    reject_extended_acl(&object, &path)?;
    require_cache_tag_signature(&object, &path)?;
    Ok(EntrySeal::Present {
        identity: directory_identity(&opened, &path)?,
        object,
    })
}

fn seal_lock(root: &OwnedFd, root_path: &Path) -> Result<EntrySeal, UvCacheRootSealError> {
    const NAME: &str = ".lock";
    let path = root_path.join(NAME);
    let inspected = match rustix::fs::statat(root, NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(EntrySeal::Missing),
        Err(source) => return Err(inspect(&path, io::Error::from(source))),
    };
    if FileType::from_raw_mode(inspected.st_mode) != FileType::RegularFile {
        return Err(unsafe_path(
            &path,
            "uv lock entry is a symlink or non-regular file",
        ));
    }
    if inspected.st_uid != rustix::process::geteuid().as_raw() {
        return Err(unsafe_path(
            &path,
            "uv lock entry is not owned by the effective user",
        ));
    }
    if inspected.st_nlink != 1 {
        return Err(unsafe_path(
            &path,
            "uv lock entry has another hard-link attachment",
        ));
    }
    let object = rustix::fs::openat(
        root,
        NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| inspect(&path, io::Error::from(source)))?;
    let opened =
        rustix::fs::fstat(&object).map_err(|source| inspect(&path, io::Error::from(source)))?;
    require_same_object(&inspected, &opened, &path)?;
    reject_extended_acl(&object, &path)?;
    Ok(EntrySeal::Present {
        identity: directory_identity(&opened, &path)?,
        object,
    })
}

fn revalidate_fixed_entries(
    root: &OwnedFd,
    root_path: &Path,
    root_mount: &degu_walk::mount::MountIdentity,
    buckets: &[BucketSeal],
    tag: &EntrySeal,
    lock: &EntrySeal,
) -> Result<(), UvCacheRootSealError> {
    for bucket in buckets {
        revalidate_bucket(root, root_path, root_mount, bucket)
            .map_err(|_| UvCacheRootSealError::BucketChanged { name: bucket.name })?;
    }
    revalidate_cache_tag(root, root_path, tag)?;
    revalidate_lock(root, root_path, lock).map_err(|_| UvCacheRootSealError::LockChanged)
}

fn revalidate_cache_tag(
    root: &OwnedFd,
    root_path: &Path,
    tag: &EntrySeal,
) -> Result<(), UvCacheRootSealError> {
    revalidate_entry(root, root_path, "CACHEDIR.TAG", tag)?;
    let EntrySeal::Present { object, .. } = tag else {
        return Err(UvCacheRootSealError::RootChanged);
    };
    let path = root_path.join("CACHEDIR.TAG");
    let stat =
        rustix::fs::fstat(object).map_err(|source| inspect(&path, io::Error::from(source)))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || raw_mode_u32(stat.st_mode) & SHARED_WRITE_MASK != 0
    {
        return Err(UvCacheRootSealError::RootChanged);
    }
    reject_extended_acl(object, &path)?;
    require_cache_tag_signature(object, &path)
}

fn revalidate_bucket(
    root: &OwnedFd,
    root_path: &Path,
    root_mount: &degu_walk::mount::MountIdentity,
    bucket: &BucketSeal,
) -> Result<(), UvCacheRootSealError> {
    revalidate_entry(root, root_path, bucket.name, &bucket.entry)?;
    if let EntrySeal::Present { object, .. } = &bucket.entry {
        let path = root_path.join(bucket.name);
        let stat =
            rustix::fs::fstat(object).map_err(|source| inspect(&path, io::Error::from(source)))?;
        require_private_directory(object, &stat, &path)?;
        let mount = degu_walk::mount::identity_for_fd(object, &path)
            .map_err(|source| inspect(&path, source))?;
        if &mount != root_mount {
            return Err(UvCacheRootSealError::RootChanged);
        }
    }
    Ok(())
}

fn revalidate_lock(
    root: &OwnedFd,
    root_path: &Path,
    lock: &EntrySeal,
) -> Result<(), UvCacheRootSealError> {
    revalidate_entry(root, root_path, ".lock", lock)?;
    if let EntrySeal::Present { object, .. } = lock {
        let path = root_path.join(".lock");
        let stat =
            rustix::fs::fstat(object).map_err(|source| inspect(&path, io::Error::from(source)))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
        {
            return Err(UvCacheRootSealError::RootChanged);
        }
        reject_extended_acl(object, &path)?;
    }
    Ok(())
}

fn revalidate_entry(
    root: &OwnedFd,
    root_path: &Path,
    name: &'static str,
    seal: &EntrySeal,
) -> Result<(), UvCacheRootSealError> {
    let path = root_path.join(name);
    match seal {
        EntrySeal::Missing => match rustix::fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err(UvCacheRootSealError::RootChanged),
        },
        EntrySeal::Present { object, identity } => {
            let held = rustix::fs::fstat(object)
                .map_err(|source| inspect(&path, io::Error::from(source)))?;
            require_identity(&held, *identity, &path)?;
            let attached = rustix::fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|source| inspect(&path, io::Error::from(source)))?;
            require_identity(&attached, *identity, &path)
        }
    }
}

/// Verify every real directory ordinary prune may walk or recursively remove.
/// Descriptor-relative, no-follow traversal ensures an untrusted directory is
/// rejected before any child pathname is dereferenced. All directories must be
/// EUID-owned and non-shared-writable with no extended ACL, and every directory
/// must remain on the root mount (including Linux bind mounts via statx MNT_ID).
fn verify_prune_namespace(
    root: &OwnedFd,
    root_path: &Path,
    root_mount: &degu_walk::mount::MountIdentity,
) -> Result<(), UvCacheRootSealError> {
    let mut budget = TraversalBudget::default();
    let entries = rustix::fs::Dir::read_from(root)
        .map_err(|source| inspect(root_path, io::Error::from(source)))?;
    for entry in entries {
        let entry = entry.map_err(|source| inspect(root_path, io::Error::from(source)))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        budget.consume_entry()?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string();
        let name_text = name.to_str();
        if name_text.is_some_and(|name| SKIPPED_TOP_LEVEL_ENTRIES.contains(&name)) {
            continue;
        }
        let path = root_path.join(&name);
        let stat = rustix::fs::statat(root, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| inspect(&path, io::Error::from(source)))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            continue;
        }
        let Some(name_text) = name_text else {
            // A non-UTF-8 top-level directory cannot equal a current bucket and
            // is therefore a stale directory that prune recursively removes.
            let directory = open_verified_child(root, &name, &path, &stat, root_mount)?;
            verify_directory_tree(&directory, &path, root_mount, &mut budget, 1)?;
            continue;
        };
        let known = KNOWN_BUCKETS.contains(&name_text);
        if known && !TRAVERSED_BUCKETS.contains(&name_text) {
            continue;
        }
        let directory = open_verified_child(root, &name, &path, &stat, root_mount)?;
        verify_directory_tree(&directory, &path, root_mount, &mut budget, 1)?;
    }
    Ok(())
}

fn verify_directory_tree(
    directory: &OwnedFd,
    path: &Path,
    root_mount: &degu_walk::mount::MountIdentity,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<(), UvCacheRootSealError> {
    if depth > MAX_TRAVERSAL_DEPTH {
        return Err(UvCacheRootSealError::DepthLimitExceeded);
    }
    let entries = rustix::fs::Dir::read_from(directory)
        .map_err(|source| inspect(path, io::Error::from(source)))?;
    for entry in entries {
        let entry = entry.map_err(|source| inspect(path, io::Error::from(source)))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        budget.consume_entry()?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string();
        let child_path = path.join(&name);
        let stat = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| inspect(&child_path, io::Error::from(source)))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            continue;
        }
        let child = open_verified_child(directory, &name, &child_path, &stat, root_mount)?;
        let child_depth = depth
            .checked_add(1)
            .ok_or(UvCacheRootSealError::DepthLimitExceeded)?;
        verify_directory_tree(&child, &child_path, root_mount, budget, child_depth)?;
    }
    Ok(())
}

fn open_verified_child<Fd: rustix::fd::AsFd>(
    parent: Fd,
    name: &OsStr,
    path: &Path,
    inspected: &Stat,
    root_mount: &degu_walk::mount::MountIdentity,
) -> Result<OwnedFd, UvCacheRootSealError> {
    let directory = open_directory(parent, name, path)?;
    let opened =
        rustix::fs::fstat(&directory).map_err(|source| inspect(path, io::Error::from(source)))?;
    require_same_object(inspected, &opened, path)?;
    require_private_directory(&directory, &opened, path)?;
    let mount = degu_walk::mount::identity_for_fd(&directory, path)
        .map_err(|source| inspect(path, source))?;
    if &mount != root_mount {
        return Err(unsafe_path(
            path,
            "uv prune traversal crosses into a different mount",
        ));
    }
    Ok(directory)
}

#[derive(Default)]
struct TraversalBudget {
    entries: usize,
}

impl TraversalBudget {
    fn consume_entry(&mut self) -> Result<(), UvCacheRootSealError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(UvCacheRootSealError::EntryLimitExceeded)?;
        if self.entries > MAX_VERIFIED_ENTRIES {
            Err(UvCacheRootSealError::EntryLimitExceeded)
        } else {
            Ok(())
        }
    }
}

fn validate_namespace_chain(
    path: &Path,
    canonical_final: bool,
) -> Result<(), UvCacheRootSealError> {
    let euid = rustix::process::geteuid().as_raw();
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path(path, "cache root has no parent directory"))?;
    let mut prefix = PathBuf::from("/");
    validate_namespace_directory(&prefix, euid)?;
    for component in parent.components().skip(1) {
        let name = match component {
            Component::Normal(name) => name,
            _ => return Err(unsafe_path(path, "path is not lexically normalized")),
        };
        prefix.push(name);
        let link_metadata =
            std::fs::symlink_metadata(&prefix).map_err(|source| inspect(&prefix, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                &prefix,
                "ancestor symlink is owned by a foreign UID",
            ));
        }
        validate_namespace_directory(&prefix, euid)?;
    }
    if !canonical_final {
        let link_metadata =
            std::fs::symlink_metadata(path).map_err(|source| inspect(path, source))?;
        if link_metadata.file_type().is_symlink()
            && link_metadata.uid() != euid
            && link_metadata.uid() != 0
        {
            return Err(unsafe_path(
                path,
                "cache-root symlink is owned by a foreign UID",
            ));
        }
    }
    Ok(())
}

fn validate_namespace_directory(path: &Path, euid: u32) -> Result<(), UvCacheRootSealError> {
    let metadata = std::fs::metadata(path).map_err(|source| inspect(path, source))?;
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "ancestor is not a directory"));
    }
    if degu_walk::directory_grants_foreign_mutation(metadata.uid(), metadata.mode(), euid) {
        return Err(unsafe_path(
            path,
            "ancestor namespace grants foreign mutation authority",
        ));
    }
    // A lexical ancestor may itself be a trusted symlink (for example macOS
    // `/var`). Its link owner was checked above and the canonical target chain
    // is independently validated, so this ancestor open intentionally follows it.
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(path, io::Error::from(source)))?;
    let opened =
        rustix::fs::fstat(&directory).map_err(|source| inspect(path, io::Error::from(source)))?;
    if stat_device(opened.st_dev, path)? != metadata.dev() || opened.st_ino != metadata.ino() {
        return Err(UvCacheRootSealError::RootChanged);
    }
    reject_extended_acl(&directory, path)
}

fn require_private_directory(
    fd: &OwnedFd,
    stat: &Stat,
    path: &Path,
) -> Result<(), UvCacheRootSealError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(unsafe_path(path, "object is not a real directory"));
    }
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid {
        return Err(unsafe_path(
            path,
            "directory is not owned by the effective user",
        ));
    }
    let mode = raw_mode_u32(stat.st_mode);
    if mode & SHARED_WRITE_MASK != 0 {
        return Err(unsafe_path(path, "directory is group- or world-writable"));
    }
    if mode & REQUIRED_DIRECTORY_MODE != REQUIRED_DIRECTORY_MODE {
        return Err(unsafe_path(
            path,
            "effective-user read, write, and execute mode bits are required",
        ));
    }
    reject_extended_acl(fd, path)
}

fn open_directory<Fd: rustix::fd::AsFd, P: rustix::path::Arg>(
    parent: Fd,
    name: P,
    path: &Path,
) -> Result<OwnedFd, UvCacheRootSealError> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| inspect(path, io::Error::from(source)))
}

fn require_same_object(
    inspected: &Stat,
    opened: &Stat,
    path: &Path,
) -> Result<(), UvCacheRootSealError> {
    if inspected.st_dev != opened.st_dev
        || inspected.st_ino != opened.st_ino
        || FileType::from_raw_mode(inspected.st_mode) != FileType::from_raw_mode(opened.st_mode)
    {
        Err(unsafe_path(
            path,
            "object changed while it was being opened",
        ))
    } else {
        Ok(())
    }
}

fn require_identity(
    stat: &Stat,
    identity: DirectoryIdentity,
    path: &Path,
) -> Result<(), UvCacheRootSealError> {
    if directory_identity(stat, path)? == identity {
        Ok(())
    } else {
        Err(UvCacheRootSealError::RootChanged)
    }
}

fn directory_identity(stat: &Stat, path: &Path) -> Result<DirectoryIdentity, UvCacheRootSealError> {
    Ok(DirectoryIdentity {
        device: stat_device(stat.st_dev, path)?,
        inode: stat.st_ino,
    })
}

fn require_cache_tag_signature(fd: &OwnedFd, path: &Path) -> Result<(), UvCacheRootSealError> {
    use rustix::fd::{AsFd, AsRawFd};
    let mut prefix = [0_u8; degu_adapters::SIGNATURE_PROBE_LEN];
    let mut read = 0_usize;
    while read < prefix.len() {
        // SAFETY: the descriptor stays live and the remaining slice is a valid
        // writable allocation. `pread` leaves the shared file offset unchanged.
        let result = unsafe {
            libc::pread(
                fd.as_fd().as_raw_fd(),
                prefix[read..].as_mut_ptr().cast(),
                prefix.len() - read,
                read as libc::off_t,
            )
        };
        if result > 0 {
            read += usize::try_from(result).expect("positive pread result fits usize");
            continue;
        }
        if result == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(inspect(path, error));
        }
    }
    if degu_adapters::prefix_has_signature(&prefix[..read]) {
        Ok(())
    } else {
        Err(unsafe_path(
            path,
            "CACHEDIR.TAG does not carry the cache-directory signature",
        ))
    }
}

#[cfg(target_os = "linux")]
fn reject_extended_acl(fd: &OwnedFd, path: &Path) -> Result<(), UvCacheRootSealError> {
    let names = list_xattrs(fd).map_err(|source| UvCacheRootSealError::AclInspection {
        path: path.to_path_buf(),
        source,
    })?;
    if has_posix_acl_name(&names) {
        return Err(unsafe_path(path, "extended or default ACL is present"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn has_posix_acl_name(names: &[u8]) -> bool {
    names.split(|byte| *byte == 0).any(|name| {
        matches!(
            name,
            b"system.posix_acl_access" | b"system.posix_acl_default"
        )
    })
}

#[cfg(target_os = "macos")]
fn reject_extended_acl(fd: &OwnedFd, path: &Path) -> Result<(), UvCacheRootSealError> {
    use rustix::fd::{AsFd, AsRawFd};
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: the borrowed descriptor remains live and the constant is the
    // macOS ACL_TYPE_EXTENDED ABI value from <sys/acl.h>.
    let acl = unsafe { acl_get_fd_np(fd.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(UvCacheRootSealError::AclInspection {
            path: path.to_path_buf(),
            source: error,
        });
    }
    // SAFETY: `acl` is the owned allocation returned by acl_get_fd_np.
    unsafe {
        acl_free(acl);
    }
    Err(unsafe_path(path, "extended ACL is present"))
}

#[cfg(target_os = "linux")]
fn list_xattrs(fd: &OwnedFd) -> io::Result<Vec<u8>> {
    use rustix::fd::{AsFd, AsRawFd};
    let raw_fd = fd.as_fd().as_raw_fd();
    let size = flistxattr(raw_fd, std::ptr::null_mut(), 0)?;
    if size > MAX_ACL_XATTR_LIST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list exceeds the ACL safety bound",
        ));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; size];
    let read = flistxattr(raw_fd, names.as_mut_ptr().cast(), names.len())?;
    if read > names.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended attribute name list grew beyond its bound",
        ));
    }
    names.truncate(read);
    Ok(names)
}

#[cfg(target_os = "linux")]
fn flistxattr(fd: libc::c_int, buffer: *mut libc::c_char, size: usize) -> io::Result<usize> {
    loop {
        // SAFETY: buffer is null with size zero or identifies a writable
        // allocation of exactly `size` bytes; the descriptor stays live.
        let result = unsafe { libc::flistxattr(fd, buffer, size) };
        if result >= 0 {
            return usize::try_from(result)
                .map_err(|_| io::Error::other("extended attribute list size overflow"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn inspect(path: &Path, source: io::Error) -> UvCacheRootSealError {
    UvCacheRootSealError::Inspect {
        path: path.to_path_buf(),
        source,
    }
}

fn unsafe_path(path: &Path, reason: &'static str) -> UvCacheRootSealError {
    UvCacheRootSealError::UnsafePath {
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(target_vendor = "apple")]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(target_vendor = "apple")]
fn stat_device(device: libc::dev_t, path: &Path) -> Result<u64, UvCacheRootSealError> {
    u64::try_from(device).map_err(|_| unsafe_path(path, "filesystem device identity is negative"))
}

#[cfg(not(target_vendor = "apple"))]
fn stat_device(device: libc::dev_t, _path: &Path) -> Result<u64, UvCacheRootSealError> {
    Ok(device)
}

// MetadataExt is deliberately imported last: its `dev`, `ino`, `uid`, and
// `mode` accessors are used only for pathname/open-descriptor attachment checks.
use std::os::unix::fs::MetadataExt;

impl fmt::Debug for SealedUvCacheRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedUvCacheRoot")
            .field("selection", &self.selection)
            .field("version", &self.version)
            .field("canonical_path", &self.canonical_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
