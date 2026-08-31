//! Durable segmented files for held-tree evidence.
//!
//! A sidecar is authority-neutral data. Publishing or verifying one cannot
//! authorize chmod, rename, undo, or purge; the v12 WAL record binds the exact
//! commitment before recovery may rely on its contents.

use crate::authority::TransactionState;
use crate::backend::certify_held_fd_backend;
use crate::backend::require_held_fd_acl_absent;
use crate::backend::roles::WalStoreBackend;
use crate::seal::store::{
    StoreError, WAL_FILE_NAME, validate_entry_binding, validate_store_binding, validate_wal,
};
use crate::seal::wal::{RecoverySession, SealWal, TransactionId};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

mod scratch;

const MAGIC: &[u8; 4] = b"DHTS";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 80;
const SEGMENT_HEADER_LEN: usize = 56;
const MAX_SEGMENT_PAYLOAD: usize = 1024 * 1024;
const MAX_SEGMENTS: u64 = 1_000_000;
// Must remain aligned with the currently admitted held-tree entry ceiling.
// Raising it requires the later end-to-end reader/limit integration slice.
const MAX_RECORDS: u64 = 100_000;
const MAX_TOTAL_PAYLOAD_BYTES: u64 = MAX_SEGMENTS * MAX_SEGMENT_PAYLOAD as u64;
const MAX_FILE_BYTES: u64 =
    HEADER_LEN as u64 + MAX_SEGMENTS * SEGMENT_HEADER_LEN as u64 + MAX_TOTAL_PAYLOAD_BYTES;
const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const OPEN_NEW: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_EXISTING: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const SEGMENT_DOMAIN: &[u8] = b"degu-held-tree-sidecar-segment-v1\0";
const ROOT_DOMAIN: &[u8] = b"degu-held-tree-sidecar-root-v1\0";
const TEMP_PREFIX: &[u8] = b".tree-sidecar-v1-";
const TEMP_SUFFIX: &[u8] = b".tmp";
static NEXT_TEMP_NAME: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, thiserror::Error)]
pub(crate) enum TreeSidecarError {
    #[error(transparent)]
    StoreBinding(#[from] StoreError),
    #[error("invalid held-tree sidecar segment: {0}")]
    InvalidSegment(&'static str),
    #[error("invalid unpublished held-tree scratch data: {0}")]
    InvalidScratch(&'static str),
    #[error("held-tree sidecar already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("held-tree sidecar is malformed at {path}: {reason}")]
    Malformed { path: PathBuf, reason: &'static str },
    #[error("held-tree sidecar integrity check failed at {0}")]
    Integrity(PathBuf),
    #[error("unsafe held-tree sidecar at {path}: {reason}")]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error("failed to access held-tree sidecar at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
pub(crate) enum TreeSidecarFoldError<E> {
    Sidecar(TreeSidecarError),
    Fold(E),
}

impl<E> From<TreeSidecarError> for TreeSidecarFoldError<E> {
    fn from(error: TreeSidecarError) -> Self {
        Self::Sidecar(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeSidecarCommitment {
    pub(super) transaction: TransactionId,
    pub(super) segment_count: u64,
    pub(super) record_count: u64,
    pub(super) payload_bytes: u64,
    pub(super) file_bytes: u64,
    pub(super) root_sha256: [u8; 32],
}

impl TreeSidecarCommitment {
    /// Transaction whose derived final filename and segment hashes are bound.
    pub fn transaction(self) -> TransactionId {
        self.transaction
    }

    /// Number of ordered authenticated segments in the sidecar.
    pub fn segment_count(self) -> u64 {
        self.segment_count
    }

    /// Aggregate number of complete manifest records across all segments.
    pub fn record_count(self) -> u64 {
        self.record_count
    }

    /// Aggregate payload bytes, excluding container framing.
    pub fn payload_bytes(self) -> u64 {
        self.payload_bytes
    }

    /// Exact complete sidecar file length, including container framing.
    pub fn file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Root commitment over the ordered segment digests and aggregate counts.
    pub fn root_sha256(self) -> [u8; 32] {
        self.root_sha256
    }
}

/// Validates the allocation-free structural claims carried by a sidecar
/// commitment. This is shared by the sidecar codec and the WAL binding seam so
/// malformed lengths or counts can never become durable recovery evidence.
pub(super) fn validate_tree_sidecar_commitment(
    commitment: TreeSidecarCommitment,
) -> Result<(), &'static str> {
    if commitment.segment_count == 0 || commitment.segment_count > MAX_SEGMENTS {
        return Err("invalid sidecar segment count");
    }
    if commitment.record_count < commitment.segment_count || commitment.record_count > MAX_RECORDS {
        return Err("invalid sidecar record count");
    }
    let max_payload = commitment
        .segment_count
        .checked_mul(MAX_SEGMENT_PAYLOAD as u64)
        .ok_or("sidecar payload bound overflow")?;
    if commitment.payload_bytes > MAX_TOTAL_PAYLOAD_BYTES || commitment.payload_bytes > max_payload
    {
        return Err("invalid sidecar payload byte count");
    }
    let expected_file_bytes = (HEADER_LEN as u64)
        .checked_add(
            commitment
                .segment_count
                .checked_mul(SEGMENT_HEADER_LEN as u64)
                .ok_or("sidecar framing length overflow")?,
        )
        .and_then(|bytes| bytes.checked_add(commitment.payload_bytes))
        .ok_or("sidecar file length overflow")?;
    if expected_file_bytes > MAX_FILE_BYTES || commitment.file_bytes != expected_file_bytes {
        return Err("invalid sidecar file byte count");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TreeSidecarCleanupReport {
    pub(crate) removed: u64,
    pub(crate) corrupt_retained: u64,
}

/// Manifest evidence remains reachable until no restart path can use it for
/// verification, undo, or purge. These states have a durable terminal namespace
/// outcome and therefore no longer consume their historical sidecar.
pub(crate) fn tree_sidecar_required_for_state(state: TransactionState) -> bool {
    !matches!(
        state,
        TransactionState::Purged
            | TransactionState::PurgeOutcome
            | TransactionState::Restored
            | TransactionState::UndoConflict
            | TransactionState::RolledBack
    )
}

/// Exact private-store handle. It owns only a duplicate directory descriptor;
/// the WAL lease remains the separate serialization and mutation authority.
pub(crate) struct TreeSidecarStore {
    parent: OwnedFd,
    name: OsString,
    directory: OwnedFd,
    backend: WalStoreBackend,
    device: u64,
    wal_device: u64,
    wal_inode: u64,
    path: PathBuf,
}

impl TreeSidecarStore {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_validated_store(
        parent: OwnedFd,
        name: OsString,
        directory: OwnedFd,
        backend: WalStoreBackend,
        device: u64,
        wal_device: u64,
        wal_inode: u64,
        path: PathBuf,
    ) -> Self {
        Self {
            parent,
            name,
            directory,
            backend,
            device,
            wal_device,
            wal_inode,
            path,
        }
    }

    /// Pulls borrowed segments from a producer while the unpublished file is
    /// open. The producer may reuse one bounded buffer immediately after each
    /// call returns; the publisher never retains the payload reference.
    pub(crate) fn publish_stream<P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<TreeSidecarCommitment, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(u64, &[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
    {
        self.publish_stream_with_sync(
            wal,
            transaction,
            produce,
            |file| file.sync_all(),
            |directory| rustix::fs::fsync(directory).map_err(io::Error::from),
        )
    }

    fn publish_stream_with_sync<P, F, D>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
        mut sync_file: F,
        mut sync_directory: D,
    ) -> Result<TreeSidecarCommitment, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(u64, &[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
        F: FnMut(&File) -> io::Result<()>,
        D: FnMut(&OwnedFd) -> io::Result<()>,
    {
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        let final_name = final_name(transaction);
        let final_path = self.path.join(&final_name);
        let temp_name = temp_name(transaction);
        let temp_path = self.path.join(&temp_name);
        let fd = match rustix::fs::openat(&self.directory, &temp_name, OPEN_NEW, FILE_MODE) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) => {
                return Err(TreeSidecarError::AlreadyExists(temp_path));
            }
            Err(error) => return Err(io_error(&temp_path, error.into())),
        };
        rustix::fs::fchmod(&fd, FILE_MODE).map_err(|error| io_error(&temp_path, error.into()))?;
        validate_file(
            &self.directory,
            &temp_name,
            &fd,
            self.backend,
            self.device,
            &temp_path,
        )?;

        let mut file = File::from(fd);
        file.write_all(&[0_u8; HEADER_LEN])
            .map_err(|error| io_error(&temp_path, error))?;
        let mut root = Sha256::new();
        root.update(ROOT_DOMAIN);
        root.update(transaction.0);
        let mut segment_count = 0_u64;
        let mut record_count = 0_u64;
        let mut payload_bytes = 0_u64;
        {
            let mut emit = |segment_record_count: u64,
                            segment_payload: &[u8]|
             -> Result<(), TreeSidecarError> {
                if segment_record_count == 0 {
                    return Err(TreeSidecarError::InvalidSegment(
                        "a segment must contain at least one record",
                    ));
                }
                if segment_payload.len() > MAX_SEGMENT_PAYLOAD {
                    return Err(TreeSidecarError::InvalidSegment(
                        "segment payload exceeds 1 MiB",
                    ));
                }
                if segment_count >= MAX_SEGMENTS {
                    return Err(TreeSidecarError::InvalidSegment(
                        "segment count exceeds the codec sanity limit",
                    ));
                }
                let index = segment_count;
                let payload_len = u32::try_from(segment_payload.len()).map_err(|_| {
                    TreeSidecarError::InvalidSegment("segment payload length is not representable")
                })?;
                let digest =
                    segment_digest(transaction, index, segment_record_count, segment_payload);
                let header =
                    encode_segment_header(index, segment_record_count, payload_len, digest);
                file.write_all(&header)
                    .and_then(|()| file.write_all(segment_payload))
                    .map_err(|error| io_error(&temp_path, error))?;
                root.update(digest);
                segment_count = segment_count
                    .checked_add(1)
                    .ok_or(TreeSidecarError::InvalidSegment("segment count overflow"))?;
                record_count = record_count
                    .checked_add(segment_record_count)
                    .ok_or(TreeSidecarError::InvalidSegment("record count overflow"))?;
                payload_bytes = payload_bytes.checked_add(u64::from(payload_len)).ok_or(
                    TreeSidecarError::InvalidSegment("payload byte count overflow"),
                )?;
                if payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
                    return Err(TreeSidecarError::InvalidSegment(
                        "total payload exceeds the codec sanity limit",
                    ));
                }
                Ok(())
            };
            produce(&mut emit)?;
        }
        if segment_count == 0 {
            return Err(TreeSidecarError::InvalidSegment(
                "a sidecar must contain at least one segment",
            ));
        }
        root.update(segment_count.to_be_bytes());
        root.update(record_count.to_be_bytes());
        root.update(payload_bytes.to_be_bytes());
        let root_sha256 = root.finalize().into();
        let file_bytes = file
            .stream_position()
            .map_err(|error| io_error(&temp_path, error))?;
        let commitment = TreeSidecarCommitment {
            transaction,
            segment_count,
            record_count,
            payload_bytes,
            file_bytes,
            root_sha256,
        };
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&encode_header(commitment)))
            .map_err(|error| io_error(&temp_path, error))?;
        sync_file(&file).map_err(|error| io_error(&temp_path, error))?;
        validate_file(
            &self.directory,
            &temp_name,
            &file,
            self.backend,
            self.device,
            &temp_path,
        )?;
        verify_file(&file, commitment, &temp_path)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;

        match rustix::fs::renameat_with(
            &self.directory,
            &temp_name,
            &self.directory,
            &final_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                return Err(TreeSidecarError::AlreadyExists(final_path));
            }
            Err(error) => return Err(io_error(&final_path, error.into())),
        }
        sync_directory(&self.directory).map_err(|error| io_error(&self.path, error))?;
        validate_file(
            &self.directory,
            &final_name,
            &file,
            self.backend,
            self.device,
            &final_path,
        )?;
        verify_file(&file, commitment, &final_path)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(commitment)
    }

    /// Reopens the exact final name, revalidates its private-file contract, and
    /// streams the full codec without allocating more than one segment.
    #[cfg(test)]
    pub(crate) fn verify(&self, expected: TreeSidecarCommitment) -> Result<(), TreeSidecarError> {
        let actual = self.inspect_unbound(expected.transaction)?;
        if actual != expected {
            return Err(TreeSidecarError::Integrity(
                self.path.join(final_name(expected.transaction)),
            ));
        }
        Ok(())
    }

    /// Reopens and authenticates the exact committed sidecar, then folds its
    /// segments into an owned authority-neutral accumulator. A segment reaches
    /// `fold` only after its digest is authenticated, and the accumulator is
    /// returned only after aggregate counts, trailing EOF, and the final root
    /// commitment are authenticated.
    pub(crate) fn read_fold<A, E, F>(
        &self,
        expected: TreeSidecarCommitment,
        initial: A,
        fold: F,
    ) -> Result<A, TreeSidecarFoldError<E>>
    where
        F: FnMut(A, u64, &[u8]) -> Result<A, E>,
    {
        self.revalidate_store_binding()?;
        let name = final_name(expected.transaction);
        let path = self.path.join(&name);
        let fd = rustix::fs::openat(&self.directory, &name, OPEN_EXISTING, Mode::empty())
            .map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &self.directory,
            &name,
            &fd,
            self.backend,
            self.device,
            &path,
        )?;
        let file = File::from(fd);
        let result = fold_file(&file, expected, &path, initial, fold)?;
        self.revalidate_store_binding()?;
        Ok(result)
    }

    /// Returns a self-consistent commitment for orphan classification only. The
    /// value is derived from the sidecar itself and therefore grants no recovery
    /// or mutation authority until an independent durable WAL record matches it.
    pub(crate) fn inspect_unbound(
        &self,
        transaction: TransactionId,
    ) -> Result<TreeSidecarCommitment, TreeSidecarError> {
        self.revalidate_store_binding()?;
        let name = final_name(transaction);
        let path = self.path.join(&name);
        let fd = rustix::fs::openat(&self.directory, &name, OPEN_EXISTING, Mode::empty())
            .map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &self.directory,
            &name,
            &fd,
            self.backend,
            self.device,
            &path,
        )?;
        let file = File::from(fd);
        let file_bytes = file
            .metadata()
            .map_err(|error| io_error(&path, error))?
            .len();
        validate_file_size(file_bytes, &path)?;
        let mut reader = file.try_clone().map_err(|error| io_error(&path, error))?;
        let mut header = [0_u8; HEADER_LEN];
        reader
            .read_exact(&mut header)
            .map_err(|error| io_error(&path, error))?;
        let mut commitment = decode_header(header, &path)?;
        commitment.file_bytes = file_bytes;
        if commitment.transaction != transaction {
            return Err(TreeSidecarError::Integrity(path));
        }
        verify_file(&file, commitment, &path)?;
        self.revalidate_store_binding()?;
        Ok(commitment)
    }

    /// Removes only final sidecars proven unreachable from the exact replayed
    /// WAL projection. Active references are never inspected or removed. An
    /// exact terminal reference and a self-authenticating unreferenced orphan
    /// are removable; malformed, substituted, or mismatched finals are retained
    /// as corruption rather than guessed away.
    pub(crate) fn cleanup_unreachable(
        &self,
        wal: &mut SealWal<RecoverySession>,
    ) -> Result<TreeSidecarCleanupReport, TreeSidecarError> {
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        // `dup` would share the directory cursor and make later startup scans
        // silently begin at EOF. Opening `.` creates an independent cursor.
        let fresh = rustix::fs::openat(&self.directory, c".", OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(&self.path, error.into()))?;
        let entries = rustix::fs::Dir::new(fresh)
            .map_err(io::Error::from)
            .map_err(|error| io_error(&self.path, error))?;
        let mut report = TreeSidecarCleanupReport::default();
        for entry in entries {
            let entry = entry
                .map_err(io::Error::from)
                .map_err(|error| io_error(&self.path, error))?;
            let Some(transaction) = parse_final_name(entry.file_name().to_bytes()) else {
                continue;
            };
            let expected = wal.tree_sidecar_commitment(transaction);
            if expected.is_some()
                && wal
                    .transaction_state(transaction)
                    .is_none_or(tree_sidecar_required_for_state)
            {
                continue;
            }
            let actual = match self.inspect_unbound(transaction) {
                Ok(actual) => actual,
                Err(error) if retained_final_corruption(&error) => {
                    report.corrupt_retained = report.corrupt_retained.checked_add(1).ok_or(
                        TreeSidecarError::Malformed {
                            path: self.path.clone(),
                            reason: "corrupt sidecar count overflow",
                        },
                    )?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if expected.is_some_and(|expected| expected != actual) {
                report.corrupt_retained =
                    report
                        .corrupt_retained
                        .checked_add(1)
                        .ok_or(TreeSidecarError::Malformed {
                            path: self.path.clone(),
                            reason: "corrupt sidecar count overflow",
                        })?;
                continue;
            }
            self.remove_verified_final(actual)?;
            report.removed = report
                .removed
                .checked_add(1)
                .ok_or(TreeSidecarError::Malformed {
                    path: self.path.clone(),
                    reason: "removed sidecar count overflow",
                })?;
        }
        if report.removed != 0 {
            rustix::fs::fsync(&self.directory)
                .map_err(|error| io_error(&self.path, error.into()))?;
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(report)
    }

    fn remove_verified_final(
        &self,
        expected: TreeSidecarCommitment,
    ) -> Result<(), TreeSidecarError> {
        let name = final_name(expected.transaction);
        let path = self.path.join(&name);
        let fd = rustix::fs::openat(&self.directory, &name, OPEN_EXISTING, Mode::empty())
            .map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &self.directory,
            &name,
            &fd,
            self.backend,
            self.device,
            &path,
        )?;
        let file = File::from(fd);
        verify_file(&file, expected, &path)?;
        remove_validated_private_file(
            &self.directory,
            &name,
            &file,
            self.backend,
            self.device,
            &path,
        )
    }

    /// Removes only unpublished temp entries. Published sidecars require WAL
    /// reachability information and are deliberately outside this operation.
    pub(crate) fn cleanup_unpublished(
        &self,
        wal: &mut SealWal<RecoverySession>,
    ) -> Result<u64, TreeSidecarError> {
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        // `dup` would share the directory cursor and make later startup scans
        // silently begin at EOF. Opening `.` creates an independent cursor.
        let fresh = rustix::fs::openat(&self.directory, c".", OPEN_DIRECTORY, Mode::empty())
            .map_err(|error| io_error(&self.path, error.into()))?;
        let entries = rustix::fs::Dir::new(fresh)
            .map_err(io::Error::from)
            .map_err(|error| io_error(&self.path, error))?;
        let mut removed = 0_u64;
        for entry in entries {
            let entry = entry
                .map_err(io::Error::from)
                .map_err(|error| io_error(&self.path, error))?;
            let name = entry.file_name().to_bytes();
            if !valid_temp_name(name) && !scratch::valid_scratch_name(name) {
                continue;
            }
            let name = OsStr::from_bytes(name);
            let path = self.path.join(name);
            let fd = rustix::fs::openat(&self.directory, name, OPEN_EXISTING, Mode::empty())
                .map_err(|error| io_error(&path, error.into()))?;
            remove_validated_private_file(
                &self.directory,
                name,
                &fd,
                self.backend,
                self.device,
                &path,
            )?;
            removed = removed.checked_add(1).ok_or(TreeSidecarError::Malformed {
                path: self.path.clone(),
                reason: "unpublished sidecar count overflow",
            })?;
        }
        if removed != 0 {
            rustix::fs::fsync(&self.directory)
                .map_err(|error| io_error(&self.path, error.into()))?;
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(removed)
    }

    fn require_matching_wal(
        &self,
        wal: &mut SealWal<RecoverySession>,
    ) -> Result<(), TreeSidecarError> {
        let identity = wal
            .exact_lease_identity()
            .map_err(|error| io_error(&self.path.join("seal.wal"), error))?;
        let wal_path = self.path.join(WAL_FILE_NAME);
        if identity != (self.wal_device, self.wal_inode) {
            return Err(unsafe_file(
                &wal_path,
                "sidecar mutation lease does not match this store WAL",
            ));
        }
        let wal = rustix::fs::openat(&self.directory, WAL_FILE_NAME, OPEN_EXISTING, Mode::empty())
            .map_err(|error| io_error(&wal_path, error.into()))?;
        validate_wal(&wal, self.backend, self.device, &wal_path)
            .map_err(TreeSidecarError::StoreBinding)?;
        validate_entry_binding(&self.directory, &wal, &wal_path)
            .map_err(TreeSidecarError::StoreBinding)?;
        let stat = rustix::fs::fstat(&wal).map_err(|error| io_error(&wal_path, error.into()))?;
        #[cfg(target_vendor = "apple")]
        let device = u64::try_from(stat.st_dev)
            .map_err(|_| unsafe_file(&wal_path, "WAL device identity is invalid"))?;
        #[cfg(not(target_vendor = "apple"))]
        let device = stat.st_dev;
        if (device, stat.st_ino) != identity {
            return Err(unsafe_file(
                &wal_path,
                "locked WAL is no longer the exact store entry",
            ));
        }
        Ok(())
    }

    fn revalidate_store_binding(&self) -> Result<(), TreeSidecarError> {
        let parent_path = self.path.parent().unwrap_or_else(|| Path::new("/"));
        validate_store_binding(
            &self.parent,
            &self.name,
            &self.directory,
            self.backend,
            self.device,
            &self.path,
            parent_path,
        )
        .map_err(TreeSidecarError::StoreBinding)
    }
}

/// Removes one exact entry only after the caller validated its open descriptor,
/// private-file contract, and directory binding. This is the sidecar namespace's
/// verified fd-relative deletion seam; arbitrary user paths cannot reach it.
#[allow(clippy::disallowed_methods)]
fn remove_validated_private_file<Fd: AsFd>(
    directory: &OwnedFd,
    name: &OsStr,
    fd: Fd,
    backend: WalStoreBackend,
    device: u64,
    path: &Path,
) -> Result<(), TreeSidecarError> {
    // Revalidate at the deletion seam rather than relying on an earlier
    // directory scan observation. The unique mutable WAL writer excludes every
    // cooperative publisher while this exact name is removed.
    validate_file(directory, name, fd, backend, device, path)?;
    rustix::fs::unlinkat(directory, name, AtFlags::empty())
        .map_err(|error| io_error(path, error.into()))
}

fn encode_header(commitment: TreeSidecarCommitment) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_be_bytes());
    out[6..8].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out[8..24].copy_from_slice(&commitment.transaction.0);
    out[24..32].copy_from_slice(&commitment.segment_count.to_be_bytes());
    out[32..40].copy_from_slice(&commitment.record_count.to_be_bytes());
    out[40..48].copy_from_slice(&commitment.payload_bytes.to_be_bytes());
    out[48..80].copy_from_slice(&commitment.root_sha256);
    out
}

fn decode_header(
    bytes: [u8; HEADER_LEN],
    path: &Path,
) -> Result<TreeSidecarCommitment, TreeSidecarError> {
    if &bytes[0..4] != MAGIC {
        return Err(malformed(path, "bad magic"));
    }
    if u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != VERSION {
        return Err(malformed(path, "unsupported version"));
    }
    if usize::from(u16::from_be_bytes(bytes[6..8].try_into().unwrap())) != HEADER_LEN {
        return Err(malformed(path, "invalid header length"));
    }
    let segment_count = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    if segment_count == 0 || segment_count > MAX_SEGMENTS {
        return Err(malformed(path, "invalid segment count"));
    }
    let record_count = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let payload_bytes = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    if record_count == 0 || payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
        return Err(malformed(path, "invalid aggregate counts"));
    }
    Ok(TreeSidecarCommitment {
        transaction: TransactionId(bytes[8..24].try_into().unwrap()),
        segment_count,
        record_count,
        payload_bytes,
        file_bytes: 0,
        root_sha256: bytes[48..80].try_into().unwrap(),
    })
}

fn encode_segment_header(
    index: u64,
    record_count: u64,
    payload_len: u32,
    digest: [u8; 32],
) -> [u8; SEGMENT_HEADER_LEN] {
    let mut out = [0_u8; SEGMENT_HEADER_LEN];
    out[0..8].copy_from_slice(&index.to_be_bytes());
    out[8..16].copy_from_slice(&record_count.to_be_bytes());
    out[16..20].copy_from_slice(&payload_len.to_be_bytes());
    out[24..56].copy_from_slice(&digest);
    out
}

fn segment_digest(
    transaction: TransactionId,
    index: u64,
    record_count: u64,
    payload: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SEGMENT_DOMAIN);
    digest.update(transaction.0);
    digest.update(index.to_be_bytes());
    digest.update(record_count.to_be_bytes());
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn validate_file_size(file_bytes: u64, path: &Path) -> Result<(), TreeSidecarError> {
    if file_bytes > MAX_FILE_BYTES {
        Err(malformed(path, "sidecar exceeds the codec file-size limit"))
    } else {
        Ok(())
    }
}

fn verify_file(
    file: &File,
    expected: TreeSidecarCommitment,
    path: &Path,
) -> Result<(), TreeSidecarError> {
    match fold_file(file, expected, path, (), |(), _, _| {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(()) => Ok(()),
        Err(TreeSidecarFoldError::Sidecar(error)) => Err(error),
        Err(TreeSidecarFoldError::Fold(never)) => match never {},
    }
}

fn fold_file<A, E, F>(
    file: &File,
    expected: TreeSidecarCommitment,
    path: &Path,
    initial: A,
    mut fold: F,
) -> Result<A, TreeSidecarFoldError<E>>
where
    F: FnMut(A, u64, &[u8]) -> Result<A, E>,
{
    let actual_len = file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .len();
    if validate_tree_sidecar_commitment(expected).is_err() || actual_len != expected.file_bytes {
        return Err(TreeSidecarError::Integrity(path.to_path_buf()).into());
    }
    let mut file = file.try_clone().map_err(|error| io_error(path, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error(path, error))?;
    let mut header = [0_u8; HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|error| io_error(path, error))?;
    let mut decoded = decode_header(header, path)?;
    decoded.file_bytes = actual_len;
    if decoded != expected {
        return Err(TreeSidecarError::Integrity(path.to_path_buf()).into());
    }

    let mut root = Sha256::new();
    root.update(ROOT_DOMAIN);
    root.update(expected.transaction.0);
    let mut records = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut accumulator = Some(initial);
    for expected_index in 0..expected.segment_count {
        let mut frame = [0_u8; SEGMENT_HEADER_LEN];
        file.read_exact(&mut frame)
            .map_err(|error| io_error(path, error))?;
        let index = u64::from_be_bytes(frame[0..8].try_into().unwrap());
        let record_count = u64::from_be_bytes(frame[8..16].try_into().unwrap());
        let payload_len = u32::from_be_bytes(frame[16..20].try_into().unwrap());
        if frame[20..24] != [0_u8; 4]
            || index != expected_index
            || record_count == 0
            || payload_len as usize > MAX_SEGMENT_PAYLOAD
        {
            return Err(malformed(path, "invalid segment header").into());
        }
        let expected_digest: [u8; 32] = frame[24..56].try_into().unwrap();
        let mut payload = vec![0_u8; payload_len as usize];
        file.read_exact(&mut payload)
            .map_err(|error| io_error(path, error))?;
        let actual_digest = segment_digest(expected.transaction, index, record_count, &payload);
        if actual_digest != expected_digest {
            return Err(TreeSidecarError::Integrity(path.to_path_buf()).into());
        }
        root.update(actual_digest);
        let current = accumulator
            .take()
            .expect("fold accumulator is always present");
        accumulator =
            Some(fold(current, record_count, &payload).map_err(TreeSidecarFoldError::Fold)?);
        records = records
            .checked_add(record_count)
            .ok_or_else(|| malformed(path, "record count overflow"))?;
        payload_bytes = payload_bytes
            .checked_add(u64::from(payload_len))
            .ok_or_else(|| malformed(path, "payload byte count overflow"))?;
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| io_error(path, error))?
        != 0
    {
        return Err(malformed(path, "trailing bytes").into());
    }
    root.update(expected.segment_count.to_be_bytes());
    root.update(records.to_be_bytes());
    root.update(payload_bytes.to_be_bytes());
    let actual_root: [u8; 32] = root.finalize().into();
    if records != expected.record_count
        || payload_bytes != expected.payload_bytes
        || actual_root != expected.root_sha256
    {
        return Err(TreeSidecarError::Integrity(path.to_path_buf()).into());
    }
    Ok(accumulator.expect("fold accumulator is always present"))
}
fn validate_file<Fd: AsFd>(
    directory: &OwnedFd,
    name: &OsStr,
    fd: Fd,
    expected_backend: WalStoreBackend,
    expected_device: u64,
    path: &Path,
) -> Result<(), TreeSidecarError> {
    let opened = rustix::fs::fstat(&fd).map_err(|error| io_error(path, error.into()))?;
    match require_held_fd_acl_absent(&fd) {
        Ok(()) => {}
        Err(crate::backend::CertificationError::AclPresent) => {
            return Err(unsafe_file(path, "sidecar ACL is present"));
        }
        Err(_) => {
            return Err(unsafe_file(
                path,
                "sidecar ACL could not be verified absent",
            ));
        }
    }
    let backend = certify_held_fd_backend(&fd)
        .map_err(|_| unsafe_file(path, "sidecar backend could not be certified"))?;
    if backend != expected_backend.local_backend() {
        return Err(unsafe_file(
            path,
            "sidecar backend does not match its store",
        ));
    }
    #[cfg(target_vendor = "apple")]
    let device = u64::try_from(opened.st_dev)
        .map_err(|_| unsafe_file(path, "sidecar device identity is invalid"))?;
    #[cfg(not(target_vendor = "apple"))]
    let device = opened.st_dev;
    if device != expected_device {
        return Err(unsafe_file(path, "sidecar device does not match its store"));
    }
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || raw_mode(opened.st_mode) & 0o7777 != raw_mode(FILE_MODE.bits())
        || opened.st_nlink != 1
    {
        return Err(unsafe_file(
            path,
            "sidecar kind, owner, mode, or link count is invalid",
        ));
    }
    let entry = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(path, error.into()))?;
    if entry.st_dev != opened.st_dev
        || entry.st_ino != opened.st_ino
        || FileType::from_raw_mode(entry.st_mode) != FileType::RegularFile
    {
        return Err(unsafe_file(
            path,
            "descriptor is not the exact sidecar entry",
        ));
    }
    Ok(())
}

fn valid_temp_name(name: &[u8]) -> bool {
    let Some(body) = name
        .strip_prefix(TEMP_PREFIX)
        .and_then(|name| name.strip_suffix(TEMP_SUFFIX))
    else {
        return false;
    };
    let mut parts = body.split(|byte| *byte == b'-');
    let transaction = parts.next().unwrap_or_default();
    let pid = parts.next().unwrap_or_default();
    let sequence = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || transaction.len() != 32
        || !transaction
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return false;
    }
    let (Ok(pid_text), Ok(sequence_text)) =
        (std::str::from_utf8(pid), std::str::from_utf8(sequence))
    else {
        return false;
    };
    let (Ok(pid_value), Ok(sequence_value)) =
        (pid_text.parse::<u32>(), sequence_text.parse::<u64>())
    else {
        return false;
    };
    pid == pid_value.to_string().as_bytes() && sequence == sequence_value.to_string().as_bytes()
}

fn retained_final_corruption(error: &TreeSidecarError) -> bool {
    match error {
        TreeSidecarError::Malformed { .. }
        | TreeSidecarError::Integrity(_)
        | TreeSidecarError::Unsafe { .. } => true,
        TreeSidecarError::Io { source, .. } => source.kind() == io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

fn parse_final_name(name: &[u8]) -> Option<TransactionId> {
    let transaction = name.strip_prefix(b"tree-")?.strip_suffix(b".sidecar")?;
    if transaction.len() != 32 {
        return None;
    }
    let mut decoded = [0_u8; 16];
    let (pairs, _) = transaction.as_chunks::<2>();
    for (output, pair) in decoded.iter_mut().zip(pairs) {
        *output = decode_hex(pair[0])?.checked_mul(16)? + decode_hex(pair[1])?;
    }
    Some(TransactionId(decoded))
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn final_name(transaction: TransactionId) -> OsString {
    OsString::from(format!("tree-{}.sidecar", transaction_hex(transaction)))
}

fn temp_name(transaction: TransactionId) -> OsString {
    let sequence = NEXT_TEMP_NAME.fetch_add(1, Ordering::Relaxed);
    OsString::from(format!(
        ".tree-sidecar-v1-{}-{}-{sequence}.tmp",
        transaction_hex(transaction),
        std::process::id()
    ))
}

fn transaction_hex(transaction: TransactionId) -> String {
    let mut encoded = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in transaction.0 {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn malformed(path: &Path, reason: &'static str) -> TreeSidecarError {
    TreeSidecarError::Malformed {
        path: path.to_path_buf(),
        reason,
    }
}

fn unsafe_file(path: &Path, reason: &'static str) -> TreeSidecarError {
    TreeSidecarError::Unsafe {
        path: path.to_path_buf(),
        reason,
    }
}

fn io_error(path: &Path, source: io::Error) -> TreeSidecarError {
    TreeSidecarError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(target_vendor = "apple")]
fn raw_mode(mode: rustix::fs::RawMode) -> u32 {
    u32::from(mode)
}

#[cfg(not(target_vendor = "apple"))]
fn raw_mode(mode: rustix::fs::RawMode) -> u32 {
    mode
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::store::SealWalStore;
    use crate::seal::wal::DurableTreeManifest;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[derive(Clone, Copy)]
    struct TreeSidecarSegment<'a> {
        record_count: u64,
        payload: &'a [u8],
    }

    trait TreeSidecarTestExt {
        fn publish<'a>(
            &self,
            wal: &mut SealWal<RecoverySession>,
            transaction: TransactionId,
            segments: impl IntoIterator<Item = TreeSidecarSegment<'a>>,
        ) -> Result<TreeSidecarCommitment, TreeSidecarError>;

        fn publish_with_sync<'a, F, D>(
            &self,
            wal: &mut SealWal<RecoverySession>,
            transaction: TransactionId,
            segments: impl IntoIterator<Item = TreeSidecarSegment<'a>>,
            sync_file: F,
            sync_directory: D,
        ) -> Result<TreeSidecarCommitment, TreeSidecarError>
        where
            F: FnMut(&File) -> io::Result<()>,
            D: FnMut(&OwnedFd) -> io::Result<()>;
    }

    impl TreeSidecarTestExt for TreeSidecarStore {
        fn publish<'a>(
            &self,
            wal: &mut SealWal<RecoverySession>,
            transaction: TransactionId,
            segments: impl IntoIterator<Item = TreeSidecarSegment<'a>>,
        ) -> Result<TreeSidecarCommitment, TreeSidecarError> {
            self.publish_stream(wal, transaction, |emit| {
                for segment in segments {
                    emit(segment.record_count, segment.payload)?;
                }
                Ok(())
            })
        }

        fn publish_with_sync<'a, F, D>(
            &self,
            wal: &mut SealWal<RecoverySession>,
            transaction: TransactionId,
            segments: impl IntoIterator<Item = TreeSidecarSegment<'a>>,
            sync_file: F,
            sync_directory: D,
        ) -> Result<TreeSidecarCommitment, TreeSidecarError>
        where
            F: FnMut(&File) -> io::Result<()>,
            D: FnMut(&OwnedFd) -> io::Result<()>,
        {
            self.publish_stream_with_sync(
                wal,
                transaction,
                |emit| {
                    for segment in segments {
                        emit(segment.record_count, segment.payload)?;
                    }
                    Ok(())
                },
                sync_file,
                sync_directory,
            )
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        TreeSidecarStore,
        SealWal<RecoverySession>,
    ) {
        let temp = crate::secure_test_tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("wal-store");
        let store = SealWalStore::open_or_create(&root).unwrap();
        let sidecars = store.tree_sidecar_store().unwrap();
        let mut recovery = store.try_lease().unwrap();
        recovery.replay_and_repair().unwrap();
        let wal = recovery.resume().unwrap();
        (temp, root, sidecars, wal)
    }

    fn tx(byte: u8) -> TransactionId {
        TransactionId([byte; 16])
    }

    fn segments() -> Vec<TreeSidecarSegment<'static>> {
        vec![
            TreeSidecarSegment {
                record_count: 2,
                payload: b"first bounded segment",
            },
            TreeSidecarSegment {
                record_count: 3,
                payload: b"second bounded segment",
            },
        ]
    }

    #[test]
    fn publish_syncs_private_exact_file_and_round_trips_commitment() {
        let (_temp, root, store, mut wal) = fixture();
        let commitment = store.publish(&mut wal, tx(1), segments()).unwrap();
        store.verify(commitment).unwrap();

        let path = root.join(final_name(tx(1)));
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(commitment.segment_count, 2);
        assert_eq!(commitment.record_count, 5);
        assert_eq!(commitment.payload_bytes, 43);
        assert_eq!(metadata.len(), commitment.file_bytes);
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 0);
    }

    #[test]
    fn duplicate_publish_never_overwrites_existing_commitment() {
        let (_temp, root, store, mut wal) = fixture();
        let first = store.publish(&mut wal, tx(2), segments()).unwrap();
        let before = std::fs::read(root.join(final_name(tx(2)))).unwrap();
        assert!(matches!(
            store.publish(
                &mut wal,
                tx(2),
                [TreeSidecarSegment {
                    record_count: 1,
                    payload: b"replacement"
                }]
            ),
            Err(TreeSidecarError::AlreadyExists(_))
        ));
        assert_eq!(std::fs::read(root.join(final_name(tx(2)))).unwrap(), before);
        store.verify(first).unwrap();
    }

    #[test]
    fn durability_order_never_publishes_before_file_sync() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(8);
        let final_path = root.join(final_name(transaction));
        let observations = std::cell::RefCell::new(Vec::new());
        let commitment = store
            .publish_with_sync(
                &mut wal,
                transaction,
                segments(),
                |_| {
                    observations
                        .borrow_mut()
                        .push(("file", final_path.exists()));
                    Ok(())
                },
                |_| {
                    observations
                        .borrow_mut()
                        .push(("directory", final_path.exists()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            &*observations.borrow(),
            &[("file", false), ("directory", true)]
        );
        store.verify(commitment).unwrap();
    }

    #[test]
    fn sync_failures_leave_only_the_protocol_defined_orphan_class() {
        let (_temp, root, store, mut wal) = fixture();
        let before_publish = tx(9);
        assert!(matches!(
            store.publish_with_sync(
                &mut wal,
                before_publish,
                segments(),
                |_| Err(io::Error::other("injected file sync failure")),
                |_| Ok(())
            ),
            Err(TreeSidecarError::Io { .. })
        ));
        assert!(!root.join(final_name(before_publish)).exists());
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);

        let after_publish = tx(10);
        assert!(matches!(
            store.publish_with_sync(
                &mut wal,
                after_publish,
                segments(),
                |_| Ok(()),
                |_| Err(io::Error::other("injected directory sync failure"))
            ),
            Err(TreeSidecarError::Io { .. })
        ));
        let final_path = root.join(final_name(after_publish));
        assert!(final_path.exists());
        let orphan = store.inspect_unbound(after_publish).unwrap();
        store.verify(orphan).unwrap();
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 0);
    }

    #[test]
    fn mutation_rejects_store_or_wal_binding_replacement() {
        let (temp, root, store, mut wal) = fixture();
        let moved = temp.path().join("moved-store");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(store.publish(&mut wal, tx(12), segments()).is_err());
        assert!(!moved.join(final_name(tx(12))).exists());

        let (_temp, root, store, mut wal) = fixture();
        let wal_path = root.join(WAL_FILE_NAME);
        let displaced = root.join("displaced.wal");
        std::fs::rename(&wal_path, &displaced).unwrap();
        std::fs::write(&wal_path, b"").unwrap();
        std::fs::set_permissions(&wal_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.publish(&mut wal, tx(13), segments()).is_err());
        assert!(!root.join(final_name(tx(13))).exists());
    }

    #[test]
    fn malformed_large_lengths_fail_before_segment_allocation() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(14);
        let commitment = store.publish(&mut wal, transaction, segments()).unwrap();
        let path = root.join(final_name(transaction));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start((HEADER_LEN + 16) as u64))
            .unwrap();
        file.write_all(&u32::MAX.to_be_bytes()).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            store.verify(commitment),
            Err(TreeSidecarError::Malformed { .. } | TreeSidecarError::Integrity(_))
        ));

        assert!(matches!(
            validate_file_size(MAX_FILE_BYTES + 1, &path),
            Err(TreeSidecarError::Malformed { .. })
        ));
    }

    #[test]
    fn payload_tamper_truncation_and_trailing_bytes_fail_integrity() {
        for (byte, mutate) in [(3_u8, "payload"), (4_u8, "truncate"), (5_u8, "trailing")] {
            let (_temp, root, store, mut wal) = fixture();
            let commitment = store.publish(&mut wal, tx(byte), segments()).unwrap();
            let path = root.join(final_name(tx(byte)));
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            match mutate {
                "payload" => {
                    file.seek(SeekFrom::Start((HEADER_LEN + SEGMENT_HEADER_LEN) as u64))
                        .unwrap();
                    file.write_all(b"X").unwrap();
                }
                "truncate" => file.set_len(commitment.file_bytes - 1).unwrap(),
                "trailing" => {
                    file.seek(SeekFrom::End(0)).unwrap();
                    file.write_all(b"X").unwrap();
                }
                _ => unreachable!(),
            }
            file.sync_all().unwrap();
            assert!(
                store.verify(commitment).is_err(),
                "mutation {mutate} was accepted"
            );
        }
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // simulates out-of-protocol sidecar substitution
    fn hardlink_and_symlink_substitution_are_refused_without_touching_victim() {
        let (_temp, root, store, mut wal) = fixture();
        let commitment = store.publish(&mut wal, tx(6), segments()).unwrap();
        let path = root.join(final_name(tx(6)));
        let alias = root.join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            store.verify(commitment),
            Err(TreeSidecarError::Unsafe { .. })
        ));
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(&path).unwrap();

        let victim = root.join("victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(store.verify(commitment).is_err());
        assert_eq!(std::fs::read(victim).unwrap(), b"unchanged");
    }

    #[test]
    fn mutation_rejects_a_lease_from_another_store_before_creating_temp_state() {
        let (_temp, root, store, _wal) = fixture();
        let (_other_temp, _other_root, _other_store, mut other_wal) = fixture();
        assert!(matches!(
            store.publish(&mut other_wal, tx(7), segments()),
            Err(TreeSidecarError::Unsafe { .. })
        ));
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(TEMP_PREFIX)
        }));
    }

    #[test]
    fn final_sidecar_names_round_trip_only_canonical_transaction_hex() {
        let transaction = tx(0xab);
        assert_eq!(
            parse_final_name(final_name(transaction).as_bytes()),
            Some(transaction)
        );
        assert_eq!(
            parse_final_name(b"tree-ABABABABABABABABABABABABABABABAB.sidecar"),
            None
        );
    }

    #[test]
    fn cleanup_removes_only_replay_unreachable_valid_finals_and_resets_scan_cursor() {
        let (_temp, root, store, mut wal) = fixture();
        let orphan = store
            .publish(
                &mut wal,
                tx(20),
                [TreeSidecarSegment {
                    record_count: 1,
                    payload: b"valid orphan",
                }],
            )
            .unwrap();
        let corrupt_path = root.join(final_name(tx(21)));
        std::fs::write(&corrupt_path, b"truncated").unwrap();
        std::fs::set_permissions(&corrupt_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let first = store.cleanup_unreachable(&mut wal).unwrap();
        assert_eq!(
            first,
            TreeSidecarCleanupReport {
                removed: 1,
                corrupt_retained: 1,
            }
        );
        assert!(!root.join(final_name(orphan.transaction)).exists());
        assert!(corrupt_path.exists());

        let second = store.cleanup_unreachable(&mut wal).unwrap();
        assert_eq!(
            second,
            TreeSidecarCleanupReport {
                removed: 0,
                corrupt_retained: 1,
            },
            "every scan must use an independent directory cursor"
        );
    }

    #[test]
    fn cleanup_removes_only_valid_unpublished_temp_entries() {
        let (_temp, root, store, mut wal) = fixture();
        let temp_name = temp_name(tx(11));
        let path = root.join(&temp_name);
        std::fs::write(&path, b"partial").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let unrelated = root.join("unrelated");
        std::fs::write(&unrelated, b"keep").unwrap();
        std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lookalike = root.join(".tree-sidecar-not-generated.tmp");
        std::fs::write(&lookalike, b"keep").unwrap();
        std::fs::set_permissions(&lookalike, std::fs::Permissions::from_mode(0o600)).unwrap();
        let noncanonical = root.join(format!(
            ".tree-sidecar-v1-{}-0{}-01.tmp",
            transaction_hex(tx(15)),
            std::process::id()
        ));
        std::fs::write(&noncanonical, b"keep").unwrap();
        std::fs::set_permissions(&noncanonical, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);
        assert!(!path.exists());
        assert!(unrelated.exists());
        assert!(lookalike.exists());
        assert!(noncanonical.exists());
    }

    #[test]
    fn streaming_publish_and_authenticated_read_fold_round_trip() {
        let (_temp, _root, store, mut wal) = fixture();
        let commitment = store
            .publish_stream(&mut wal, tx(16), |emit| {
                let mut buffer = Vec::with_capacity(32);
                buffer.extend_from_slice(b"first bounded segment");
                emit(2, &buffer)?;
                buffer.clear();
                buffer.extend_from_slice(b"second bounded segment");
                emit(3, &buffer)?;
                Ok(())
            })
            .unwrap();

        let payloads = store
            .read_fold(commitment, Vec::new(), |mut payloads, records, payload| {
                payloads.push((records, payload.to_vec()));
                Ok::<_, std::convert::Infallible>(payloads)
            })
            .unwrap();
        assert_eq!(
            payloads,
            vec![
                (2, b"first bounded segment".to_vec()),
                (3, b"second bounded segment".to_vec())
            ]
        );
    }

    #[test]
    fn read_fold_never_returns_a_result_after_segment_or_root_tamper() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(17);
        let commitment = store.publish(&mut wal, transaction, segments()).unwrap();
        let path = root.join(final_name(transaction));
        let first_payload_len = b"first bounded segment".len() as u64;
        let second_payload_offset = HEADER_LEN as u64
            + SEGMENT_HEADER_LEN as u64
            + first_payload_len
            + SEGMENT_HEADER_LEN as u64;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(second_payload_offset)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();

        let folded_segments = std::cell::Cell::new(0_u64);
        let result = store.read_fold(commitment, 0_u64, |records, segment_records, _| {
            folded_segments.set(folded_segments.get() + 1);
            Ok::<_, std::convert::Infallible>(records + segment_records)
        });
        assert!(matches!(
            result,
            Err(TreeSidecarFoldError::Sidecar(TreeSidecarError::Integrity(
                _
            )))
        ));
        assert_eq!(
            folded_segments.get(),
            1,
            "only the authenticated first segment may reach the fold"
        );

        // An independently supplied wrong root is rejected before any value is
        // returned, even though every on-disk segment remains self-authenticating.
        let (_temp, _root, store, mut wal) = fixture();
        let mut wrong_root = store.publish(&mut wal, tx(18), segments()).unwrap();
        wrong_root.root_sha256[0] ^= 1;
        let result = store.read_fold(wrong_root, (), |(), _, _| {
            Ok::<_, std::convert::Infallible>(())
        });
        assert!(matches!(result, Err(TreeSidecarFoldError::Sidecar(_))));
    }
    fn v3_directory_record(path: &[u8], inode: u64) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&(path.len() as u64).to_be_bytes());
        record.extend_from_slice(path);
        record.push(0);
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&0o700_u32.to_be_bytes());
        record.push(0);
        record
    }

    fn v3_regular_record(path: &[u8], inode: u64) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&(path.len() as u64).to_be_bytes());
        record.extend_from_slice(path);
        record.push(1);
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&0o600_u32.to_be_bytes());
        record.push(1);
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&2_i64.to_be_bytes());
        record.extend_from_slice(&3_u32.to_be_bytes());
        record.extend_from_slice(&4_i64.to_be_bytes());
        record.extend_from_slice(&5_u32.to_be_bytes());
        record.extend_from_slice(&[inode as u8; 32]);
        record.extend_from_slice(&0_u64.to_be_bytes());
        record.extend_from_slice(&0_u64.to_be_bytes());
        record.extend_from_slice(&[0_u8; 32]);
        record
    }

    fn v3_symlink_record(path: &[u8], inode: u64, target: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&(path.len() as u64).to_be_bytes());
        record.extend_from_slice(path);
        record.push(2);
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&inode.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&1000_u32.to_be_bytes());
        record.extend_from_slice(&0o777_u32.to_be_bytes());
        record.push(2);
        record.extend_from_slice(&(target.len() as u64).to_be_bytes());
        record.extend_from_slice(target);
        record
    }

    fn sorted_v3_manifest(records: &[Vec<u8>]) -> (Vec<Vec<u8>>, DurableTreeManifest) {
        let mut sorted = records.to_vec();
        sorted.sort_unstable_by(|left, right| {
            scratch::record_path(left)
                .unwrap()
                .cmp(scratch::record_path(right).unwrap())
        });
        let mut digest = Sha256::new();
        digest.update(b"degu-held-tree-manifest-v3-content-xattr\0");
        digest.update((sorted.len() as u64).to_be_bytes());
        for record in &sorted {
            digest.update(record);
        }
        (
            sorted,
            DurableTreeManifest {
                schema_version: 3,
                entry_count: records.len() as u64,
                sha256: digest.finalize().into(),
            },
        )
    }

    #[test]
    fn scratch_builder_preserves_producer_error_type_and_leaves_only_unpublished_state() {
        #[derive(Debug)]
        enum ProducerFailure {
            Scratch,
            Stop,
        }

        impl From<TreeSidecarError> for ProducerFailure {
            fn from(_error: TreeSidecarError) -> Self {
                Self::Scratch
            }
        }

        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(32);
        let target = vec![b'x'; 600_000];
        let result = store.build_sorted_manifest_scratch_with_output(
            &mut wal,
            transaction,
            |emit| -> Result<(), ProducerFailure> {
                emit(&v3_symlink_record(b"a", 2, &target))?;
                emit(&v3_symlink_record(b"b", 3, &target))?;
                Err(ProducerFailure::Stop)
            },
        );
        assert!(matches!(
            result,
            Err(scratch::TreeManifestScratchBuildError::Produce(
                ProducerFailure::Stop
            ))
        ));
        assert_eq!(wal.tree_sidecar_commitment(transaction), None);
        assert!(!root.join(final_name(transaction)).exists());
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);
    }

    #[test]
    fn sorted_scratch_fold_returns_producer_output_and_typed_records_only_after_validation() {
        use crate::backend::held::ManifestV3RecordKind;

        let (_temp, _root, store, mut wal) = fixture();
        let transaction = tx(29);
        let records = vec![
            v3_regular_record(b"z", 3),
            v3_directory_record(b"", 1),
            v3_regular_record(b"a", 2),
        ];
        let (_, expected) = sorted_v3_manifest(&records);
        let (mut scratch, producer_output) = store
            .build_sorted_manifest_scratch_with_output(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok::<_, TreeSidecarError>(73_u64)
            })
            .unwrap();
        assert_eq!(producer_output, 73);

        let visited = store
            .read_sorted_manifest_scratch(
                &mut wal,
                transaction,
                expected,
                &mut scratch,
                Vec::new(),
                |mut visited, record| {
                    visited.push((record.path.to_vec(), record.kind));
                    Ok::<_, std::convert::Infallible>(visited)
                },
            )
            .unwrap();
        assert_eq!(
            visited,
            vec![
                (b"".to_vec(), ManifestV3RecordKind::Directory),
                (b"a".to_vec(), ManifestV3RecordKind::Regular),
                (b"z".to_vec(), ManifestV3RecordKind::Regular),
            ]
        );
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);
    }

    #[test]
    fn sorted_scratch_fold_propagates_consumer_failure_without_returning_partial_state() {
        #[derive(Debug, Eq, PartialEq)]
        struct Stop;

        let (_temp, _root, store, mut wal) = fixture();
        let transaction = tx(30);
        let records = vec![v3_regular_record(b"a", 2), v3_directory_record(b"", 1)];
        let (_, expected) = sorted_v3_manifest(&records);
        let mut scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        let visits = std::cell::Cell::new(0_u64);
        let result = store.read_sorted_manifest_scratch(
            &mut wal,
            transaction,
            expected,
            &mut scratch,
            (),
            |(), _| {
                visits.set(visits.get() + 1);
                Err(Stop)
            },
        );
        assert!(matches!(result, Err(TreeSidecarFoldError::Fold(Stop))));
        assert_eq!(visits.get(), 1);
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);
    }

    #[test]
    fn sorted_scratch_fold_withholds_accumulator_after_late_run_integrity_failure() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(31);
        let records = vec![v3_directory_record(b"", 1), v3_regular_record(b"a", 2)];
        let (_, expected) = sorted_v3_manifest(&records);
        let mut scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        let run = root.join(&scratch.run_names_for_test()[0]);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(run)
            .unwrap();
        let last = file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(last)).unwrap();
        file.write_all(&byte).unwrap();
        file.flush().unwrap();

        let visits = std::cell::Cell::new(0_u64);
        let result = store.read_sorted_manifest_scratch(
            &mut wal,
            transaction,
            expected,
            &mut scratch,
            Vec::<Vec<u8>>::new(),
            |mut paths, record| {
                visits.set(visits.get() + 1);
                paths.push(record.path.to_vec());
                Ok::<_, std::convert::Infallible>(paths)
            },
        );
        assert!(matches!(
            result,
            Err(TreeSidecarFoldError::Sidecar(
                TreeSidecarError::InvalidScratch("scratch run integrity check failed")
            ))
        ));
        assert_eq!(
            visits.get(),
            2,
            "records may be observed but no accumulator returned"
        );
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 1);
    }

    #[test]
    fn scratch_external_sort_uses_many_runs_and_publishes_exact_v3_bytes() {
        let (_temp, _root, store, mut wal) = fixture();
        let transaction = tx(22);
        let mut records = (0..72_u64)
            .rev()
            .map(|index| v3_regular_record(format!("f{index:02}").as_bytes(), index + 2))
            .collect::<Vec<_>>();
        records.push(v3_directory_record(b"", 1));
        let (sorted, expected) = sorted_v3_manifest(&records);
        let scratch = store
            .build_sorted_manifest_scratch_with_budget(&mut wal, transaction, 128, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        assert!(
            scratch.max_level_for_test() >= 2,
            "fixture must exercise hierarchical bounded fan-in compaction"
        );
        // Runs hold their descriptors for their whole life, so live runs are
        // live descriptors. Eager fan-in compaction keeps at most
        // MERGE_FAN_IN - 1 runs per level, which bounds retention at
        // O(log_fan_in) of the record count rather than O(runs produced).
        let live_runs = scratch.run_names_for_test().len();
        let level_ceiling = (usize::from(scratch.max_level_for_test()) + 1)
            * (crate::seal::sidecar::scratch::MERGE_FAN_IN - 1);
        assert!(
            live_runs <= level_ceiling,
            "held run descriptors must stay bounded by level: {live_runs} > {level_ceiling}"
        );

        let commitment = store
            .publish_sorted_manifest_scratch(&mut wal, transaction, expected, scratch)
            .unwrap();
        let bytes = store
            .read_fold(commitment, Vec::new(), |mut bytes, _, payload| {
                bytes.extend_from_slice(payload);
                Ok::<_, std::convert::Infallible>(bytes)
            })
            .unwrap();
        assert_eq!(bytes, sorted.concat());
        assert_eq!(store.cleanup_unpublished(&mut wal).unwrap(), 0);
    }

    #[test]
    fn scratch_publisher_preserves_exact_legacy_segment_framing_and_commitment() {
        let (_reference_temp, _reference_root, reference, mut reference_wal) = fixture();
        let (_scratch_temp, _scratch_root, scratch_store, mut scratch_wal) = fixture();
        let transaction = tx(28);
        let target = vec![b'x'; 400_000];
        let records = vec![
            v3_symlink_record(b"d", 5, &target),
            v3_symlink_record(b"c", 4, &target),
            v3_symlink_record(b"b", 3, &target),
            v3_symlink_record(b"a", 2, &target),
            v3_directory_record(b"", 1),
        ];
        let (sorted, expected) = sorted_v3_manifest(&records);
        let reference_commitment = reference
            .publish_stream(&mut reference_wal, transaction, |emit| {
                let mut payload = Vec::with_capacity(MAX_SEGMENT_PAYLOAD);
                let mut count = 0_u64;
                for record in &sorted {
                    if count != 0 && payload.len() + record.len() > MAX_SEGMENT_PAYLOAD {
                        emit(count, &payload)?;
                        payload.clear();
                        count = 0;
                    }
                    payload.extend_from_slice(record);
                    count += 1;
                }
                if count != 0 {
                    emit(count, &payload)?;
                }
                Ok(())
            })
            .unwrap();
        let scratch = scratch_store
            .build_sorted_manifest_scratch(&mut scratch_wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        let scratch_commitment = scratch_store
            .publish_sorted_manifest_scratch(&mut scratch_wal, transaction, expected, scratch)
            .unwrap();

        assert!(reference_commitment.segment_count() > 1);
        assert_eq!(scratch_commitment, reference_commitment);
    }

    #[test]
    fn scratch_duplicate_path_fails_before_publication_and_stays_unpublished() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(23);
        let records = vec![
            v3_directory_record(b"", 1),
            v3_regular_record(b"same", 2),
            v3_regular_record(b"same", 3),
        ];
        let (_, expected) = sorted_v3_manifest(&records);
        let scratch = store
            .build_sorted_manifest_scratch_with_budget(&mut wal, transaction, 128, |emit| {
                for record in records.iter().rev() {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            store.publish_sorted_manifest_scratch(&mut wal, transaction, expected, scratch),
            Err(TreeSidecarError::InvalidScratch(
                "scratch paths are not in strict raw-byte order"
            ))
        ));
        assert!(!root.join(final_name(transaction)).exists());
        assert_eq!(wal.tree_sidecar_commitment(transaction), None);
        assert!(store.cleanup_unpublished(&mut wal).unwrap() >= 2);
    }

    #[test]
    fn scratch_fingerprint_mismatch_never_publishes_a_final_sidecar() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(24);
        let records = vec![v3_regular_record(b"z", 2), v3_directory_record(b"", 1)];
        let (_, mut expected) = sorted_v3_manifest(&records);
        expected.sha256[0] ^= 1;
        let scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            store.publish_sorted_manifest_scratch(&mut wal, transaction, expected, scratch),
            Err(TreeSidecarError::InvalidScratch(
                "merged v3 manifest fingerprint changed"
            ))
        ));
        assert!(!root.join(final_name(transaction)).exists());
        assert_eq!(wal.tree_sidecar_commitment(transaction), None);
        assert!(store.cleanup_unpublished(&mut wal).unwrap() >= 2);
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // simulates out-of-protocol scratch replacement
    fn replaced_scratch_inode_is_rejected_even_when_its_bytes_are_identical() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(27);
        let records = vec![v3_directory_record(b"", 1), v3_regular_record(b"file", 2)];
        let (_, expected) = sorted_v3_manifest(&records);
        let scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        let run = root.join(&scratch.run_names_for_test()[0]);
        let bytes = std::fs::read(&run).unwrap();
        std::fs::remove_file(&run).unwrap();
        std::fs::write(&run, bytes).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o600)).unwrap();

        // The run holds its descriptor from creation, so replacement is caught
        // through that descriptor rather than through a carried device/inode
        // copy: unlinking the run drops its link count to zero, which the held
        // descriptor observes directly. Nothing here depends on how the
        // filesystem allocates inode numbers, so ext4 recycling the number into
        // the replacement changes nothing.
        assert!(matches!(
            store.publish_sorted_manifest_scratch(&mut wal, transaction, expected, scratch),
            Err(TreeSidecarError::Unsafe {
                reason: "sidecar kind, owner, mode, or link count is invalid",
                ..
            })
        ));
        assert!(!root.join(final_name(transaction)).exists());
        assert_eq!(wal.tree_sidecar_commitment(transaction), None);
        assert!(store.cleanup_unpublished(&mut wal).unwrap() >= 2);
    }

    #[test]
    fn corrupt_scratch_run_cannot_publish_or_become_wal_evidence() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(26);
        let records = vec![v3_directory_record(b"", 1), v3_regular_record(b"file", 2)];
        let (_, expected) = sorted_v3_manifest(&records);
        let scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                for record in &records {
                    emit(record)?;
                }
                Ok(())
            })
            .unwrap();
        let run = root.join(&scratch.run_names_for_test()[0]);
        let length = std::fs::metadata(&run).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&run)
            .unwrap()
            .set_len(length - 1)
            .unwrap();

        assert!(
            store
                .publish_sorted_manifest_scratch(&mut wal, transaction, expected, scratch)
                .is_err()
        );
        assert!(!root.join(final_name(transaction)).exists());
        assert_eq!(wal.tree_sidecar_commitment(transaction), None);
        assert!(store.cleanup_unpublished(&mut wal).unwrap() >= 2);
    }

    #[test]
    fn replay_lease_cleanup_removes_canonical_scratch_but_not_lookalikes() {
        let (_temp, root, store, mut wal) = fixture();
        let transaction = tx(25);
        let scratch = store
            .build_sorted_manifest_scratch(&mut wal, transaction, |emit| {
                emit(&v3_directory_record(b"", 1))
            })
            .unwrap();
        let run_names = scratch.run_names_for_test();
        drop(scratch);
        let lookalike = root.join(format!(
            ".tree-scratch-v1-{}-0{}-01.tmp",
            transaction_hex(transaction),
            std::process::id()
        ));
        std::fs::write(&lookalike, b"keep").unwrap();
        std::fs::set_permissions(&lookalike, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            store.cleanup_unpublished(&mut wal).unwrap(),
            run_names.len() as u64
        );
        assert!(run_names.iter().all(|name| !root.join(name).exists()));
        assert!(lookalike.exists());
    }
}
