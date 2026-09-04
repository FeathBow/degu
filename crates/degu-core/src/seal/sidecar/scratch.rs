//! Unpublished, authority-neutral external sorting for v3 manifest records.
//!
//! Scratch runs live only in the already-private sidecar store. Their names are
//! internally generated, they can never be referenced by the WAL, and startup
//! removes them only after replay has resumed the exact mutable WAL lease.
//! The lease serializes cooperative publishers; retained inode, length, name-
//! bound digest, and private-file checks make same-UID replacement fail closed.

use super::*;
use crate::backend::held::{
    ManifestV3Decoder, ManifestV3Record, ManifestV3VisitError, StructureEvidence,
    compare_manifest_paths, decode_structure_record,
};
use crate::seal::wal::DurableTreeManifest;
use std::os::unix::fs::FileExt;

const SCRATCH_MAGIC: &[u8; 4] = b"DHSR";
const SCRATCH_VERSION: u16 = 1;
const SCRATCH_HEADER_LEN: usize = 72;
const SCRATCH_DOMAIN: &[u8] = b"degu-held-tree-scratch-run-v1\0";
const SCRATCH_PREFIX: &[u8] = b".tree-scratch-v1-";
const SCRATCH_SUFFIX: &[u8] = b".tmp";
const SORT_MEMORY_BYTES: usize = 1024 * 1024;
pub(super) const MERGE_FAN_IN: usize = 8;
/// Eight current records, one previous path, and one outgoing segment. Vec/file
/// bookkeeping adds a small fixed overhead outside this payload-byte ceiling.
const MERGE_PAYLOAD_MEMORY_BYTES: usize = (MERGE_FAN_IN + 2) * PURGE_RECORD_MAX_BYTES;
/// Purge records carry the manifest record plus a bounded ancestor context.
/// Keep the published manifest ceiling unchanged while admitting that fixed
/// private planning overhead.
const PURGE_RECORD_MAX_BYTES: usize = 2 * MAX_SEGMENT_PAYLOAD + 64 * 1024;
const PURGE_TOTAL_MAX_BYTES: u64 = 2 * MAX_TOTAL_PAYLOAD_BYTES + MAX_RECORDS * 64 * 1024;
const PURGE_PLAN_MAGIC: &[u8; 4] = b"DHPP";
const PURGE_PLAN_VERSION: u16 = 1;
const PURGE_PLAN_HEADER_LEN: usize = 72;
const PURGE_PLAN_DOMAIN: &[u8] = b"degu-held-tree-purge-plan-v1\0";
const PURGE_PLAN_FRAME_DOMAIN: &[u8] = b"degu-held-tree-purge-frame-v1\0";
const DIRECTORY_PLAN_MAGIC: &[u8; 4] = b"DHDP";
const DIRECTORY_PLAN_VERSION: u16 = 1;
const DIRECTORY_PLAN_HEADER_LEN: usize = 72;
const DIRECTORY_PLAN_DOMAIN: &[u8] = b"degu-held-tree-directory-plan-v1\0";
const DIRECTORY_PLAN_FRAME_DOMAIN: &[u8] = b"degu-held-tree-directory-frame-v1\0";
const DIRECTORY_PLAN_MAX_RECORD_BYTES: usize = MAX_SEGMENT_PAYLOAD;
const DIRECTORY_PLAN_MAX_TOTAL_BYTES: u64 = MAX_TOTAL_PAYLOAD_BYTES + MAX_RECORDS * 40;
static NEXT_SCRATCH_NAME: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScratchBinding {
    device: u64,
    wal_device: u64,
    wal_inode: u64,
}

/// A sorted unpublished run, held open from creation until removal. The owned
/// descriptor *is* the run's identity: while it lives the inode cannot be freed,
/// so its number cannot be recycled under us and no carried device/inode/size
/// copy is needed to detect replacement. `validate_file` still binds the
/// descriptor to its name at every use, which is what fails closed when an
/// out-of-protocol writer swaps the entry.
#[derive(Debug)]
struct ScratchRun {
    name: OsString,
    record_count: u64,
    level: u8,
    digest: [u8; 32],
    pin: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScratchOrder {
    ManifestPath,
    HardlinkIdentityThenPath,
    PurgePostorder,
}

fn validate_scratch_key(order: ScratchOrder, key: &[u8]) -> Result<(), TreeSidecarError> {
    match order {
        ScratchOrder::ManifestPath | ScratchOrder::PurgePostorder => Ok(()),
        ScratchOrder::HardlinkIdentityThenPath
            if key == [0] || (key.first() == Some(&1) && key.len() >= 25) =>
        {
            Ok(())
        }
        ScratchOrder::HardlinkIdentityThenPath => Err(TreeSidecarError::InvalidScratch(
            "hardlink scratch key is invalid",
        )),
    }
}

fn compare_scratch_keys(order: ScratchOrder, left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    match order {
        ScratchOrder::ManifestPath => compare_manifest_paths(left, right),
        ScratchOrder::PurgePostorder => {
            let left_depth = Path::new(OsStr::from_bytes(left)).components().count();
            let right_depth = Path::new(OsStr::from_bytes(right)).components().count();
            right_depth.cmp(&left_depth).then_with(|| {
                Path::new(OsStr::from_bytes(right)).cmp(Path::new(OsStr::from_bytes(left)))
            })
        }
        ScratchOrder::HardlinkIdentityThenPath => match (left.first(), right.first()) {
            (Some(0), Some(0)) => std::cmp::Ordering::Equal,
            (Some(0), _) => std::cmp::Ordering::Less,
            (_, Some(0)) => std::cmp::Ordering::Greater,
            (Some(1), Some(1)) => left[1..25]
                .cmp(&right[1..25])
                .then_with(|| compare_manifest_paths(&left[25..], &right[25..])),
            _ => left.cmp(right),
        },
    }
}

/// A set of sorted unpublished runs. It contains no filesystem or recovery
/// authority; every operation re-enters through its originating store and WAL
/// lease and revalidates the exact private files by descriptor.
#[derive(Debug)]
pub(crate) struct TreeManifestScratch {
    transaction: TransactionId,
    binding: ScratchBinding,
    record_count: u64,
    order: ScratchOrder,
    runs: Vec<ScratchRun>,
}

/// Sorted unpublished private structure observations. This wrapper prevents
/// structure-only records from reaching manifest fingerprint/publication APIs.
#[derive(Debug)]
pub(crate) struct TreeStructureScratch(TreeManifestScratch);

/// Sorted final regular-file observations keyed by strong inode identity and
/// canonical manifest path. It is unpublished, never WAL-referenceable, and
/// cannot enter manifest fingerprint or publication APIs.
#[derive(Debug)]
pub(crate) struct TreeHardlinkScratch(TreeManifestScratch);

/// Unpublished purge records sorted in the exact historical postorder.
#[derive(Debug)]
pub(crate) struct TreePurgeScratch(TreeManifestScratch);

/// One-shot pre-seal directory plan. The backing file is unlinked before any
/// record is written; only this keyed descriptor can enumerate its contents.
#[derive(Debug)]
pub(crate) struct TreeDirectoryPlan {
    file: File,
    path: PathBuf,
    transaction: TransactionId,
    frame_key: [u8; 32],
    expected_records: u64,
    expected_payload_bytes: u64,
    expected_digest: [u8; 32],
    file_bytes: u64,
    authenticated: bool,
    reverse_remaining: u64,
    reverse_offset: u64,
}

pub(crate) struct TreeStructureScratchCursor {
    scratch: TreeManifestScratch,
    readers: Vec<ScratchRunReader>,
    emitted: u64,
    previous_path: Vec<u8>,
    has_previous: bool,
    semantic_error: Option<TreeSidecarError>,
}

#[derive(Debug)]
pub(crate) enum TreeManifestScratchBuildError<E> {
    Sidecar(TreeSidecarError),
    Produce(E),
}

impl<E> From<TreeSidecarError> for TreeManifestScratchBuildError<E> {
    fn from(error: TreeSidecarError) -> Self {
        Self::Sidecar(error)
    }
}

#[cfg(test)]
fn flatten_scratch_build(
    error: TreeManifestScratchBuildError<TreeSidecarError>,
) -> TreeSidecarError {
    match error {
        TreeManifestScratchBuildError::Sidecar(error)
        | TreeManifestScratchBuildError::Produce(error) => error,
    }
}

#[derive(Debug)]
enum ScratchMergeError<E> {
    Scratch(TreeSidecarError),
    Emit(E),
}

impl<E> From<TreeSidecarError> for ScratchMergeError<E> {
    fn from(error: TreeSidecarError) -> Self {
        Self::Scratch(error)
    }
}

fn flatten_scratch_merge(error: ScratchMergeError<TreeSidecarError>) -> TreeSidecarError {
    match error {
        ScratchMergeError::Scratch(error) | ScratchMergeError::Emit(error) => error,
    }
}

#[cfg(test)]
impl TreeStructureScratch {
    pub(super) fn run_names_for_test(&self) -> Vec<OsString> {
        self.0.runs.iter().map(|run| run.name.clone()).collect()
    }
}

#[cfg(test)]
impl TreePurgeScratch {
    pub(super) fn max_level_for_test(&self) -> u8 {
        self.0.runs.iter().map(|run| run.level).max().unwrap_or(0)
    }
}

#[cfg(test)]
impl TreeHardlinkScratch {
    pub(super) fn run_names_for_test(&self) -> Vec<OsString> {
        self.0.runs.iter().map(|run| run.name.clone()).collect()
    }
}

#[cfg(test)]
impl TreeManifestScratch {
    pub(super) fn max_level_for_test(&self) -> u8 {
        self.runs.iter().map(|run| run.level).max().unwrap_or(0)
    }

    pub(super) fn run_names_for_test(&self) -> Vec<OsString> {
        self.runs.iter().map(|run| run.name.clone()).collect()
    }
}

#[derive(Clone, Copy)]
struct RecordIndex {
    offset: usize,
    length: usize,
}

struct RunBuilder<'a> {
    store: &'a TreeSidecarStore,
    transaction: TransactionId,
    memory_bytes: usize,
    order: ScratchOrder,
    arena: Vec<u8>,
    records: Vec<RecordIndex>,
    runs: Vec<ScratchRun>,
    record_count: u64,
    payload_bytes: u64,
}

impl TreeSidecarStore {
    /// Collects complete encoded v3 records into fixed-memory sorted runs. The
    /// producer may present records in any order. No run is synced or published,
    /// and neither the result nor any partially written file can become WAL
    /// evidence.
    #[cfg(test)]
    pub(crate) fn build_sorted_manifest_scratch<P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<TreeManifestScratch, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
    {
        self.build_sorted_manifest_scratch_with_output(wal, transaction, |emit| produce(emit))
            .map(|(scratch, ())| scratch)
            .map_err(flatten_scratch_build)
    }

    /// Builds the same unpublished sorted scratch while returning the producer's
    /// owned result separately. This lets traversal hand bounded descriptor/data
    /// state to a later authenticated scratch fold; the scratch object neither
    /// derives from nor augments any authority carried by that separate result.
    pub(crate) fn build_sorted_manifest_scratch_with_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<(TreeManifestScratch, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            SORT_MEMORY_BYTES,
            ScratchOrder::ManifestPath,
            produce,
        )
    }

    /// Builds fixed-memory sorted runs for fresh structure observations.
    /// Records use a private path-prefixed codec and can never be fingerprinted,
    /// published, or referenced by the WAL through this wrapper.
    pub(crate) fn build_sorted_structure_scratch_with_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<(TreeStructureScratch, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            SORT_MEMORY_BYTES,
            ScratchOrder::ManifestPath,
            produce,
        )
        .map(|(scratch, output)| (TreeStructureScratch(scratch), output))
    }

    /// Builds fixed-memory sorted runs for final regular-file observations.
    /// The private ordering groups equal strong inode identities and then uses
    /// historical component ordering for the original manifest path.
    pub(crate) fn build_sorted_hardlink_scratch_with_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<(TreeHardlinkScratch, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            SORT_MEMORY_BYTES,
            ScratchOrder::HardlinkIdentityThenPath,
            produce,
        )
        .map(|(scratch, output)| (TreeHardlinkScratch(scratch), output))
    }

    /// Folds an authenticated sorted manifest while spooling final regular-file
    /// observations into a second fixed-memory identity-sorted scratch. Keeping
    /// both builders inside this lease-bound method avoids any resident hardlink
    /// inventory and avoids publishing a pre-seal sidecar.
    pub(crate) fn build_sorted_hardlink_scratch_from_manifest<A, E, F>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        manifest_scratch: &mut TreeManifestScratch,
        expected_manifest: DurableTreeManifest,
        initial: A,
        mut fold: F,
    ) -> Result<(TreeHardlinkScratch, A), TreeSidecarFoldError<E>>
    where
        F: FnMut(
            &mut A,
            ManifestV3Record<'_>,
            &mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), E>,
    {
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        let mut builder = RunBuilder {
            store: self,
            transaction,
            memory_bytes: SORT_MEMORY_BYTES,
            order: ScratchOrder::HardlinkIdentityThenPath,
            arena: Vec::with_capacity(SORT_MEMORY_BYTES),
            records: Vec::new(),
            runs: Vec::new(),
            record_count: 0,
            payload_bytes: 0,
        };
        builder.push(crate::backend::held::hardlink_scratch_sentinel_record())?;
        let output = self.read_sorted_manifest_scratch(
            wal,
            transaction,
            expected_manifest,
            manifest_scratch,
            initial,
            |mut accumulator, record, _wal| {
                let mut emit = |bytes: &[u8]| builder.push(bytes);
                fold(&mut accumulator, record, &mut emit)?;
                Ok(accumulator)
            },
        )?;
        let scratch = TreeHardlinkScratch(builder.finish()?);
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok((scratch, output))
    }

    /// Seals BFS directory records into an anonymous keyed plan. The producer's
    /// resident traversal vector is consumed before this method returns.
    pub(crate) fn build_directory_plan_with_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        expected_records: u64,
        produce: P,
    ) -> Result<(TreeDirectoryPlan, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        let mut writer = DirectoryPlanWriter::create(self, transaction)?;
        let output = {
            let mut emit = |record: &[u8]| writer.push(record);
            produce(&mut emit).map_err(TreeManifestScratchBuildError::Produce)?
        };
        let plan = writer.finish(expected_records)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok((plan, output))
    }

    /// Builds private purge runs in deepest-first historical postorder.
    pub(crate) fn build_sorted_purge_scratch_with_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        produce: P,
    ) -> Result<(TreePurgeScratch, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            SORT_MEMORY_BYTES,
            ScratchOrder::PurgePostorder,
            produce,
        )
        .map(|(scratch, output)| (TreePurgeScratch(scratch), output))
    }

    #[cfg(test)]
    pub(super) fn build_sorted_purge_scratch_with_budget<P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        memory_bytes: usize,
        produce: P,
    ) -> Result<TreePurgeScratch, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            memory_bytes,
            ScratchOrder::PurgePostorder,
            produce,
        )
        .map(|(scratch, ())| TreePurgeScratch(scratch))
        .map_err(flatten_scratch_build)
    }

    #[cfg(test)]
    pub(super) fn build_sorted_hardlink_scratch_with_budget<P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        memory_bytes: usize,
        produce: P,
    ) -> Result<TreeHardlinkScratch, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            memory_bytes,
            ScratchOrder::HardlinkIdentityThenPath,
            produce,
        )
        .map(|(scratch, ())| TreeHardlinkScratch(scratch))
        .map_err(flatten_scratch_build)
    }

    #[cfg(test)]
    pub(super) fn build_sorted_manifest_scratch_with_budget<P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        memory_bytes: usize,
        produce: P,
    ) -> Result<TreeManifestScratch, TreeSidecarError>
    where
        P: FnOnce(
            &mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>,
        ) -> Result<(), TreeSidecarError>,
    {
        self.build_sorted_manifest_scratch_with_budget_and_output(
            wal,
            transaction,
            memory_bytes,
            ScratchOrder::ManifestPath,
            produce,
        )
        .map(|(scratch, ())| scratch)
        .map_err(flatten_scratch_build)
    }

    fn build_sorted_manifest_scratch_with_budget_and_output<T, E, P>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        memory_bytes: usize,
        order: ScratchOrder,
        produce: P,
    ) -> Result<(TreeManifestScratch, T), TreeManifestScratchBuildError<E>>
    where
        P: FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), TreeSidecarError>) -> Result<T, E>,
    {
        if memory_bytes == 0 || memory_bytes > SORT_MEMORY_BYTES {
            return Err(
                TreeSidecarError::InvalidScratch("invalid scratch sort memory budget").into(),
            );
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        let mut builder = RunBuilder {
            store: self,
            transaction,
            memory_bytes,
            order,
            arena: Vec::with_capacity(memory_bytes),
            records: Vec::new(),
            runs: Vec::new(),
            record_count: 0,
            payload_bytes: 0,
        };
        let output = {
            let mut push = |record: &[u8]| builder.push(record);
            produce(&mut push).map_err(TreeManifestScratchBuildError::Produce)?
        };
        let scratch = builder.finish()?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok((scratch, output))
    }

    /// Opens a pull cursor over globally sorted fresh structure records. Run
    /// identity and headers validate before return; complete run digests, codec
    /// EOF, and cleanup are enforced by `finish_sorted_structure_scratch_cursor`.
    pub(crate) fn open_sorted_structure_scratch_cursor(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: TreeStructureScratch,
    ) -> Result<TreeStructureScratchCursor, TreeSidecarError> {
        let mut scratch = scratch.0;
        self.require_scratch_binding(transaction, &scratch, ScratchOrder::ManifestPath)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        self.collapse_runs(&mut scratch)?;
        let readers = scratch
            .runs
            .iter()
            .map(|run| ScratchRunReader::open(self, run, ScratchOrder::ManifestPath))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TreeStructureScratchCursor {
            scratch,
            readers,
            emitted: 0,
            previous_path: Vec::new(),
            has_previous: false,
            semantic_error: None,
        })
    }

    /// Drains and authenticates the complete structure scratch, then removes its
    /// private runs and syncs the store. Scratch integrity/codec errors are
    /// returned before any held-tree comparison error retained by the caller.
    pub(crate) fn finish_sorted_structure_scratch_cursor(
        &self,
        wal: &mut SealWal<RecoverySession>,
        mut cursor: TreeStructureScratchCursor,
    ) -> Result<(), TreeSidecarError> {
        let validation = (|| {
            while !cursor.at_eof() {
                let _ = cursor.consume_next()?;
            }
            let mut integrity_error = None;
            for reader in cursor.readers {
                if let Err(error) = reader.finish()
                    && integrity_error.is_none()
                {
                    integrity_error = Some(error);
                }
            }
            if let Some(error) = integrity_error {
                return Err(error);
            }
            if let Some(error) = cursor.semantic_error {
                return Err(error);
            }
            if cursor.emitted != cursor.scratch.record_count {
                return Err(TreeSidecarError::InvalidScratch(
                    "structure scratch record count changed",
                ));
            }
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            self.remove_runs(&cursor.scratch.runs)?;
            rustix::fs::fsync(&self.directory)
                .map_err(|error| io_error(&self.path, error.into()))?;
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()
        })();
        // Normal execution must not accumulate unpublished runs. The leased
        // store-wide cleanup can safely remove corrupt/partial scratch whose
        // exact run handle was lost; published final sidecars are out of scope.
        let cleanup = self.cleanup_unpublished(wal).map(|_| ());
        match (validation, cleanup) {
            (Err(primary), _) => Err(primary),
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Authenticates and folds final regular-file observations in strong-inode
    /// groups. The sentinel, private key codec, run digests, strict global
    /// ordering, aggregate count, cleanup, and store/WAL binding all validate
    /// before a caller fold error can be returned.
    pub(crate) fn fold_sorted_hardlink_scratch<A, E, F>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: TreeHardlinkScratch,
        accumulator: A,
        fold: F,
    ) -> Result<A, TreeSidecarFoldError<E>>
    where
        F: FnMut(&mut A, &[u8]) -> Result<(), E>,
    {
        self.fold_sorted_hardlink_scratch_with_cleanup(
            wal,
            transaction,
            scratch,
            accumulator,
            fold,
            true,
        )
    }

    /// Pre-seal manifest scratch must survive this fold until its exact
    /// WAL-applied directory modes have been substituted. On success only the
    /// hardlink runs are removed; callers still perform store-wide cleanup on
    /// every error path.
    pub(crate) fn fold_sorted_hardlink_scratch_preserving_manifest<A, E, F>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: TreeHardlinkScratch,
        accumulator: A,
        fold: F,
    ) -> Result<A, TreeSidecarFoldError<E>>
    where
        F: FnMut(&mut A, &[u8]) -> Result<(), E>,
    {
        self.fold_sorted_hardlink_scratch_with_cleanup(
            wal,
            transaction,
            scratch,
            accumulator,
            fold,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn fold_sorted_hardlink_scratch_with_cleanup<A, E, F>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: TreeHardlinkScratch,
        mut accumulator: A,
        mut fold: F,
        cleanup_all_unpublished: bool,
    ) -> Result<A, TreeSidecarFoldError<E>>
    where
        F: FnMut(&mut A, &[u8]) -> Result<(), E>,
    {
        let mut scratch = scratch.0;
        let validation = (|| {
            self.require_scratch_binding(
                transaction,
                &scratch,
                ScratchOrder::HardlinkIdentityThenPath,
            )?;
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            self.collapse_runs(&mut scratch)?;
            let mut saw_sentinel = false;
            let mut semantic_error = None;
            let mut fold_error = None;
            let merged = self.merge_runs(&scratch.runs, scratch.order, |record| {
                let key = record_path(record).expect("merged scratch records were validated");
                if key == [0] {
                    if saw_sentinel || record.len() != 9 {
                        semantic_error.get_or_insert(TreeSidecarError::InvalidScratch(
                            "hardlink scratch sentinel is invalid",
                        ));
                    }
                    saw_sentinel = true;
                } else if semantic_error.is_none()
                    && fold_error.is_none()
                    && let Err(error) = fold(&mut accumulator, record)
                {
                    fold_error = Some(error);
                }
                Ok::<(), std::convert::Infallible>(())
            });
            let emitted = match merged {
                Ok(emitted) => emitted,
                Err(ScratchMergeError::Scratch(error)) => return Err(error.into()),
                Err(ScratchMergeError::Emit(never)) => match never {},
            };
            if emitted != scratch.record_count {
                return Err(TreeSidecarError::InvalidScratch(
                    "hardlink scratch record count changed",
                )
                .into());
            }
            if !saw_sentinel {
                return Err(TreeSidecarError::InvalidScratch(
                    "hardlink scratch sentinel is missing",
                )
                .into());
            }
            if let Some(error) = semantic_error {
                return Err(error.into());
            }
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            self.remove_runs(&scratch.runs)?;
            rustix::fs::fsync(&self.directory)
                .map_err(|error| io_error(&self.path, error.into()))?;
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            if let Some(error) = fold_error {
                return Err(TreeSidecarFoldError::Fold(error));
            }
            Ok(accumulator)
        })();
        let cleanup = if cleanup_all_unpublished {
            self.cleanup_unpublished(wal).map(|_| ())
        } else {
            Ok(())
        };
        match (validation, cleanup) {
            (Err(TreeSidecarFoldError::Sidecar(primary)), _) => {
                Err(TreeSidecarFoldError::Sidecar(primary))
            }
            (Err(TreeSidecarFoldError::Fold(_)), Err(cleanup)) | (Ok(_), Err(cleanup)) => {
                Err(TreeSidecarFoldError::Sidecar(cleanup))
            }
            (Err(TreeSidecarFoldError::Fold(error)), Ok(())) => {
                Err(TreeSidecarFoldError::Fold(error))
            }
            (Ok(accumulator), Ok(())) => Ok(accumulator),
        }
    }

    /// Validates and globally decodes every sorted unpublished record, returning
    /// only its fixed-size v3 fingerprint. The result is authority-neutral: the
    /// runs remain unpublished, are revalidated again during publication, and
    /// cannot become recovery evidence without the later exact WAL reference.
    pub(crate) fn fingerprint_sorted_manifest_scratch(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: &mut TreeManifestScratch,
    ) -> Result<DurableTreeManifest, TreeSidecarError> {
        self.require_scratch_binding(transaction, scratch, ScratchOrder::ManifestPath)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        self.collapse_runs(scratch)?;
        let mut decoder = ManifestV3Decoder::new(scratch.record_count).map_err(|_| {
            TreeSidecarError::InvalidScratch("sorted scratch manifest has an invalid count")
        })?;
        let merged = self.merge_runs(&scratch.runs, scratch.order, |record| {
            decoder.push_segment(1, record).map_err(|_| {
                TreeSidecarError::InvalidScratch("sorted scratch v3 record validation failed")
            })
        });
        match merged {
            Ok(count) if count == scratch.record_count => {}
            Ok(_) => {
                return Err(TreeSidecarError::InvalidScratch(
                    "sorted scratch record count changed",
                ));
            }
            Err(ScratchMergeError::Scratch(error) | ScratchMergeError::Emit(error)) => {
                return Err(error);
            }
        }
        let manifest = decoder.finish().map_err(|_| {
            TreeSidecarError::InvalidScratch("sorted scratch v3 manifest validation failed")
        })?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(manifest)
    }

    /// Authenticates and removes one unpublished manifest scratch without ever
    /// publishing it or making it WAL-referenceable. The containing directory is
    /// synced before success so later post-seal collection starts from a clean
    /// scratch namespace.
    pub(crate) fn discard_sorted_manifest_scratch(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        expected_manifest: DurableTreeManifest,
        mut scratch: TreeManifestScratch,
    ) -> Result<(), TreeSidecarError> {
        let actual = self.fingerprint_sorted_manifest_scratch(wal, transaction, &mut scratch)?;
        if actual != expected_manifest {
            return Err(TreeSidecarError::InvalidScratch(
                "discarded scratch manifest fingerprint changed",
            ));
        }
        self.require_scratch_binding(transaction, &scratch, ScratchOrder::ManifestPath)?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        self.remove_runs(&scratch.runs)?;
        rustix::fs::fsync(&self.directory).map_err(|error| io_error(&self.path, error.into()))?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()
    }

    /// Authenticates and globally decodes every sorted scratch record, folding
    /// borrowed typed records into owned authority-neutral data. The accumulator
    /// is returned only after all run identities/digests, global v3 ordering,
    /// aggregate fingerprint, root/parent constraints, and EOF checks pass.
    /// A fold error consumes partial decoder state; callers must discard any
    /// observations made before the error and may not treat them as evidence.
    pub(crate) fn read_sorted_manifest_scratch<A, E, F>(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        expected_manifest: DurableTreeManifest,
        scratch: &mut TreeManifestScratch,
        initial: A,
        mut fold: F,
    ) -> Result<A, TreeSidecarFoldError<E>>
    where
        F: FnMut(A, ManifestV3Record<'_>, &SealWal<RecoverySession>) -> Result<A, E>,
    {
        self.require_scratch_binding(transaction, scratch, ScratchOrder::ManifestPath)?;
        if expected_manifest.entry_count != scratch.record_count {
            return Err(TreeSidecarError::InvalidScratch(
                "expected manifest count does not match scratch",
            )
            .into());
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        self.collapse_runs(scratch)?;
        let mut decoder = ManifestV3Decoder::new(scratch.record_count).map_err(|_| {
            TreeSidecarError::InvalidScratch("sorted scratch manifest has an invalid count")
        })?;
        let mut accumulator = Some(initial);
        let merged = self.merge_runs(&scratch.runs, scratch.order, |record| {
            match decoder.push_segment_with(1, record, |typed| {
                let current = accumulator
                    .take()
                    .expect("scratch fold accumulator is always present");
                accumulator = Some(fold(current, typed, wal)?);
                Ok(())
            }) {
                Ok(()) => Ok(()),
                Err(ManifestV3VisitError::Codec(_)) => Err(TreeSidecarFoldError::Sidecar(
                    TreeSidecarError::InvalidScratch("sorted scratch v3 record validation failed"),
                )),
                Err(ManifestV3VisitError::Visit(error)) => Err(TreeSidecarFoldError::Fold(error)),
            }
        });
        match merged {
            Ok(count) if count == scratch.record_count => {}
            Ok(_) => {
                return Err(TreeSidecarError::InvalidScratch(
                    "sorted scratch record count changed",
                )
                .into());
            }
            Err(ScratchMergeError::Scratch(error)) => return Err(error.into()),
            Err(ScratchMergeError::Emit(error)) => return Err(error),
        }
        let actual = decoder.finish().map_err(|_| {
            TreeSidecarError::InvalidScratch("sorted scratch v3 manifest validation failed")
        })?;
        if actual != expected_manifest {
            return Err(TreeSidecarError::InvalidScratch(
                "sorted scratch v3 manifest fingerprint changed",
            )
            .into());
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(accumulator.expect("scratch fold accumulator is always present"))
    }

    /// Reduces arbitrarily many runs with bounded fan-in, merges their exact
    /// raw record bytes directly into the existing durable sidecar publisher,
    /// then removes the unpublished runs under the same mutable WAL lease.
    pub(crate) fn publish_sorted_manifest_scratch(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        expected_manifest: DurableTreeManifest,
        mut scratch: TreeManifestScratch,
    ) -> Result<TreeSidecarCommitment, TreeSidecarError> {
        self.require_scratch_binding(transaction, &scratch, ScratchOrder::ManifestPath)?;
        if expected_manifest.entry_count != scratch.record_count {
            return Err(TreeSidecarError::InvalidScratch(
                "expected manifest count does not match scratch",
            ));
        }
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        self.collapse_runs(&mut scratch)?;
        let expected_records = scratch.record_count;
        let order = scratch.order;
        // The runs move out for the duration of the merge; each one carries its
        // own held descriptor, so they are borrowed here rather than copied.
        let runs = std::mem::take(&mut scratch.runs);
        let commitment = self.publish_stream(wal, transaction, |emit| {
            let mut decoder = ManifestV3Decoder::new(expected_records).map_err(|_| {
                TreeSidecarError::InvalidScratch("merged v3 manifest has an invalid count")
            })?;
            {
                let mut segment = SegmentBuilder::new(emit, &mut decoder);
                let merged = self
                    .merge_runs(&runs, order, |record| segment.push(record))
                    .map_err(flatten_scratch_merge)?;
                if merged != expected_records {
                    return Err(TreeSidecarError::InvalidScratch(
                        "merged scratch record count changed",
                    ));
                }
                segment.finish()?;
            }
            let actual = decoder.finish().map_err(|_| {
                TreeSidecarError::InvalidScratch("merged v3 manifest validation failed")
            })?;
            if actual != expected_manifest {
                return Err(TreeSidecarError::InvalidScratch(
                    "merged v3 manifest fingerprint changed",
                ));
            }
            Ok(())
        })?;
        if commitment.record_count() != expected_records {
            return Err(TreeSidecarError::InvalidScratch(
                "published scratch record count changed",
            ));
        }
        self.remove_runs(&runs)?;
        rustix::fs::fsync(&self.directory).map_err(|error| io_error(&self.path, error.into()))?;
        self.require_matching_wal(wal)?;
        self.revalidate_store_binding()?;
        Ok(commitment)
    }

    /// Authenticates all named purge runs and seals them into an anonymous,
    /// descriptor-only sequential purge plan. Named runs are removed and the
    /// containing directory synced before the plan is returned.
    pub(crate) fn seal_sorted_purge_scratch(
        &self,
        wal: &mut SealWal<RecoverySession>,
        transaction: TransactionId,
        scratch: TreePurgeScratch,
    ) -> Result<TreePurgePlan, TreeSidecarError> {
        let mut scratch = scratch.0;
        let validation = (|| {
            self.require_scratch_binding(transaction, &scratch, ScratchOrder::PurgePostorder)?;
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            self.collapse_runs(&mut scratch)?;
            let mut writer = PurgePlanWriter::create(self, transaction)?;
            let expected = scratch.record_count;
            let emitted = self
                .merge_runs(&scratch.runs, ScratchOrder::PurgePostorder, |record| {
                    writer.push(record)
                })
                .map_err(flatten_scratch_merge)?;
            if emitted != expected {
                return Err(TreeSidecarError::InvalidScratch(
                    "purge scratch record count changed",
                ));
            }
            let plan = writer.finish(expected)?;
            self.remove_runs(&scratch.runs)?;
            rustix::fs::fsync(&self.directory)
                .map_err(|error| io_error(&self.path, error.into()))?;
            self.require_matching_wal(wal)?;
            self.revalidate_store_binding()?;
            Ok(plan)
        })();
        let cleanup = self.cleanup_unpublished(wal).map(|_| ());
        match (validation, cleanup) {
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Ok(plan), Ok(())) => Ok(plan),
        }
    }

    fn require_scratch_binding(
        &self,
        transaction: TransactionId,
        scratch: &TreeManifestScratch,
        expected_order: ScratchOrder,
    ) -> Result<(), TreeSidecarError> {
        if scratch.transaction != transaction
            || scratch.order != expected_order
            || scratch.binding
                != (ScratchBinding {
                    device: self.device,
                    wal_device: self.wal_device,
                    wal_inode: self.wal_inode,
                })
            || scratch.record_count == 0
            || scratch.runs.is_empty()
        {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch does not match its transaction and store",
            ));
        }
        Ok(())
    }

    fn collapse_runs(&self, scratch: &mut TreeManifestScratch) -> Result<(), TreeSidecarError> {
        while scratch.runs.len() > MERGE_FAN_IN {
            let old_runs = std::mem::take(&mut scratch.runs);
            let mut next = Vec::with_capacity(old_runs.len().div_ceil(MERGE_FAN_IN));
            // Runs own their held descriptors, so groups are taken by value
            // rather than sliced and copied.
            let mut remaining = old_runs.into_iter();
            loop {
                let group = remaining
                    .by_ref()
                    .take(MERGE_FAN_IN)
                    .collect::<Vec<ScratchRun>>();
                if group.is_empty() {
                    break;
                }
                if group.len() == 1 {
                    next.extend(group);
                    continue;
                }
                let level = group
                    .iter()
                    .map(|run| run.level)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(TreeSidecarError::InvalidScratch(
                        "scratch merge level overflow",
                    ))?;
                let output =
                    self.create_merged_run(scratch.transaction, &group, level, scratch.order)?;
                self.remove_runs(&group)?;
                next.push(output);
            }
            scratch.runs = next;
        }
        let merged_count = scratch.runs.iter().try_fold(0_u64, |total, run| {
            total
                .checked_add(run.record_count)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch record count overflow",
                ))
        })?;
        if merged_count != scratch.record_count {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch record count changed during merge",
            ));
        }
        Ok(())
    }

    fn create_merged_run(
        &self,
        transaction: TransactionId,
        runs: &[ScratchRun],
        level: u8,
        order: ScratchOrder,
    ) -> Result<ScratchRun, TreeSidecarError> {
        let mut writer = ScratchRunWriter::create(self, transaction)?;
        let count = self
            .merge_runs(runs, order, |record| writer.push(record))
            .map_err(flatten_scratch_merge)?;
        writer.finish(count, level)
    }

    fn merge_runs<E>(
        &self,
        runs: &[ScratchRun],
        order: ScratchOrder,
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<u64, ScratchMergeError<E>> {
        debug_assert_eq!(
            MERGE_PAYLOAD_MEMORY_BYTES,
            (MERGE_FAN_IN + 2) * PURGE_RECORD_MAX_BYTES
        );
        if runs.is_empty() || runs.len() > MERGE_FAN_IN {
            return Err(TreeSidecarError::InvalidScratch("invalid scratch merge fan-in").into());
        }
        let mut readers = runs
            .iter()
            .map(|run| ScratchRunReader::open(self, run, order))
            .collect::<Result<Vec<_>, _>>()?;
        let mut emitted = 0_u64;
        let mut previous_path = Vec::new();
        let mut has_previous = false;
        loop {
            let selected = readers
                .iter()
                .enumerate()
                .filter(|(_, reader)| reader.current.is_some())
                .min_by(|(_, left), (_, right)| {
                    compare_scratch_keys(
                        order,
                        record_path(left.current.as_deref().unwrap())
                            .expect("opened scratch records were validated"),
                        record_path(right.current.as_deref().unwrap())
                            .expect("opened scratch records were validated"),
                    )
                })
                .map(|(index, _)| index);
            let Some(selected) = selected else {
                break;
            };
            let record = readers[selected]
                .current
                .as_deref()
                .expect("selected scratch reader has a record");
            let path = record_path(record)?;
            if has_previous
                && compare_scratch_keys(order, &previous_path, path) != std::cmp::Ordering::Less
            {
                return Err(TreeSidecarError::InvalidScratch(
                    "scratch paths are not in strict component order",
                )
                .into());
            }
            previous_path.clear();
            previous_path.extend_from_slice(path);
            has_previous = true;
            emit(record).map_err(ScratchMergeError::Emit)?;
            emitted = emitted
                .checked_add(1)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch record count overflow",
                ))?;
            readers[selected].advance()?;
        }
        for reader in readers {
            reader.finish()?;
        }
        Ok(emitted)
    }

    fn remove_runs(&self, runs: &[ScratchRun]) -> Result<(), TreeSidecarError> {
        for run in runs {
            let path = self.path.join(&run.name);
            // Removal goes through the same pin, so the entry unlinked here is
            // the entry this run has held open since it was written.
            remove_validated_private_file(
                &self.directory,
                &run.name,
                &run.pin,
                self.backend,
                self.device,
                &path,
            )?;
        }
        Ok(())
    }
}

impl RunBuilder<'_> {
    fn push(&mut self, record: &[u8]) -> Result<(), TreeSidecarError> {
        if self.record_count >= MAX_RECORDS {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch record count exceeds the sidecar limit",
            ));
        }
        let key = record_path(record)?;
        validate_scratch_key(self.order, key)?;
        let max_record = if self.order == ScratchOrder::PurgePostorder {
            PURGE_RECORD_MAX_BYTES
        } else {
            MAX_SEGMENT_PAYLOAD
        };
        if record.len() > max_record {
            return Err(TreeSidecarError::InvalidScratch(
                "one scratch record exceeds the manifest limit plus ancestor overhead",
            ));
        }
        let record_bytes = u64::try_from(record.len()).map_err(|_| {
            TreeSidecarError::InvalidScratch("scratch record length is not representable")
        })?;
        self.payload_bytes = self.payload_bytes.checked_add(record_bytes).ok_or(
            TreeSidecarError::InvalidScratch("scratch aggregate payload length overflow"),
        )?;
        let max_payload_bytes = if self.order == ScratchOrder::PurgePostorder {
            PURGE_TOTAL_MAX_BYTES
        } else {
            MAX_TOTAL_PAYLOAD_BYTES
        };
        if self.payload_bytes > max_payload_bytes {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch aggregate payload exceeds its order-specific limit",
            ));
        }
        let charge = record
            .len()
            .checked_add(std::mem::size_of::<RecordIndex>())
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch memory charge overflow",
            ))?;
        let used = self
            .arena
            .len()
            .checked_add(
                self.records
                    .len()
                    .checked_mul(std::mem::size_of::<RecordIndex>())
                    .ok_or(TreeSidecarError::InvalidScratch(
                        "scratch memory charge overflow",
                    ))?,
            )
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch memory charge overflow",
            ))?;
        if !self.records.is_empty() && used.saturating_add(charge) > self.memory_bytes {
            self.flush()?;
        }
        let offset = self.arena.len();
        self.arena.extend_from_slice(record);
        self.records.push(RecordIndex {
            offset,
            length: record.len(),
        });
        self.record_count =
            self.record_count
                .checked_add(1)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch record count overflow",
                ))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), TreeSidecarError> {
        if self.records.is_empty() {
            return Ok(());
        }
        self.records.sort_unstable_by(|left, right| {
            let left = &self.arena[left.offset..left.offset + left.length];
            let right = &self.arena[right.offset..right.offset + right.length];
            compare_scratch_keys(
                self.order,
                record_path(left).expect("buffered scratch records were validated"),
                record_path(right).expect("buffered scratch records were validated"),
            )
        });
        let mut writer = ScratchRunWriter::create(self.store, self.transaction)?;
        for index in &self.records {
            writer.push(&self.arena[index.offset..index.offset + index.length])?;
        }
        let count = u64::try_from(self.records.len()).map_err(|_| {
            TreeSidecarError::InvalidScratch("scratch run record count is not representable")
        })?;
        let run = writer.finish(count, 0)?;
        self.arena.clear();
        self.records.clear();
        self.insert_run(run)
    }

    fn insert_run(&mut self, run: ScratchRun) -> Result<(), TreeSidecarError> {
        self.runs.push(run);
        loop {
            let Some(level) = self.runs.iter().map(|run| run.level).find(|level| {
                self.runs.iter().filter(|run| run.level == *level).count() >= MERGE_FAN_IN
            }) else {
                return Ok(());
            };
            let mut group = Vec::with_capacity(MERGE_FAN_IN);
            let mut retained = Vec::with_capacity(self.runs.len() - MERGE_FAN_IN + 1);
            for run in self.runs.drain(..) {
                if run.level == level && group.len() < MERGE_FAN_IN {
                    group.push(run);
                } else {
                    retained.push(run);
                }
            }
            let next_level = level
                .checked_add(1)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch merge level overflow",
                ))?;
            let output =
                self.store
                    .create_merged_run(self.transaction, &group, next_level, self.order)?;
            self.store.remove_runs(&group)?;
            retained.push(output);
            self.runs = retained;
        }
    }

    fn finish(mut self) -> Result<TreeManifestScratch, TreeSidecarError> {
        self.flush()?;
        if self.record_count == 0 || self.runs.is_empty() {
            return Err(TreeSidecarError::InvalidScratch(
                "a scratch manifest must contain at least one record",
            ));
        }
        Ok(TreeManifestScratch {
            transaction: self.transaction,
            binding: ScratchBinding {
                device: self.store.device,
                wal_device: self.store.wal_device,
                wal_inode: self.store.wal_inode,
            },
            record_count: self.record_count,
            order: self.order,
            runs: self.runs,
        })
    }
}

struct ScratchRunWriter<'a> {
    store: &'a TreeSidecarStore,
    transaction: TransactionId,
    name: OsString,
    path: PathBuf,
    file: File,
    digest: Sha256,
    payload_bytes: u64,
    records: u64,
}

impl<'a> ScratchRunWriter<'a> {
    fn create(
        store: &'a TreeSidecarStore,
        transaction: TransactionId,
    ) -> Result<Self, TreeSidecarError> {
        let name = scratch_name(transaction);
        let path = store.path.join(&name);
        let fd = match rustix::fs::openat(&store.directory, &name, OPEN_NEW, FILE_MODE) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) => return Err(TreeSidecarError::AlreadyExists(path)),
            Err(error) => return Err(io_error(&path, error.into())),
        };
        rustix::fs::fchmod(&fd, FILE_MODE).map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &store.directory,
            &name,
            &fd,
            store.backend,
            store.device,
            &path,
        )?;
        let mut file = File::from(fd);
        file.write_all(&[0_u8; SCRATCH_HEADER_LEN])
            .map_err(|error| io_error(&path, error))?;
        let mut digest = Sha256::new();
        digest.update(SCRATCH_DOMAIN);
        digest.update(transaction.0);
        digest.update(name.as_bytes());
        Ok(Self {
            store,
            transaction,
            name,
            path,
            file,
            digest,
            payload_bytes: 0,
            records: 0,
        })
    }

    fn push(&mut self, record: &[u8]) -> Result<(), TreeSidecarError> {
        record_path(record)?;
        let length = u32::try_from(record.len()).map_err(|_| {
            TreeSidecarError::InvalidScratch("scratch record length is not representable")
        })?;
        let frame_len =
            4_u64
                .checked_add(u64::from(length))
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch payload length overflow",
                ))?;
        self.payload_bytes =
            self.payload_bytes
                .checked_add(frame_len)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch payload length overflow",
                ))?;
        let length_bytes = length.to_be_bytes();
        self.file
            .write_all(&length_bytes)
            .and_then(|()| self.file.write_all(record))
            .map_err(|error| io_error(&self.path, error))?;
        self.digest.update(length_bytes);
        self.digest.update(record);
        self.records = self
            .records
            .checked_add(1)
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch record count overflow",
            ))?;
        Ok(())
    }

    fn finish(mut self, expected_records: u64, level: u8) -> Result<ScratchRun, TreeSidecarError> {
        if self.records == 0 || self.records != expected_records {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch run record count changed",
            ));
        }
        self.digest.update(self.records.to_be_bytes());
        self.digest.update(self.payload_bytes.to_be_bytes());
        let digest = self.digest.finalize().into();
        let header =
            encode_scratch_header(self.transaction, self.records, self.payload_bytes, digest);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(&header))
            .and_then(|_| self.file.flush())
            .map_err(|error| io_error(&self.path, error))?;
        validate_file(
            &self.store.directory,
            &self.name,
            &self.file,
            self.store.backend,
            self.store.device,
            &self.path,
        )?;
        Ok(ScratchRun {
            name: self.name,
            record_count: self.records,
            level,
            digest,
            pin: self.file,
        })
    }
}

impl TreeStructureScratchCursor {
    pub(crate) fn next(&mut self) -> Result<Option<StructureEvidence>, TreeSidecarError> {
        self.consume_next()
    }

    fn at_eof(&self) -> bool {
        self.readers.iter().all(|reader| reader.current.is_none())
    }

    fn consume_next(&mut self) -> Result<Option<StructureEvidence>, TreeSidecarError> {
        let selected = self
            .readers
            .iter()
            .enumerate()
            .filter(|(_, reader)| reader.current.is_some())
            .min_by(|(_, left), (_, right)| {
                compare_manifest_paths(
                    record_path(left.current.as_deref().unwrap())
                        .expect("opened scratch records were path-validated"),
                    record_path(right.current.as_deref().unwrap())
                        .expect("opened scratch records were path-validated"),
                )
            })
            .map(|(index, _)| index);
        let Some(selected) = selected else {
            return Ok(None);
        };
        let record = self.readers[selected]
            .current
            .as_deref()
            .expect("selected structure scratch reader has a record");
        let path = record_path(record)?;
        if self.has_previous
            && compare_manifest_paths(&self.previous_path, path) != std::cmp::Ordering::Less
            && self.semantic_error.is_none()
        {
            self.semantic_error = Some(TreeSidecarError::InvalidScratch(
                "structure scratch paths are not in strict component order",
            ));
        }
        self.previous_path.clear();
        self.previous_path.extend_from_slice(path);
        self.has_previous = true;
        let evidence = if self.semantic_error.is_none() {
            match decode_structure_record(record) {
                Ok(evidence) => Some(evidence),
                Err(_) => {
                    self.semantic_error = Some(TreeSidecarError::InvalidScratch(
                        "structure scratch record validation failed",
                    ));
                    None
                }
            }
        } else {
            None
        };
        self.readers[selected].advance()?;
        self.emitted = self
            .emitted
            .checked_add(1)
            .ok_or(TreeSidecarError::InvalidScratch(
                "structure scratch record count overflow",
            ))?;
        Ok(evidence)
    }
}

fn directory_plan_digest(transaction: TransactionId) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(DIRECTORY_PLAN_DOMAIN);
    digest.update(transaction.0);
    digest
}

fn directory_plan_frame_tag(
    key: &[u8; 32],
    transaction: TransactionId,
    ordinal: u64,
    length: [u8; 4],
    record: &[u8],
) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (pad, byte) in inner_pad.iter_mut().zip(key) {
        *pad ^= byte;
    }
    for (pad, byte) in outer_pad.iter_mut().zip(key) {
        *pad ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(DIRECTORY_PLAN_FRAME_DOMAIN);
    inner.update(transaction.0);
    inner.update(ordinal.to_be_bytes());
    inner.update(length);
    inner.update(record);
    let inner: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn plan_read_exact_at(
    file: &File,
    path: &Path,
    offset: u64,
    bytes: &mut [u8],
) -> Result<(), TreeSidecarError> {
    file.read_exact_at(bytes, offset)
        .map_err(|error| io_error(path, error))
}

impl TreeDirectoryPlan {
    fn validate_header(&self) -> Result<(), TreeSidecarError> {
        let mut header = [0_u8; DIRECTORY_PLAN_HEADER_LEN];
        plan_read_exact_at(&self.file, &self.path, 0, &mut header)?;
        if &header[0..4] != DIRECTORY_PLAN_MAGIC
            || u16::from_be_bytes(header[4..6].try_into().unwrap()) != DIRECTORY_PLAN_VERSION
            || u16::from_be_bytes(header[6..8].try_into().unwrap()) as usize
                != DIRECTORY_PLAN_HEADER_LEN
            || header[8..24] != self.transaction.0
            || u64::from_be_bytes(header[24..32].try_into().unwrap()) != self.expected_records
            || u64::from_be_bytes(header[32..40].try_into().unwrap()) != self.expected_payload_bytes
            || header[40..72] != self.expected_digest
        {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan header validation failed",
            ));
        }
        Ok(())
    }

    fn read_forward_frame(
        &self,
        ordinal: u64,
        offset: u64,
    ) -> Result<(Vec<u8>, u64), TreeSidecarError> {
        let mut length_bytes = [0_u8; 4];
        plan_read_exact_at(&self.file, &self.path, offset, &mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > DIRECTORY_PLAN_MAX_RECORD_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid directory plan record length",
            ));
        }
        let mut frame_tag = [0_u8; 32];
        plan_read_exact_at(&self.file, &self.path, offset + 4, &mut frame_tag)?;
        let mut record = vec![0_u8; length];
        plan_read_exact_at(&self.file, &self.path, offset + 36, &mut record)?;
        let trailing_offset =
            offset
                .checked_add(36 + length as u64)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "directory plan frame offset overflow",
                ))?;
        let mut trailing = [0_u8; 4];
        plan_read_exact_at(&self.file, &self.path, trailing_offset, &mut trailing)?;
        if trailing != length_bytes
            || directory_plan_frame_tag(
                &self.frame_key,
                self.transaction,
                ordinal,
                length_bytes,
                &record,
            ) != frame_tag
        {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan frame authentication failed",
            ));
        }
        Ok((record, trailing_offset + 4))
    }

    /// Authenticates the entire anonymous plan before TreeSealIntent. Every frame
    /// is authenticated again when scanned or consumed in reverse.
    pub(crate) fn authenticate(&mut self) -> Result<(), TreeSidecarError> {
        self.authenticated = false;
        self.validate_header()?;
        let mut offset = DIRECTORY_PLAN_HEADER_LEN as u64;
        let mut payload_bytes = 0_u64;
        let mut digest = directory_plan_digest(self.transaction);
        for ordinal in 0..self.expected_records {
            let (record, next) = self.read_forward_frame(ordinal, offset)?;
            let length = (record.len() as u32).to_be_bytes();
            let tag = directory_plan_frame_tag(
                &self.frame_key,
                self.transaction,
                ordinal,
                length,
                &record,
            );
            digest.update(length);
            digest.update(tag);
            digest.update(&record);
            digest.update(length);
            payload_bytes = payload_bytes.checked_add(next - offset).ok_or(
                TreeSidecarError::InvalidScratch("directory plan payload overflow"),
            )?;
            offset = next;
        }
        digest.update(self.expected_records.to_be_bytes());
        digest.update(self.expected_payload_bytes.to_be_bytes());
        let actual: [u8; 32] = digest.finalize().into();
        if offset != self.file_bytes
            || payload_bytes != self.expected_payload_bytes
            || actual != self.expected_digest
        {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan aggregate integrity failed",
            ));
        }
        self.authenticated = true;
        self.reverse_remaining = self.expected_records;
        self.reverse_offset = self.file_bytes;
        Ok(())
    }

    pub(crate) fn record_count(&self) -> u64 {
        self.expected_records
    }

    pub(crate) fn for_each_forward<E>(
        &self,
        mut visit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), TreeSidecarFoldError<E>> {
        if !self.authenticated {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan scan precedes authentication",
            )
            .into());
        }
        let mut offset = DIRECTORY_PLAN_HEADER_LEN as u64;
        for ordinal in 0..self.expected_records {
            let (record, next) = self.read_forward_frame(ordinal, offset)?;
            visit(&record).map_err(TreeSidecarFoldError::Fold)?;
            offset = next;
        }
        if offset != self.file_bytes {
            return Err(
                TreeSidecarError::InvalidScratch("directory plan scan did not reach EOF").into(),
            );
        }
        Ok(())
    }

    pub(crate) fn next_reverse(&mut self) -> Result<Option<Vec<u8>>, TreeSidecarError> {
        if !self.authenticated {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan reverse read precedes authentication",
            ));
        }
        if self.reverse_remaining == 0 {
            if self.reverse_offset != DIRECTORY_PLAN_HEADER_LEN as u64 {
                return Err(TreeSidecarError::InvalidScratch(
                    "directory plan reverse read missed the header boundary",
                ));
            }
            return Ok(None);
        }
        if self.reverse_offset < DIRECTORY_PLAN_HEADER_LEN as u64 + 40 {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan reverse frame is truncated",
            ));
        }
        let mut trailing = [0_u8; 4];
        plan_read_exact_at(
            &self.file,
            &self.path,
            self.reverse_offset - 4,
            &mut trailing,
        )?;
        let length = u32::from_be_bytes(trailing) as u64;
        if length == 0 || length as usize > DIRECTORY_PLAN_MAX_RECORD_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid reverse directory plan length",
            ));
        }
        let frame_bytes = length
            .checked_add(40)
            .ok_or(TreeSidecarError::InvalidScratch(
                "directory plan reverse frame length overflow",
            ))?;
        let start = self
            .reverse_offset
            .checked_sub(frame_bytes)
            .filter(|offset| *offset >= DIRECTORY_PLAN_HEADER_LEN as u64)
            .ok_or(TreeSidecarError::InvalidScratch(
                "directory plan reverse frame crosses the header",
            ))?;
        let ordinal = self.reverse_remaining - 1;
        let (record, next) = self.read_forward_frame(ordinal, start)?;
        if next != self.reverse_offset {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan reverse frame boundary changed",
            ));
        }
        self.reverse_offset = start;
        self.reverse_remaining -= 1;
        Ok(Some(record))
    }

    pub(crate) fn finish(mut self) -> Result<(), TreeSidecarError> {
        while self.next_reverse()?.is_some() {}
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn link_count_for_test(&self) -> libc::nlink_t {
        rustix::fs::fstat(&self.file).unwrap().st_nlink
    }

    #[cfg(test)]
    pub(crate) fn corrupt_frame_for_test(&self, target: u64) {
        let mut offset = DIRECTORY_PLAN_HEADER_LEN as u64;
        for ordinal in 0..self.expected_records {
            let (record, next) = self.read_forward_frame(ordinal, offset).unwrap();
            if ordinal == target {
                let byte_offset = offset + 36;
                let byte = [record[0] ^ 0x80];
                self.file.write_all_at(&byte, byte_offset).unwrap();
                self.file.sync_data().unwrap();
                return;
            }
            offset = next;
        }
        panic!("directory plan test frame {target} is absent");
    }
}

fn require_anonymous_plan_fd(file: &File, path: &Path) -> Result<(), TreeSidecarError> {
    let stat = rustix::fs::fstat(file).map_err(|error| io_error(path, error.into()))?;
    if stat.st_nlink != 0 {
        return Err(TreeSidecarError::InvalidScratch(
            "ephemeral plan descriptor remains named",
        ));
    }
    Ok(())
}

struct DirectoryPlanWriter {
    transaction: TransactionId,
    path: PathBuf,
    file: File,
    frame_key: [u8; 32],
    digest: Sha256,
    payload_bytes: u64,
    records: u64,
}

impl DirectoryPlanWriter {
    #[allow(clippy::disallowed_methods)]
    fn create(
        store: &TreeSidecarStore,
        transaction: TransactionId,
    ) -> Result<Self, TreeSidecarError> {
        let name = scratch_name(transaction);
        let path = store.path.join(&name);
        let fd = rustix::fs::openat(&store.directory, &name, OPEN_NEW, FILE_MODE)
            .map_err(|error| io_error(&path, error.into()))?;
        rustix::fs::fchmod(&fd, FILE_MODE).map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &store.directory,
            &name,
            &fd,
            store.backend,
            store.device,
            &path,
        )?;
        let mut file = File::from(fd);
        file.write_all(&[0_u8; DIRECTORY_PLAN_HEADER_LEN])
            .map_err(|error| io_error(&path, error))?;
        rustix::fs::unlinkat(&store.directory, &name, AtFlags::empty())
            .map_err(|error| io_error(&path, error.into()))?;
        require_anonymous_plan_fd(&file, &path)?;
        rustix::fs::fsync(&store.directory).map_err(|error| io_error(&store.path, error.into()))?;
        let mut frame_key = [0_u8; 32];
        getrandom::fill(&mut frame_key)
            .map_err(|error| io_error(&path, io::Error::other(error)))?;
        Ok(Self {
            transaction,
            path,
            file,
            frame_key,
            digest: directory_plan_digest(transaction),
            payload_bytes: 0,
            records: 0,
        })
    }

    fn push(&mut self, record: &[u8]) -> Result<(), TreeSidecarError> {
        if record.is_empty() || record.len() > DIRECTORY_PLAN_MAX_RECORD_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid directory plan record",
            ));
        }
        let length = u32::try_from(record.len())
            .map_err(|_| TreeSidecarError::InvalidScratch("directory plan length overflow"))?
            .to_be_bytes();
        let tag = directory_plan_frame_tag(
            &self.frame_key,
            self.transaction,
            self.records,
            length,
            record,
        );
        self.file
            .write_all(&length)
            .and_then(|_| self.file.write_all(&tag))
            .and_then(|_| self.file.write_all(record))
            .and_then(|_| self.file.write_all(&length))
            .map_err(|error| io_error(&self.path, error))?;
        self.digest.update(length);
        self.digest.update(tag);
        self.digest.update(record);
        self.digest.update(length);
        self.payload_bytes = self
            .payload_bytes
            .checked_add(40 + record.len() as u64)
            .filter(|bytes| *bytes <= DIRECTORY_PLAN_MAX_TOTAL_BYTES)
            .ok_or(TreeSidecarError::InvalidScratch(
                "directory plan exceeds its payload limit",
            ))?;
        self.records = self
            .records
            .checked_add(1)
            .filter(|n| *n <= MAX_RECORDS)
            .ok_or(TreeSidecarError::InvalidScratch(
                "directory plan record count overflow",
            ))?;
        Ok(())
    }

    fn finish(mut self, expected: u64) -> Result<TreeDirectoryPlan, TreeSidecarError> {
        if expected == 0 || self.records != expected {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan record count changed",
            ));
        }
        self.digest.update(self.records.to_be_bytes());
        self.digest.update(self.payload_bytes.to_be_bytes());
        let digest: [u8; 32] = self.digest.finalize().into();
        let mut header = [0_u8; DIRECTORY_PLAN_HEADER_LEN];
        header[0..4].copy_from_slice(DIRECTORY_PLAN_MAGIC);
        header[4..6].copy_from_slice(&DIRECTORY_PLAN_VERSION.to_be_bytes());
        header[6..8].copy_from_slice(&(DIRECTORY_PLAN_HEADER_LEN as u16).to_be_bytes());
        header[8..24].copy_from_slice(&self.transaction.0);
        header[24..32].copy_from_slice(&self.records.to_be_bytes());
        header[32..40].copy_from_slice(&self.payload_bytes.to_be_bytes());
        header[40..72].copy_from_slice(&digest);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(&header))
            .and_then(|_| self.file.sync_all())
            .map_err(|error| io_error(&self.path, error))?;
        let stat =
            rustix::fs::fstat(&self.file).map_err(|error| io_error(&self.path, error.into()))?;
        let file_bytes = u64::try_from(stat.st_size).map_err(|_| {
            TreeSidecarError::InvalidScratch("directory plan file length is not representable")
        })?;
        let expected_bytes = DIRECTORY_PLAN_HEADER_LEN as u64 + self.payload_bytes;
        if file_bytes != expected_bytes {
            return Err(TreeSidecarError::InvalidScratch(
                "directory plan file length changed",
            ));
        }
        Ok(TreeDirectoryPlan {
            file: self.file,
            path: self.path,
            transaction: self.transaction,
            frame_key: self.frame_key,
            expected_records: self.records,
            expected_payload_bytes: self.payload_bytes,
            expected_digest: digest,
            file_bytes,
            authenticated: false,
            reverse_remaining: 0,
            reverse_offset: 0,
        })
    }
}

fn purge_plan_digest(transaction: TransactionId) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(PURGE_PLAN_DOMAIN);
    digest.update(transaction.0);
    digest
}

fn purge_plan_frame_tag(
    key: &[u8; 32],
    transaction: TransactionId,
    ordinal: u64,
    length: [u8; 4],
    record: &[u8],
) -> [u8; 32] {
    // HMAC-SHA256 with a fixed 32-byte random key retained only by the
    // one-shot authority. A pathname racer cannot forge, remove, duplicate, or
    // reorder a record that will pass the pre-unlink frame check.
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (pad, byte) in inner_pad.iter_mut().zip(key) {
        *pad ^= byte;
    }
    for (pad, byte) in outer_pad.iter_mut().zip(key) {
        *pad ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(PURGE_PLAN_FRAME_DOMAIN);
    inner.update(transaction.0);
    inner.update(ordinal.to_be_bytes());
    inner.update(length);
    inner.update(record);
    let inner: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/// A sealed purge plan owns only an unlinked file descriptor. It has no
/// pathname authority and can be consumed exactly once.
#[derive(Debug)]
pub(crate) struct TreePurgePlan {
    file: File,
    path: PathBuf,
    transaction: TransactionId,
    frame_key: [u8; 32],
    expected_records: u64,
    expected_payload_bytes: u64,
    expected_digest: [u8; 32],
    remaining: u64,
    payload_bytes: u64,
    digest: Sha256,
    previous_path: Option<Vec<u8>>,
    checked_eof: bool,
}

impl TreePurgePlan {
    pub(crate) fn next(&mut self) -> Result<Option<Vec<u8>>, TreeSidecarError> {
        if self.remaining == 0 {
            if !self.checked_eof {
                let mut extra = [0_u8; 1];
                if self
                    .file
                    .read(&mut extra)
                    .map_err(|error| io_error(&self.path, error))?
                    != 0
                {
                    return Err(TreeSidecarError::InvalidScratch(
                        "purge plan contains trailing bytes",
                    ));
                }
                self.digest.update(self.expected_records.to_be_bytes());
                self.digest
                    .update(self.expected_payload_bytes.to_be_bytes());
                let actual: [u8; 32] = self.digest.clone().finalize().into();
                if self.payload_bytes != self.expected_payload_bytes
                    || actual != self.expected_digest
                {
                    return Err(TreeSidecarError::InvalidScratch(
                        "purge plan integrity check failed",
                    ));
                }
                self.checked_eof = true;
            }
            return Ok(None);
        }
        let mut length_bytes = [0_u8; 4];
        self.file
            .read_exact(&mut length_bytes)
            .map_err(|error| io_error(&self.path, error))?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > PURGE_RECORD_MAX_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid purge plan record length",
            ));
        }
        let mut frame_tag = [0_u8; 32];
        self.file
            .read_exact(&mut frame_tag)
            .map_err(|error| io_error(&self.path, error))?;
        let mut record = vec![0_u8; length];
        self.file
            .read_exact(&mut record)
            .map_err(|error| io_error(&self.path, error))?;
        let ordinal = self.expected_records - self.remaining;
        if purge_plan_frame_tag(
            &self.frame_key,
            self.transaction,
            ordinal,
            length_bytes,
            &record,
        ) != frame_tag
        {
            return Err(TreeSidecarError::InvalidScratch(
                "purge plan frame authentication failed",
            ));
        }
        let path = record_path(&record)?;
        if let Some(previous) = self.previous_path.as_deref()
            && compare_scratch_keys(ScratchOrder::PurgePostorder, previous, path)
                != std::cmp::Ordering::Less
        {
            return Err(TreeSidecarError::InvalidScratch(
                "purge plan is not in strict postorder",
            ));
        }
        self.previous_path = Some(path.to_vec());
        self.digest.update(length_bytes);
        self.digest.update(frame_tag);
        self.digest.update(&record);
        self.payload_bytes = self
            .payload_bytes
            .checked_add(4 + 32 + length as u64)
            .ok_or(TreeSidecarError::InvalidScratch(
                "purge plan payload length overflow",
            ))?;
        self.remaining -= 1;
        Ok(Some(record))
    }

    /// Fully authenticates count, order, every keyed frame, aggregate digest,
    /// and EOF before PurgeIntent. The anonymous FD is then rewound; keyed
    /// frames are checked again immediately before each destructive use.
    pub(crate) fn authenticate(&mut self) -> Result<(), TreeSidecarError> {
        while self.next()?.is_some() {}
        self.rewind()
    }

    fn rewind(&mut self) -> Result<(), TreeSidecarError> {
        if !self.checked_eof {
            return Err(TreeSidecarError::InvalidScratch(
                "purge plan rewind precedes authentication",
            ));
        }
        self.file
            .seek(SeekFrom::Start(PURGE_PLAN_HEADER_LEN as u64))
            .map_err(|error| io_error(&self.path, error))?;
        self.remaining = self.expected_records;
        self.payload_bytes = 0;
        self.digest = purge_plan_digest(self.transaction);
        self.previous_path = None;
        self.checked_eof = false;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(), TreeSidecarError> {
        while self.next()?.is_some() {}
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn corrupt_frame_for_test(&mut self, target: u64) {
        self.file
            .seek(SeekFrom::Start(PURGE_PLAN_HEADER_LEN as u64))
            .unwrap();
        for ordinal in 0..self.expected_records {
            let mut length = [0_u8; 4];
            self.file.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as i64;
            if ordinal == target {
                self.file.seek(SeekFrom::Current(32)).unwrap();
                let offset = self.file.stream_position().unwrap();
                let mut byte = [0_u8; 1];
                self.file.read_exact(&mut byte).unwrap();
                byte[0] ^= 0x80;
                self.file.seek(SeekFrom::Start(offset)).unwrap();
                self.file.write_all(&byte).unwrap();
                self.file.flush().unwrap();
                self.file
                    .seek(SeekFrom::Start(PURGE_PLAN_HEADER_LEN as u64))
                    .unwrap();
                return;
            }
            self.file.seek(SeekFrom::Current(32 + length)).unwrap();
        }
        panic!("purge plan test frame {target} is absent");
    }
}

struct PurgePlanWriter {
    transaction: TransactionId,
    path: PathBuf,
    file: File,
    frame_key: [u8; 32],
    digest: Sha256,
    payload_bytes: u64,
    records: u64,
}

impl PurgePlanWriter {
    #[allow(clippy::disallowed_methods)] // unlinks only the just-created private ephemeral plan name
    fn create(
        store: &TreeSidecarStore,
        transaction: TransactionId,
    ) -> Result<Self, TreeSidecarError> {
        // Reuse the canonical unpublished scratch namespace so a crash in the
        // narrow create-before-unlink window is collected by ordinary replay.
        let name = scratch_name(transaction);
        let path = store.path.join(&name);
        let fd = rustix::fs::openat(&store.directory, &name, OPEN_NEW, FILE_MODE)
            .map_err(|error| io_error(&path, error.into()))?;
        rustix::fs::fchmod(&fd, FILE_MODE).map_err(|error| io_error(&path, error.into()))?;
        validate_file(
            &store.directory,
            &name,
            &fd,
            store.backend,
            store.device,
            &path,
        )?;
        let mut file = File::from(fd);
        file.write_all(&[0_u8; PURGE_PLAN_HEADER_LEN])
            .map_err(|error| io_error(&path, error))?;
        // Unlink before any plan data is written: only this descriptor survives.
        rustix::fs::unlinkat(&store.directory, &name, AtFlags::empty())
            .map_err(|error| io_error(&path, error.into()))?;
        require_anonymous_plan_fd(&file, &path)?;
        let mut frame_key = [0_u8; 32];
        getrandom::fill(&mut frame_key)
            .map_err(|error| io_error(&path, io::Error::other(error)))?;
        Ok(Self {
            transaction,
            path,
            file,
            frame_key,
            digest: purge_plan_digest(transaction),
            payload_bytes: 0,
            records: 0,
        })
    }

    fn push(&mut self, record: &[u8]) -> Result<(), TreeSidecarError> {
        let path = record_path(record)?;
        validate_scratch_key(ScratchOrder::PurgePostorder, path)?;
        if record.is_empty() || record.len() > PURGE_RECORD_MAX_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid purge plan record",
            ));
        }
        let len = u32::try_from(record.len())
            .map_err(|_| TreeSidecarError::InvalidScratch("purge plan record length overflow"))?;
        let length_bytes = len.to_be_bytes();
        let frame_tag = purge_plan_frame_tag(
            &self.frame_key,
            self.transaction,
            self.records,
            length_bytes,
            record,
        );
        self.file
            .write_all(&length_bytes)
            .and_then(|_| self.file.write_all(&frame_tag))
            .and_then(|_| self.file.write_all(record))
            .map_err(|error| io_error(&self.path, error))?;
        self.digest.update(length_bytes);
        self.digest.update(frame_tag);
        self.digest.update(record);
        self.payload_bytes = self
            .payload_bytes
            .checked_add(4 + 32 + record.len() as u64)
            .ok_or(TreeSidecarError::InvalidScratch(
                "purge plan payload length overflow",
            ))?;
        self.records = self
            .records
            .checked_add(1)
            .ok_or(TreeSidecarError::InvalidScratch(
                "purge plan record count overflow",
            ))?;
        Ok(())
    }

    fn finish(mut self, expected: u64) -> Result<TreePurgePlan, TreeSidecarError> {
        if self.records != expected || expected == 0 {
            return Err(TreeSidecarError::InvalidScratch(
                "purge plan record count changed",
            ));
        }
        self.digest.update(self.records.to_be_bytes());
        self.digest.update(self.payload_bytes.to_be_bytes());
        let digest: [u8; 32] = self.digest.finalize().into();
        let mut header = [0_u8; PURGE_PLAN_HEADER_LEN];
        header[0..4].copy_from_slice(PURGE_PLAN_MAGIC);
        header[4..6].copy_from_slice(&PURGE_PLAN_VERSION.to_be_bytes());
        header[6..8].copy_from_slice(&(PURGE_PLAN_HEADER_LEN as u16).to_be_bytes());
        header[8..24].copy_from_slice(&self.transaction.0);
        header[24..32].copy_from_slice(&self.records.to_be_bytes());
        header[32..40].copy_from_slice(&self.payload_bytes.to_be_bytes());
        header[40..72].copy_from_slice(&digest);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(&header))
            .and_then(|_| self.file.sync_all())
            .map_err(|error| io_error(&self.path, error))?;
        self.file
            .seek(SeekFrom::Start(PURGE_PLAN_HEADER_LEN as u64))
            .map_err(|error| io_error(&self.path, error))?;
        let mut check = [0_u8; PURGE_PLAN_HEADER_LEN];
        // Header is validated from the retained FD, not from a pathname.
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_exact(&mut check))
            .map_err(|error| io_error(&self.path, error))?;
        if &check[0..4] != PURGE_PLAN_MAGIC {
            return Err(TreeSidecarError::InvalidScratch(
                "purge plan header validation failed",
            ));
        }
        self.file
            .seek(SeekFrom::Start(PURGE_PLAN_HEADER_LEN as u64))
            .map_err(|error| io_error(&self.path, error))?;
        let reader_digest = purge_plan_digest(self.transaction);
        Ok(TreePurgePlan {
            file: self.file,
            path: self.path,
            transaction: self.transaction,
            frame_key: self.frame_key,
            expected_records: self.records,
            expected_payload_bytes: self.payload_bytes,
            expected_digest: digest,
            remaining: self.records,
            payload_bytes: 0,
            digest: reader_digest,
            previous_path: None,
            checked_eof: false,
        })
    }
}

struct ScratchRunReader {
    path: PathBuf,
    file: File,
    order: ScratchOrder,
    expected_digest: [u8; 32],
    expected_payload_bytes: u64,
    expected_records: u64,
    remaining: u64,
    payload_bytes: u64,
    digest: Sha256,
    current: Option<Vec<u8>>,
}

impl ScratchRunReader {
    fn open(
        store: &TreeSidecarStore,
        run: &ScratchRun,
        order: ScratchOrder,
    ) -> Result<Self, TreeSidecarError> {
        let path = store.path.join(&run.name);
        // The run is read through the descriptor taken when it was written, so
        // the name is never resolved a second time. `validate_file` re-binds
        // that descriptor to its name; because the pin keeps the inode alive,
        // its number cannot have been recycled, so a swapped or unlinked entry
        // fails here rather than being compared against a carried copy.
        validate_file(
            &store.directory,
            &run.name,
            &run.pin,
            store.backend,
            store.device,
            &path,
        )?;
        // Duplicating the pin keeps the reader owning its descriptor without
        // reopening the name. The duplicate shares the pin's file description,
        // and a run is read by one reader at a time, so seeking to the start
        // here is deterministic.
        let mut file = run
            .pin
            .try_clone()
            .map_err(|error| io_error(&path, error))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| io_error(&path, error))?;
        let mut header = [0_u8; SCRATCH_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|error| io_error(&path, error))?;
        let (transaction, records, payload_bytes, expected_digest) = decode_scratch_header(header)?;
        if transaction
            != scratch_transaction(&run.name).ok_or(TreeSidecarError::InvalidScratch(
                "scratch name is not canonical",
            ))?
            || records != run.record_count
            || expected_digest != run.digest
        {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch header does not match its run",
            ));
        }
        let expected_file_bytes = (SCRATCH_HEADER_LEN as u64)
            .checked_add(payload_bytes)
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch file length overflow",
            ))?;
        if file
            .metadata()
            .map_err(|error| io_error(&path, error))?
            .len()
            != expected_file_bytes
        {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch file length does not match its header",
            ));
        }
        let mut digest = Sha256::new();
        digest.update(SCRATCH_DOMAIN);
        digest.update(transaction.0);
        digest.update(run.name.as_bytes());
        let mut reader = Self {
            path,
            file,
            order,
            expected_digest,
            expected_payload_bytes: payload_bytes,
            expected_records: records,
            remaining: records,
            payload_bytes: 0,
            digest,
            current: None,
        };
        reader.read_next()?;
        Ok(reader)
    }

    fn advance(&mut self) -> Result<(), TreeSidecarError> {
        if self.current.is_none() {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch reader advanced past EOF",
            ));
        }
        self.read_next()
    }

    fn read_next(&mut self) -> Result<(), TreeSidecarError> {
        if self.remaining == 0 {
            self.current = None;
            return Ok(());
        }
        let mut length_bytes = [0_u8; 4];
        self.file
            .read_exact(&mut length_bytes)
            .map_err(|error| io_error(&self.path, error))?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let max_record = if self.order == ScratchOrder::PurgePostorder {
            PURGE_RECORD_MAX_BYTES
        } else {
            MAX_SEGMENT_PAYLOAD
        };
        if length == 0 || length > max_record {
            return Err(TreeSidecarError::InvalidScratch(
                "invalid scratch record length",
            ));
        }
        let mut record = self.current.take().unwrap_or_default();
        record.resize(length, 0);
        self.file
            .read_exact(&mut record)
            .map_err(|error| io_error(&self.path, error))?;
        let key = record_path(&record)?;
        validate_scratch_key(self.order, key)?;
        self.digest.update(length_bytes);
        self.digest.update(&record);
        self.payload_bytes = self
            .payload_bytes
            .checked_add(4_u64 + length as u64)
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch payload length overflow",
            ))?;
        self.remaining -= 1;
        self.current = Some(record);
        Ok(())
    }

    fn finish(mut self) -> Result<(), TreeSidecarError> {
        if self.current.is_some() || self.remaining != 0 {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch reader did not reach EOF",
            ));
        }
        let mut extra = [0_u8; 1];
        if self
            .file
            .read(&mut extra)
            .map_err(|error| io_error(&self.path, error))?
            != 0
        {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch run contains trailing bytes",
            ));
        }
        self.digest.update(self.expected_records.to_be_bytes());
        self.digest
            .update(self.expected_payload_bytes.to_be_bytes());
        let actual: [u8; 32] = self.digest.finalize().into();
        if self.payload_bytes != self.expected_payload_bytes || actual != self.expected_digest {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch run integrity check failed",
            ));
        }
        Ok(())
    }
}

type SegmentEmitter<'a> = dyn FnMut(u64, &[u8]) -> Result<(), TreeSidecarError> + 'a;

struct SegmentBuilder<'a> {
    emit: &'a mut SegmentEmitter<'a>,
    decoder: &'a mut ManifestV3Decoder,
    payload: Vec<u8>,
    records: u64,
}

impl<'a> SegmentBuilder<'a> {
    fn new(emit: &'a mut SegmentEmitter<'a>, decoder: &'a mut ManifestV3Decoder) -> Self {
        Self {
            emit,
            decoder,
            payload: Vec::with_capacity(MAX_SEGMENT_PAYLOAD),
            records: 0,
        }
    }

    fn push(&mut self, record: &[u8]) -> Result<(), TreeSidecarError> {
        if record.len() > MAX_SEGMENT_PAYLOAD {
            return Err(TreeSidecarError::InvalidScratch(
                "one scratch record exceeds 1 MiB",
            ));
        }
        if self.records != 0 && self.payload.len() + record.len() > MAX_SEGMENT_PAYLOAD {
            self.flush()?;
        }
        self.payload.extend_from_slice(record);
        self.records = self
            .records
            .checked_add(1)
            .ok_or(TreeSidecarError::InvalidScratch(
                "scratch segment record count overflow",
            ))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), TreeSidecarError> {
        if self.records != 0 {
            match self
                .decoder
                .push_segment_with(self.records, &self.payload, |_| {
                    Ok::<(), std::convert::Infallible>(())
                }) {
                Ok(()) => {}
                Err(ManifestV3VisitError::Codec(_)) => {
                    return Err(TreeSidecarError::InvalidScratch(
                        "merged v3 manifest record validation failed",
                    ));
                }
                Err(ManifestV3VisitError::Visit(never)) => match never {},
            }
            (self.emit)(self.records, &self.payload)?;
            self.payload.clear();
            self.records = 0;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), TreeSidecarError> {
        self.flush()
    }
}

pub(super) fn record_path(record: &[u8]) -> Result<&[u8], TreeSidecarError> {
    let length = record
        .get(..8)
        .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
        .ok_or(TreeSidecarError::InvalidScratch(
            "scratch record is truncated before its path",
        ))?;
    let length = usize::try_from(length).map_err(|_| {
        TreeSidecarError::InvalidScratch("scratch record path length is not representable")
    })?;
    record
        .get(
            8..8_usize
                .checked_add(length)
                .ok_or(TreeSidecarError::InvalidScratch(
                    "scratch record path length overflow",
                ))?,
        )
        .ok_or(TreeSidecarError::InvalidScratch(
            "scratch record path is truncated",
        ))
}

fn encode_scratch_header(
    transaction: TransactionId,
    record_count: u64,
    payload_bytes: u64,
    digest: [u8; 32],
) -> [u8; SCRATCH_HEADER_LEN] {
    let mut header = [0_u8; SCRATCH_HEADER_LEN];
    header[0..4].copy_from_slice(SCRATCH_MAGIC);
    header[4..6].copy_from_slice(&SCRATCH_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&(SCRATCH_HEADER_LEN as u16).to_be_bytes());
    header[8..24].copy_from_slice(&transaction.0);
    header[24..32].copy_from_slice(&record_count.to_be_bytes());
    header[32..40].copy_from_slice(&payload_bytes.to_be_bytes());
    header[40..72].copy_from_slice(&digest);
    header
}

fn decode_scratch_header(
    header: [u8; SCRATCH_HEADER_LEN],
) -> Result<(TransactionId, u64, u64, [u8; 32]), TreeSidecarError> {
    if &header[0..4] != SCRATCH_MAGIC
        || u16::from_be_bytes(header[4..6].try_into().unwrap()) != SCRATCH_VERSION
        || usize::from(u16::from_be_bytes(header[6..8].try_into().unwrap())) != SCRATCH_HEADER_LEN
    {
        return Err(TreeSidecarError::InvalidScratch(
            "invalid scratch run header",
        ));
    }
    let record_count = u64::from_be_bytes(header[24..32].try_into().unwrap());
    if record_count == 0 {
        return Err(TreeSidecarError::InvalidScratch(
            "scratch run has no records",
        ));
    }
    let digest = header[40..72].try_into().unwrap();
    Ok((
        TransactionId(header[8..24].try_into().unwrap()),
        record_count,
        u64::from_be_bytes(header[32..40].try_into().unwrap()),
        digest,
    ))
}

pub(super) fn valid_scratch_name(name: &[u8]) -> bool {
    scratch_transaction(OsStr::from_bytes(name)).is_some()
}

fn scratch_transaction(name: &OsStr) -> Option<TransactionId> {
    let body = name
        .as_bytes()
        .strip_prefix(SCRATCH_PREFIX)?
        .strip_suffix(SCRATCH_SUFFIX)?;
    let mut parts = body.split(|byte| *byte == b'-');
    let transaction = parts.next()?;
    let pid = parts.next()?;
    let sequence = parts.next()?;
    if parts.next().is_some()
        || transaction.len() != 32
        || !transaction
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let pid_text = std::str::from_utf8(pid).ok()?;
    let sequence_text = std::str::from_utf8(sequence).ok()?;
    let pid_value = pid_text.parse::<u32>().ok()?;
    let sequence_value = sequence_text.parse::<u64>().ok()?;
    if pid != pid_value.to_string().as_bytes() || sequence != sequence_value.to_string().as_bytes()
    {
        return None;
    }
    let mut decoded = [0_u8; 16];
    let (pairs, _) = transaction.as_chunks::<2>();
    for (output, pair) in decoded.iter_mut().zip(pairs) {
        *output = decode_hex(pair[0])?.checked_mul(16)? + decode_hex(pair[1])?;
    }
    Some(TransactionId(decoded))
}

fn scratch_name(transaction: TransactionId) -> OsString {
    let sequence = NEXT_SCRATCH_NAME.fetch_add(1, Ordering::Relaxed);
    OsString::from(format!(
        ".tree-scratch-v1-{}-{}-{sequence}.tmp",
        transaction_hex(transaction),
        std::process::id()
    ))
}
