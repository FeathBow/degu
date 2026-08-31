//! Unpublished, authority-neutral external sorting for v3 manifest records.
//!
//! Scratch runs live only in the already-private sidecar store. Their names are
//! internally generated, they can never be referenced by the WAL, and startup
//! removes them only after replay has resumed the exact mutable WAL lease.
//! The lease serializes cooperative publishers; retained inode, length, name-
//! bound digest, and private-file checks make same-UID replacement fail closed.

use super::*;
#[cfg(test)]
use crate::backend::held::ManifestV3Record;
use crate::backend::held::{
    ManifestV3Decoder, ManifestV3VisitError, StructureEvidence, compare_manifest_paths,
    decode_structure_record,
};
use crate::seal::wal::DurableTreeManifest;

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
const MERGE_PAYLOAD_MEMORY_BYTES: usize = (MERGE_FAN_IN + 2) * MAX_SEGMENT_PAYLOAD;
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
}

fn validate_scratch_key(order: ScratchOrder, key: &[u8]) -> Result<(), TreeSidecarError> {
    match order {
        ScratchOrder::ManifestPath => Ok(()),
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
        mut accumulator: A,
        mut fold: F,
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
        let cleanup = self.cleanup_unpublished(wal).map(|_| ());
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

    /// Authenticates and globally decodes every sorted scratch record, folding
    /// borrowed typed records into owned authority-neutral data. The accumulator
    /// is returned only after all run identities/digests, global v3 ordering,
    /// aggregate fingerprint, root/parent constraints, and EOF checks pass.
    /// A fold error consumes partial decoder state; callers must discard any
    /// observations made before the error and may not treat them as evidence.
    #[cfg(test)]
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
        F: FnMut(A, ManifestV3Record<'_>) -> Result<A, E>,
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
                accumulator = Some(fold(current, typed)?);
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
            (MERGE_FAN_IN + 2) * MAX_SEGMENT_PAYLOAD
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
        if record.len() > MAX_SEGMENT_PAYLOAD {
            return Err(TreeSidecarError::InvalidScratch(
                "one scratch record exceeds 1 MiB",
            ));
        }
        let record_bytes = u64::try_from(record.len()).map_err(|_| {
            TreeSidecarError::InvalidScratch("scratch record length is not representable")
        })?;
        self.payload_bytes = self.payload_bytes.checked_add(record_bytes).ok_or(
            TreeSidecarError::InvalidScratch("scratch aggregate payload length overflow"),
        )?;
        if self.payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(TreeSidecarError::InvalidScratch(
                "scratch aggregate payload exceeds the sidecar limit",
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
        if length == 0 || length > MAX_SEGMENT_PAYLOAD {
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
