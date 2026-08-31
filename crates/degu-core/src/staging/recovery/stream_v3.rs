use super::*;
use crate::backend::held::{
    HardlinkTopologyFold, HeldTreeV3CollectError, ManifestV3CodecError, ManifestV3Record,
    ManifestV3RecordKind, PendingV3Inventory, StreamedV3Inventory, StructureEvidence,
    decode_hardlink_scratch_record, hardlink_scratch_sentinel_record,
    structure_evidence_from_v3_record,
};
use crate::seal::sidecar::{
    TreeManifestFoldError, TreeManifestScratchBuildError, TreeSidecarCommitment, TreeSidecarError,
    TreeSidecarFoldError, TreeSidecarStore, TreeStructureScratchCursor,
};
use std::convert::Infallible;
use std::os::unix::ffi::OsStrExt;

#[cfg(test)]
std::thread_local! {
    static AFTER_MANIFEST_SCRATCH_BUILD: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn install_after_manifest_scratch_build_test_hook(callback: impl FnOnce() + 'static) {
    AFTER_MANIFEST_SCRATCH_BUILD.with(|slot| {
        assert!(
            slot.borrow_mut().replace(Box::new(callback)).is_none(),
            "recovery v3 manifest-scratch hook already installed"
        );
    });
}

#[cfg(test)]
fn fire_after_manifest_scratch_build_test_hook() {
    AFTER_MANIFEST_SCRATCH_BUILD.with(|slot| {
        if let Some(callback) = slot.borrow_mut().take() {
            callback();
        }
    });
}

#[cfg(not(test))]
fn fire_after_manifest_scratch_build_test_hook() {}

#[derive(Debug)]
enum RecoveryV3EmitError {
    Sidecar(TreeSidecarError),
    Verification,
}

fn sidecar_error(error: TreeSidecarError) -> RecoveryRebindError {
    RecoveryRebindError::Sidecar(error)
}

fn manifest_changed() -> RecoveryRebindError {
    RecoveryRebindError::UndoManifestChanged
}

fn destination_root(metadata: &StagingTransactionMetadata) -> PathBuf {
    metadata
        .destination_parent()
        .relative_path()
        .join(metadata.destination_basename())
}

/// Returns (freshly required current mode, sealed manifest mode) for exactly one
/// durable tree-seal plan. A scan avoids creating another tree-sized index; WAL
/// admission already bounds the descriptor-free plan vector.
fn directory_modes(
    plans: &[RecoveryPermissionPlan],
    destination_root: &Path,
    path: &Path,
    modes_restored: bool,
) -> Result<(u32, u32), RecoveryRebindError> {
    let mut matched = None;
    for plan in plans {
        let suffix = plan
            .relative_path
            .strip_prefix(destination_root)
            .map_err(|_| RecoveryRebindError::InvalidLocator)?;
        if suffix != path {
            continue;
        }
        if matched.is_some() {
            return Err(RecoveryRebindError::UndoManifestChanged);
        }
        let sealed = plan.permission.expected_mode;
        let current = if modes_restored {
            plan.permission.pre_mode
        } else {
            sealed
        };
        matched = Some((current, sealed));
    }
    matched.ok_or(RecoveryRebindError::UndoManifestChanged)
}

/// Rewrites only the directory mode field of one internally generated canonical
/// v3 record. All other bytes remain byte-identical. The current on-disk mode is
/// checked before normalization, so recovery cannot hide unexpected mode drift.
fn normalize_collected_record(
    record: &[u8],
    plans: &[RecoveryPermissionPlan],
    destination_root: &Path,
    modes_restored: bool,
    normalized: &mut Vec<u8>,
    observed_directories: &mut u64,
) -> Result<(), RecoveryRebindError> {
    // These offsets track `emit_manifest_entry_v3_with_mode`, the canonical v3
    // manifest layout that `PendingV3Inventory::collect` emits through
    // `emit_forward_v3_record`. It carries no record magic; the structure
    // scratch encoder is a different layout and is not what arrives here.
    let path_len_bytes: [u8; 8] = record
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    let path_len = usize::try_from(u64::from_be_bytes(path_len_bytes))
        .map_err(|_| RecoveryRebindError::UndoManifestChanged)?;
    let kind_offset = 8_usize
        .checked_add(path_len)
        .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    // kind(1) + device(8) + inode(8) + incarnation(8) + uid(4) + gid(4)
    let mode_offset = kind_offset
        .checked_add(1 + 24 + 4 + 4)
        .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    let mode_end = mode_offset
        .checked_add(4)
        .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    let kind = *record
        .get(kind_offset)
        .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    let actual_mode = u32::from_be_bytes(
        record
            .get(mode_offset..mode_end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(RecoveryRebindError::UndoManifestChanged)?,
    );
    normalized.clear();
    normalized.extend_from_slice(record);
    if kind == 0 {
        let path = Path::new(OsStr::from_bytes(
            record
                .get(8..kind_offset)
                .ok_or(RecoveryRebindError::UndoManifestChanged)?,
        ));
        let (current_mode, sealed_mode) =
            directory_modes(plans, destination_root, path, modes_restored)?;
        if actual_mode != current_mode {
            return Err(RecoveryRebindError::UndoManifestChanged);
        }
        normalized[mode_offset..mode_end].copy_from_slice(&sealed_mode.to_be_bytes());
        *observed_directories = observed_directories
            .checked_add(1)
            .ok_or(RecoveryRebindError::UndoManifestChanged)?;
    }
    Ok(())
}

fn authenticate_manifest(
    sidecars: &TreeSidecarStore,
    commitment: TreeSidecarCommitment,
    manifest: DurableTreeManifest,
) -> Result<(), RecoveryRebindError> {
    sidecars
        .read_manifest_v3_fold(commitment, manifest, (), |(), _| Ok::<(), Infallible>(()))
        .map(|_| ())
        .map_err(|error| match error {
            TreeManifestFoldError::Sidecar(error) => sidecar_error(error),
            TreeManifestFoldError::Codec(_) | TreeManifestFoldError::FingerprintMismatch => {
                RecoveryRebindError::SidecarManifestChanged
            }
            TreeManifestFoldError::Fold(never) => match never {},
        })
}

fn authenticate_then_cleanup(
    wal: &mut SealWal<RecoverySession>,
    sidecars: &TreeSidecarStore,
    commitment: TreeSidecarCommitment,
    manifest: DurableTreeManifest,
    primary: RecoveryRebindError,
) -> RecoveryRebindError {
    let authenticated = authenticate_manifest(sidecars, commitment, manifest);
    let cleanup = sidecars.cleanup_unpublished(wal).map_err(sidecar_error);
    authenticated
        .err()
        .or_else(|| cleanup.err())
        .unwrap_or(primary)
}

pub(super) struct ReboundV3Verification<'a> {
    pub(super) transaction: TransactionId,
    pub(super) commitment: TreeSidecarCommitment,
    pub(super) expected_manifest: DurableTreeManifest,
    pub(super) root: &'a ReboundObject,
    pub(super) metadata: &'a StagingTransactionMetadata,
    pub(super) plans: &'a [RecoveryPermissionPlan],
    pub(super) modes_restored: bool,
    pub(super) limits: HeldTreeLimits,
}

pub(super) fn verify_rebound_v3(
    wal: &mut SealWal<RecoverySession>,
    sidecars: &TreeSidecarStore,
    request: ReboundV3Verification<'_>,
) -> Result<StreamedV3Inventory, RecoveryRebindError> {
    let ReboundV3Verification {
        transaction,
        commitment,
        expected_manifest,
        root,
        metadata,
        plans,
        modes_restored,
        limits,
    } = request;
    if expected_manifest.schema_version != 3 {
        let cleanup = sidecars.cleanup_unpublished(wal).map_err(sidecar_error);
        return Err(cleanup.err().unwrap_or_else(manifest_changed));
    }
    // A corrupt published baseline wins over traversal or scratch producer
    // failures. Every early exit below reauthenticates it before returning.
    if let Err(error) = sidecars.verify(commitment) {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(sidecar_error(error));
    }
    if plans.is_empty() {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            manifest_changed(),
        ));
    }
    if let Err(error) = root.verify_fresh_binding() {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            error,
        ));
    }
    let ReboundBinding::Named {
        parent, basename, ..
    } = &root.binding
    else {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            RecoveryRebindError::InvalidLocator,
        ));
    };
    let destination_root = destination_root(metadata);
    let produced =
        sidecars.build_sorted_manifest_scratch_with_output(wal, transaction, |emit_record| {
            let parent = rustix::io::dup(parent)
                .map_err(io::Error::from)
                .map_err(|_| HeldTreeV3CollectError::Emit(RecoveryV3EmitError::Verification))?;
            let held_parent = certify_held_fd(parent)
                .map_err(|_| HeldTreeV3CollectError::Emit(RecoveryV3EmitError::Verification))?;
            let mut normalized = Vec::new();
            let mut observed_directories = 0_u64;
            let pending = PendingV3Inventory::collect(
                held_parent,
                basename,
                crate::backend::held_tree_protected_names(),
                limits,
                |record| {
                    normalize_collected_record(
                        record,
                        plans,
                        &destination_root,
                        modes_restored,
                        &mut normalized,
                        &mut observed_directories,
                    )
                    .map_err(|_| RecoveryV3EmitError::Verification)?;
                    emit_record(&normalized).map_err(RecoveryV3EmitError::Sidecar)
                },
            )?;
            Ok((pending, observed_directories))
        });
    let (mut scratch, (pending, observed_directories)) = match produced {
        Ok(value) => value,
        Err(TreeManifestScratchBuildError::Sidecar(error)) => {
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                expected_manifest,
                sidecar_error(error),
            ));
        }
        Err(TreeManifestScratchBuildError::Produce(error)) => {
            let primary = match error {
                HeldTreeV3CollectError::Emit(RecoveryV3EmitError::Sidecar(error)) => {
                    sidecar_error(error)
                }
                HeldTreeV3CollectError::Tree(_)
                | HeldTreeV3CollectError::Codec(_)
                | HeldTreeV3CollectError::Emit(RecoveryV3EmitError::Verification) => {
                    manifest_changed()
                }
            };
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                expected_manifest,
                primary,
            ));
        }
    };
    fire_after_manifest_scratch_build_test_hook();
    if u64::try_from(plans.len()).ok() != Some(observed_directories) {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            manifest_changed(),
        ));
    }
    let actual = match sidecars.fingerprint_sorted_manifest_scratch(wal, transaction, &mut scratch)
    {
        Ok(actual) => actual,
        Err(error) => {
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                expected_manifest,
                sidecar_error(error),
            ));
        }
    };
    if actual != expected_manifest {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            manifest_changed(),
        ));
    }
    let finalizer = match pending.into_finalizer(expected_manifest) {
        Ok(finalizer) => finalizer,
        Err(_) => {
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                expected_manifest,
                manifest_changed(),
            ));
        }
    };
    // The manifest scratch is private and unpublished; it is no longer needed
    // once its authenticated fingerprint has matched the durable baseline.
    if let Err(error) = sidecars.cleanup_unpublished(wal) {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            sidecar_error(error),
        ));
    }

    let hardlink_build =
        sidecars.build_sorted_hardlink_scratch_with_output(wal, transaction, |emit_hardlink| {
            emit_hardlink(hardlink_scratch_sentinel_record()).map_err(|error| {
                TreeManifestFoldError::Fold(HeldTreeV3CollectError::Emit(error))
            })?;
            sidecars.read_manifest_v3_fold(
                commitment,
                expected_manifest,
                finalizer,
                |finalizer, record| {
                    let observed_mode = if record.kind == ManifestV3RecordKind::Directory {
                        let path = Path::new(OsStr::from_bytes(record.path));
                        Some(
                            directory_modes(plans, &destination_root, path, modes_restored)
                                .map_err(|_| {
                                    HeldTreeV3CollectError::Tree(HeldTreeError::PostChanged(
                                        path.to_path_buf(),
                                    ))
                                })?
                                .0,
                        )
                    } else {
                        None
                    };
                    finalizer.observe_with_directory_mode(record, observed_mode, emit_hardlink)
                },
            )
        });
    let (hardlink_scratch, (finalizer, authenticated)) = match hardlink_build {
        Ok(value) => value,
        Err(error) => {
            let primary = match error {
                TreeManifestScratchBuildError::Sidecar(error)
                | TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Sidecar(error)) => {
                    sidecar_error(error)
                }
                TreeManifestScratchBuildError::Produce(
                    TreeManifestFoldError::Codec(_) | TreeManifestFoldError::FingerprintMismatch,
                ) => RecoveryRebindError::SidecarManifestChanged,
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Fold(
                    HeldTreeV3CollectError::Tree(_) | HeldTreeV3CollectError::Codec(_),
                )) => manifest_changed(),
                TreeManifestScratchBuildError::Produce(TreeManifestFoldError::Fold(
                    HeldTreeV3CollectError::Emit(error),
                )) => sidecar_error(error),
            };
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                expected_manifest,
                primary,
            ));
        }
    };
    let hardlink_fold = sidecars.fold_sorted_hardlink_scratch(
        wal,
        transaction,
        hardlink_scratch,
        HardlinkTopologyFold::new(),
        |groups, record| {
            let record = decode_hardlink_scratch_record(record)
                .map_err(HeldTreeV3CollectError::<Infallible>::Codec)?
                .ok_or(HeldTreeV3CollectError::Codec(
                    ManifestV3CodecError::InvalidTag,
                ))?;
            groups.observe(record).map_err(HeldTreeV3CollectError::Tree)
        },
    );
    let hardlink_fold = match hardlink_fold {
        Ok(fold) => fold,
        Err(TreeSidecarFoldError::Sidecar(error)) => {
            authenticate_manifest(sidecars, commitment, expected_manifest)?;
            return Err(sidecar_error(error));
        }
        Err(TreeSidecarFoldError::Fold(_)) => {
            authenticate_manifest(sidecars, commitment, expected_manifest)?;
            return Err(manifest_changed());
        }
    };
    let hardlinks = match hardlink_fold.finish() {
        Ok(hardlinks) => hardlinks,
        Err(_) => {
            authenticate_manifest(sidecars, commitment, expected_manifest)?;
            return Err(manifest_changed());
        }
    };
    let tree = match finalizer.finish(authenticated, hardlinks) {
        Ok(tree) => tree,
        Err(_) => {
            authenticate_manifest(sidecars, commitment, expected_manifest)?;
            return Err(manifest_changed());
        }
    };
    if let Err(error) = rewalk_structure(
        wal,
        sidecars,
        transaction,
        commitment,
        expected_manifest,
        &tree,
        plans,
        &destination_root,
        modes_restored,
    ) {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            error,
        ));
    }
    if let Err(error) = root.verify_fresh_binding() {
        return Err(authenticate_then_cleanup(
            wal,
            sidecars,
            commitment,
            expected_manifest,
            error,
        ));
    }
    authenticate_manifest(sidecars, commitment, expected_manifest)?;
    Ok(tree)
}

struct StructureComparison {
    actual: Option<StructureEvidence>,
    scratch_error: Option<TreeSidecarError>,
    first_tree_error: Option<HeldTreeError>,
}

impl StructureComparison {
    fn record_tree_error(&mut self, error: HeldTreeError) {
        if self.first_tree_error.is_none() {
            self.first_tree_error = Some(error);
        }
    }

    fn observe(
        &mut self,
        cursor: &mut TreeStructureScratchCursor,
        expected: ManifestV3Record<'_>,
        plans: &[RecoveryPermissionPlan],
        destination_root: &Path,
        modes_restored: bool,
    ) {
        let mut expected = structure_evidence_from_v3_record(expected);
        loop {
            if self.actual.is_none() && self.scratch_error.is_none() {
                match cursor.next() {
                    Ok(actual) => self.actual = actual,
                    Err(error) => self.scratch_error = Some(error),
                }
            }
            if self.scratch_error.is_some() {
                return;
            }
            let Some(actual) = self.actual.as_mut() else {
                self.record_tree_error(HeldTreeError::PostRemoved(expected.path().to_path_buf()));
                return;
            };
            match expected.path().cmp(actual.path()) {
                std::cmp::Ordering::Less => {
                    self.record_tree_error(HeldTreeError::PostRemoved(
                        expected.path().to_path_buf(),
                    ));
                    return;
                }
                std::cmp::Ordering::Greater => {
                    let path = actual.path().to_path_buf();
                    self.actual = None;
                    self.record_tree_error(HeldTreeError::PostAdded(path));
                }
                std::cmp::Ordering::Equal => {
                    let mut changed = false;
                    // Both sides must be directories: normalizing only on the
                    // expected kind would run the directory-only rewrite on a
                    // same-path kind swap. A kind mismatch stays a deterministic
                    // `PostChanged` through the inequality check below.
                    if expected.is_directory() && actual.is_directory() {
                        match directory_modes(
                            plans,
                            destination_root,
                            expected.path(),
                            modes_restored,
                        ) {
                            Ok((current, sealed)) if actual.mode() == current => {
                                actual.normalize_directory_mode(sealed);
                                expected.normalize_directory_mode(sealed);
                            }
                            _ => changed = true,
                        }
                    }
                    changed |= expected != *actual;
                    let path = expected.path().to_path_buf();
                    self.actual = None;
                    if changed {
                        self.record_tree_error(HeldTreeError::PostChanged(path));
                    }
                    return;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn rewalk_structure(
    wal: &mut SealWal<RecoverySession>,
    sidecars: &TreeSidecarStore,
    transaction: TransactionId,
    commitment: TreeSidecarCommitment,
    manifest: DurableTreeManifest,
    tree: &StreamedV3Inventory,
    plans: &[RecoveryPermissionPlan],
    destination_root: &Path,
    modes_restored: bool,
) -> Result<(), RecoveryRebindError> {
    if let Err(error) = sidecars.verify(commitment) {
        let _ = sidecars.cleanup_unpublished(wal);
        return Err(sidecar_error(error));
    }
    let produced =
        sidecars.build_sorted_structure_scratch_with_output(wal, transaction, |emit_record| {
            tree.stream_structure_records(emit_record)
        });
    let (scratch, ()) = match produced {
        Ok(value) => value,
        Err(error) => {
            let primary = match error {
                TreeManifestScratchBuildError::Sidecar(error) => sidecar_error(error),
                TreeManifestScratchBuildError::Produce(_) => manifest_changed(),
            };
            return Err(authenticate_then_cleanup(
                wal, sidecars, commitment, manifest, primary,
            ));
        }
    };
    let mut cursor = match sidecars.open_sorted_structure_scratch_cursor(wal, transaction, scratch)
    {
        Ok(cursor) => cursor,
        Err(error) => {
            return Err(authenticate_then_cleanup(
                wal,
                sidecars,
                commitment,
                manifest,
                sidecar_error(error),
            ));
        }
    };
    let mut comparison = StructureComparison {
        actual: None,
        scratch_error: None,
        first_tree_error: None,
    };
    let sidecar_result =
        sidecars.read_manifest_v3_fold(commitment, manifest, (), |(), expected| {
            comparison.observe(
                &mut cursor,
                expected,
                plans,
                destination_root,
                modes_restored,
            );
            Ok::<(), Infallible>(())
        });
    if let Err(error) = sidecar_result {
        let primary = match error {
            TreeManifestFoldError::Sidecar(error) => sidecar_error(error),
            TreeManifestFoldError::Codec(_) | TreeManifestFoldError::FingerprintMismatch => {
                RecoveryRebindError::SidecarManifestChanged
            }
            TreeManifestFoldError::Fold(never) => match never {},
        };
        let cleanup = sidecars
            .finish_sorted_structure_scratch_cursor(wal, cursor)
            .map_err(sidecar_error);
        let authenticated = authenticate_manifest(sidecars, commitment, manifest);
        return Err(authenticated
            .err()
            .or_else(|| cleanup.err())
            .unwrap_or(primary));
    }
    while comparison.actual.is_some()
        || (comparison.scratch_error.is_none()
            && cursor
                .next()
                .map(|actual| {
                    comparison.actual = actual;
                    comparison.actual.is_some()
                })
                .unwrap_or_else(|error| {
                    comparison.scratch_error = Some(error);
                    false
                }))
    {
        if let Some(actual) = comparison.actual.take() {
            comparison.record_tree_error(HeldTreeError::PostAdded(actual.path().to_path_buf()));
        }
    }
    if let Err(error) = sidecars.finish_sorted_structure_scratch_cursor(wal, cursor) {
        authenticate_manifest(sidecars, commitment, manifest)?;
        return Err(sidecar_error(error));
    }
    if let Some(error) = comparison.scratch_error {
        authenticate_manifest(sidecars, commitment, manifest)?;
        return Err(sidecar_error(error));
    }
    if comparison.first_tree_error.is_some() {
        authenticate_manifest(sidecars, commitment, manifest)?;
        return Err(manifest_changed());
    }
    if tree.finish_streamed_structure_rewalk().is_err() {
        authenticate_manifest(sidecars, commitment, manifest)?;
        return Err(manifest_changed());
    }
    Ok(())
}
