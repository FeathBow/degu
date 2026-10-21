//! What a settled transaction may still write to the WAL.
//!
//! An entry in the trash holds its frames, and it also holds a claim on room it
//! has not used yet: an undo writes an inverse for every directory it sealed, a
//! purge writes its claim and its count. Admission has to leave that room alone,
//! so it has to know how much it is. The answer here is not a formula. It builds
//! the frames the rest of the transaction's life would write, from the records
//! the WAL already holds, and encodes them: a frame's size is whatever encoding
//! it says it is, and a formula kept beside the encoder is a second answer that
//! can drift from the first.
//!
//! Only the states admission can meet are measured. Every other state blocks a
//! new staging transaction until startup recovery has moved it on, so nothing
//! would read its allowance.

use super::*;

/// Mutation ids are fixed width, so the id a future frame will carry does not
/// change its size and any id measures it.
const ANY_MUTATION_ID: u64 = 0;

/// Why an allowance could not be measured.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AllowanceError {
    #[error("transaction is in {0:?}, which admission never meets")]
    Unsettled(TransactionState),
    #[error("transaction lacks the {0} its remaining frames are built from")]
    Missing(&'static str),
    #[error("tree seal {mutation_id} names a path outside the staged source root")]
    SealOutsideRoot { mutation_id: u64 },
    #[error("a remaining permission record could not be read back: {0}")]
    PermissionRecord(#[from] PermissionReadError),
    #[error("a remaining frame could not be encoded: {0}")]
    Frame(#[from] FrameError),
}

fn frame_len(record: &SealRecord) -> Result<u64, FrameError> {
    encode_frame(record).map(|frame| frame.len() as u64)
}

fn states_len(transaction: TransactionId, states: &[TransactionState]) -> Result<u64, FrameError> {
    states.iter().try_fold(0, |total, &state| {
        Ok(total + frame_len(&SealRecord::State { transaction, state })?)
    })
}

impl<W: DurableWrite> SealWal<W> {
    /// The most this transaction may still append, over every path its state
    /// leaves open.
    ///
    /// No room is added for a `RecoveryRequired` frame a path may end in. Each
    /// path ends in a state frame the same size, so a failure that writes one
    /// writes it in place of at least that frame. The exception is an entry
    /// with no path left but that one frame: a quarantine whose seals are all
    /// reversed, which a later open marks `RecoveryRequired` if its sidecar no
    /// longer verifies.
    pub(crate) fn remaining_allowance(
        &self,
        transaction: TransactionId,
    ) -> Result<u64, AllowanceError> {
        let Some(&state) = self.states.get(&transaction) else {
            return Ok(0);
        };
        // Measured once per state. Admission asks every settled entry twice for
        // each new staging, and measuring reads its records back; without
        // this, staging N entries in one session would read the earlier ones'
        // records on the order of N squared times.
        //
        // The state is all a measure depends on that can change. A settled
        // transaction gains no permission record while it stays settled: an
        // undo writes `UndoIntent` before its first inverse, a purge writes no
        // permission record, and a quarantine is settled only once nothing is
        // left to reverse. An unsettled one is an error, and is not kept.
        if let Some(&(measured, allowance)) = self.allowances.borrow().get(&transaction)
            && measured == state
        {
            return Ok(allowance);
        }
        let allowance = self.measure_allowance(transaction, state)?;
        self.allowances
            .borrow_mut()
            .insert(transaction, (state, allowance));
        Ok(allowance)
    }

    fn measure_allowance(
        &self,
        transaction: TransactionId,
        state: TransactionState,
    ) -> Result<u64, AllowanceError> {
        match state {
            TransactionState::VerifiedCommitted => Ok(self
                .undo_allowance(transaction)?
                .max(self.purge_allowance(transaction, true)?)),
            TransactionState::Purgeable => self.purge_allowance(transaction, false),
            TransactionState::Quarantined
                if self
                    .ledgers
                    .get(&transaction)
                    .is_none_or(|ledger| !ledger.retains_active_seals()) =>
            {
                Ok(states_len(
                    transaction,
                    &[TransactionState::RecoveryRequired],
                )?)
            }
            TransactionState::Purged
            | TransactionState::Restored
            | TransactionState::RolledBack
            | TransactionState::UndoConflict => Ok(0),
            other => Err(AllowanceError::Unsettled(other)),
        }
    }

    /// The frames a verified undo of a committed transaction writes: its state
    /// changes, an inverse and its resolution for every tree seal, and the
    /// rename back.
    ///
    /// Each inverse is built as the undo builds it. Its evidence names the
    /// directory where the undo finds it, under the destination root rather
    /// than the source root, so it is not the size of the seal it reverses.
    pub(crate) fn undo_allowance(&self, transaction: TransactionId) -> Result<u64, AllowanceError> {
        let metadata = self
            .staging
            .get(&transaction)
            .ok_or(AllowanceError::Missing("staging metadata"))?;
        let source_root = metadata
            .source_parent()
            .relative_path()
            .join(metadata.source_basename());
        let destination_root = metadata
            .destination_parent()
            .relative_path()
            .join(metadata.destination_basename());
        let mut total = states_len(
            transaction,
            &[
                TransactionState::UndoIntent,
                TransactionState::UndoModesRestored,
                TransactionState::UndoRenameIntent,
                TransactionState::Restored,
            ],
        )?;
        total += frame_len(&SealRecord::UndoRenameOutcome {
            transaction,
            outcome: DurableUndoRenameOutcome::AppliedAndParentsSynced(metadata.root_identity()),
        })?;
        let resolution = frame_len(&SealRecord::PermissionApplied {
            transaction,
            mutation_id: ANY_MUTATION_ID,
        })?;
        for seal in self.permission_records(transaction)? {
            if seal.phase != TransactionState::TreeSealIntent
                || seal.application != ApplicationStatus::Applied
                || seal.reverses_mutation_id.is_some()
            {
                continue;
            }
            let suffix = seal
                .evidence
                .relative_path()
                .strip_prefix(&source_root)
                .map_err(|_| AllowanceError::SealOutsideRoot {
                    mutation_id: seal.mutation_id,
                })?;
            let evidence = PersistentRecoveryEvidence::new_staging(
                destination_root.join(suffix),
                seal.evidence.filesystem_id().map(str::to_owned),
                seal.evidence.device(),
                seal.evidence.inode(),
                seal.evidence.generation_or_btime(),
                seal.pre_mode,
            )
            .ok_or(AllowanceError::SealOutsideRoot {
                mutation_id: seal.mutation_id,
            })?;
            total += frame_len(&SealRecord::PermissionIntent {
                transaction,
                mutation_id: ANY_MUTATION_ID,
                evidence,
                pre_mode: seal.expected_mode,
                expected_mode: seal.pre_mode,
                reverses_mutation_id: Some(seal.mutation_id),
            })? + resolution;
        }
        Ok(total)
    }

    /// The frames a verified purge writes: its authorization when it has none
    /// yet, its claim, its one count, and its two closing states.
    pub(crate) fn purge_allowance(
        &self,
        transaction: TransactionId,
        authorize: bool,
    ) -> Result<u64, AllowanceError> {
        let metadata = self
            .staging
            .get(&transaction)
            .ok_or(AllowanceError::Missing("staging metadata"))?;
        let manifest = *self
            .manifests
            .get(&transaction)
            .ok_or(AllowanceError::Missing("tree manifest"))?;
        let commitment = DurablePurgeCommitment::exact(metadata, manifest);
        let mut total = 0;
        if authorize {
            total += frame_len(&SealRecord::PurgeAuthorized {
                transaction,
                commitment: commitment.clone(),
            })?;
        }
        total += frame_len(&SealRecord::PurgeClaimed {
            transaction,
            commitment,
        })?;
        total += frame_len(&SealRecord::PurgeProgress {
            transaction,
            removed_entries: manifest.entry_count,
            last_path: PathBuf::new(),
        })?;
        total += states_len(
            transaction,
            &[TransactionState::PurgeOutcome, TransactionState::Purged],
        )?;
        Ok(total)
    }
}

/// A manifest with the shape a staged tree's will have. Every field but the
/// entry count is fixed width, so this sizes the frames that carry one.
fn sized_manifest(entry_count: u64) -> DurableTreeManifest {
    DurableTreeManifest {
        schema_version: CONTENT_PROOF_MANIFEST_VERSION,
        entry_count,
        sha256: [0; 32],
    }
}

/// One permission intent as staging writes it for the directory at `path`:
/// a seal when `reverses` is `None`, an inverse otherwise. Staging always
/// records a filesystem id and an incarnation, and the rest is fixed width.
fn staging_intent_len(
    transaction: TransactionId,
    path: PathBuf,
    filesystem_id: &str,
    reverses: Option<u64>,
) -> Result<u64, AllowanceError> {
    let evidence = PersistentRecoveryEvidence::new_staging(
        path,
        Some(filesystem_id.to_owned()),
        0,
        0,
        Some(0),
        0,
    )
    .ok_or(AllowanceError::Missing("a confined seal path"))?;
    Ok(frame_len(&SealRecord::PermissionIntent {
        transaction,
        mutation_id: ANY_MUTATION_ID,
        evidence,
        pre_mode: 0,
        expected_mode: 0,
        reverses_mutation_id: reverses,
    })?)
}

impl<W: DurableWrite> SealWal<W> {
    /// The room a new staging transaction can use: the limit, less what is
    /// committed, less every settled transaction's allowance. `admitting` is
    /// left out of the sum; it is the transaction being measured, and part
    /// way through its own staging it has no settled allowance to give.
    pub(crate) fn headroom(&self, admitting: Option<TransactionId>) -> Result<u64, AllowanceError> {
        let reserved = self
            .states
            .keys()
            .filter(|&&transaction| Some(transaction) != admitting)
            .try_fold(0_u64, |total, &transaction| {
                Ok::<_, AllowanceError>(
                    total.saturating_add(self.remaining_allowance(transaction)?),
                )
            })?;
        Ok(self
            .max_wal_len
            .saturating_sub(self.committed_len)
            .saturating_sub(reserved))
    }

    /// What a staging transaction writes from its first frame until its source
    /// parent is sealed, and what undoing that seal writes if the tree it finds
    /// there is refused.
    pub(crate) fn begin_projection(
        &self,
        transaction: TransactionId,
        metadata: &StagingTransactionMetadata,
    ) -> Result<BeginProjection, AllowanceError> {
        let parent = metadata.source_parent().relative_path().to_path_buf();
        let filesystem_id = metadata.filesystem_id();
        let resolution = frame_len(&SealRecord::PermissionApplied {
            transaction,
            mutation_id: ANY_MUTATION_ID,
        })?;
        Ok(BeginProjection {
            forward: frame_len(&SealRecord::StagingBegin {
                transaction,
                metadata: metadata.clone(),
            })? + states_len(
                transaction,
                &[
                    TransactionState::ParentSealIntent,
                    TransactionState::ParentSealed,
                ],
            )? + staging_intent_len(transaction, parent.clone(), filesystem_id, None)?
                + resolution,
            rolled_back: states_len(
                transaction,
                &[TransactionState::RestoreIntent, TransactionState::Restored],
            )? + staging_intent_len(
                transaction,
                parent,
                filesystem_id,
                Some(ANY_MUTATION_ID),
            )? + resolution,
        })
    }

    /// The most a staging transaction may still write once its source parent
    /// is sealed and its tree is planned. See [`TreeProjection`] for the ends
    /// it measures.
    pub(crate) fn tree_projection<'a>(
        &self,
        transaction: TransactionId,
        metadata: &StagingTransactionMetadata,
        directories: impl IntoIterator<Item = &'a Path>,
        entry_count: u64,
    ) -> Result<TreeProjection, AllowanceError> {
        let filesystem_id = metadata.filesystem_id();
        let source_root = metadata
            .source_parent()
            .relative_path()
            .join(metadata.source_basename());
        let destination_root = metadata
            .destination_parent()
            .relative_path()
            .join(metadata.destination_basename());
        let parent = metadata.source_parent().relative_path().to_path_buf();
        let resolution = frame_len(&SealRecord::PermissionApplied {
            transaction,
            mutation_id: ANY_MUTATION_ID,
        })?;
        let (mut seals, mut rollback, mut undo) = (0_u64, 0_u64, 0_u64);
        for relative in directories {
            let sealed = source_root.join(relative);
            seals +=
                staging_intent_len(transaction, sealed.clone(), filesystem_id, None)? + resolution;
            rollback +=
                staging_intent_len(transaction, sealed, filesystem_id, Some(ANY_MUTATION_ID))?
                    + resolution;
            undo += staging_intent_len(
                transaction,
                destination_root.join(relative),
                filesystem_id,
                Some(ANY_MUTATION_ID),
            )? + resolution;
        }
        let parent_inverse =
            staging_intent_len(transaction, parent, filesystem_id, Some(ANY_MUTATION_ID))?
                + resolution;
        let manifest = sized_manifest(entry_count);

        // Everything up to the rename's outcome is written whichever way the
        // transaction then goes.
        let to_rename = seals
            + frame_len(&SealRecord::TreeManifestSidecarComplete {
                transaction,
                manifest,
                commitment: TreeSidecarCommitment {
                    transaction,
                    segment_count: 0,
                    record_count: 0,
                    payload_bytes: 0,
                    file_bytes: 0,
                    root_sha256: [0; 32],
                },
            })?
            + frame_len(&SealRecord::RenameIntent { transaction })?
            + frame_len(&SealRecord::RenameOutcome {
                transaction,
                outcome: DurableRenameOutcome::AppliedAndParentsSynced(metadata.root_identity()),
            })?
            + states_len(
                transaction,
                &[
                    TransactionState::TreeSealIntent,
                    TransactionState::TreeSealed,
                ],
            )?;
        let forward = to_rename
            + parent_inverse
            + states_len(
                transaction,
                &[
                    TransactionState::StagedUnverified,
                    TransactionState::StagedSealed,
                    TransactionState::SourceParentRestoreIntent,
                    TransactionState::SourceParentRestored,
                    TransactionState::VerifiedCommitted,
                ],
            )?;
        let committed_undo =
            undo + states_len(
                transaction,
                &[
                    TransactionState::UndoIntent,
                    TransactionState::UndoModesRestored,
                    TransactionState::UndoRenameIntent,
                    TransactionState::Restored,
                ],
            )? + frame_len(&SealRecord::UndoRenameOutcome {
                transaction,
                outcome: DurableUndoRenameOutcome::AppliedAndParentsSynced(
                    metadata.root_identity(),
                ),
            })?;
        let commitment = DurablePurgeCommitment::exact(metadata, manifest);
        let committed_purge = frame_len(&SealRecord::PurgeAuthorized {
            transaction,
            commitment: commitment.clone(),
        })? + frame_len(&SealRecord::PurgeClaimed {
            transaction,
            commitment,
        })? + frame_len(&SealRecord::PurgeProgress {
            transaction,
            removed_entries: entry_count,
            last_path: PathBuf::new(),
        })? + states_len(
            transaction,
            &[TransactionState::PurgeOutcome, TransactionState::Purged],
        )?;
        Ok(TreeProjection {
            forward,
            committed: committed_undo.max(committed_purge),
            rolled_back: to_rename
                + rollback
                + parent_inverse
                + states_len(
                    transaction,
                    &[TransactionState::RestoreIntent, TransactionState::Restored],
                )?,
        })
    }
}

impl<W: DurableWrite> SealWal<W> {
    /// The room a transaction needs to retry reversing its seals, beside the
    /// room it has, while one of its seals still in force has had an inverse
    /// refused; `None` otherwise.
    ///
    /// A refusal a later attempt already put right is not a retry still owed.
    /// A source parent whose restore was refused once and then applied commits
    /// like any other entry, and its first undo runs in the room admission set
    /// aside for it; asking that undo for room to retry would fail it closed
    /// for want of a frame it is not going to write.
    ///
    /// Admission set room aside for one attempt at each inverse. A refused one
    /// is tried again at the next open, and every attempt writes a frame pair
    /// no allowance covered, so retries have to be paid for out of what is
    /// left. What a retry needs is everything this transaction may still
    /// write -- an inverse for each seal not yet reversed, the frames that
    /// close its state, and for a source parent about to be restored the room
    /// the committed entry then holds -- and a `RecoveryRequired` frame, so a
    /// retry that fails can still fail closed.
    pub(crate) fn retry_room(
        &self,
        transaction: TransactionId,
    ) -> Result<Option<(u64, u64)>, AllowanceError> {
        let Some(&state) = self.states.get(&transaction) else {
            return Ok(None);
        };
        let records = self.permission_records(transaction)?;
        let reversed = records
            .iter()
            .filter(|permission| permission.application == ApplicationStatus::Applied)
            .filter_map(|permission| permission.reverses_mutation_id)
            .collect::<std::collections::BTreeSet<_>>();
        if !records.iter().any(|permission| {
            permission.application == ApplicationStatus::ConfirmedNotApplied
                && permission
                    .reverses_mutation_id
                    .is_some_and(|original| !reversed.contains(&original))
        }) {
            return Ok(None);
        }
        let metadata = self
            .staging
            .get(&transaction)
            .ok_or(AllowanceError::Missing("staging metadata"))?;
        let filesystem_id = metadata.filesystem_id();
        let source_root = metadata
            .source_parent()
            .relative_path()
            .join(metadata.source_basename());
        let destination_root = metadata
            .destination_parent()
            .relative_path()
            .join(metadata.destination_basename());
        let resolution = frame_len(&SealRecord::PermissionApplied {
            transaction,
            mutation_id: ANY_MUTATION_ID,
        })?;
        let mut needed = 0;
        for seal in records.iter().filter(|permission| {
            permission.reverses_mutation_id.is_none()
                && permission.application == ApplicationStatus::Applied
                && !reversed.contains(&permission.mutation_id)
        }) {
            let tree = seal.phase == TransactionState::TreeSealIntent;
            // A source parent's seal is reversed before its entry commits, so an
            // undo never finds it among these. A tree seal is reversed where the
            // tree now is once it has been renamed, and a source parent being
            // restored is the one seal its phase reverses.
            let path = match (state, tree) {
                (TransactionState::UndoIntent, true) | (TransactionState::Quarantined, true) => {
                    let suffix = seal
                        .evidence
                        .relative_path()
                        .strip_prefix(&source_root)
                        .map_err(|_| AllowanceError::SealOutsideRoot {
                            mutation_id: seal.mutation_id,
                        })?;
                    destination_root.join(suffix)
                }
                (TransactionState::SourceParentRestoreIntent, true) => continue,
                _ => seal.evidence.relative_path().to_path_buf(),
            };
            needed += staging_intent_len(transaction, path, filesystem_id, Some(ANY_MUTATION_ID))?
                + resolution;
        }
        needed += match state {
            TransactionState::RestoreIntent => {
                states_len(transaction, &[TransactionState::Restored])?
            }
            TransactionState::SourceParentRestoreIntent => {
                states_len(
                    transaction,
                    &[
                        TransactionState::SourceParentRestored,
                        TransactionState::VerifiedCommitted,
                    ],
                )? + self
                    .undo_allowance(transaction)?
                    .max(self.purge_allowance(transaction, true)?)
            }
            TransactionState::Quarantined => 0,
            TransactionState::UndoIntent => {
                states_len(
                    transaction,
                    &[
                        TransactionState::UndoModesRestored,
                        TransactionState::UndoRenameIntent,
                        TransactionState::Restored,
                    ],
                )? + frame_len(&SealRecord::UndoRenameOutcome {
                    transaction,
                    outcome: DurableUndoRenameOutcome::AppliedAndParentsSynced(
                        metadata.root_identity(),
                    ),
                })?
            }
            other => return Err(AllowanceError::Unsettled(other)),
        };
        needed += states_len(transaction, &[TransactionState::RecoveryRequired])?;
        Ok(Some((needed, self.headroom(Some(transaction))?)))
    }
}

/// What a staging transaction writes before it walks its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BeginProjection {
    /// From its first frame until its source parent is sealed.
    pub(crate) forward: u64,
    /// Undoing that seal, if the tree is then refused.
    pub(crate) rolled_back: u64,
}

impl BeginProjection {
    /// The room it needs before it writes its first frame.
    pub(crate) fn needed(self) -> u64 {
        self.forward + self.rolled_back
    }
}

/// What a staging transaction may still write once its tree is planned.
///
/// Two ends are open. It may run to a commit, after which it holds what every
/// committed entry holds. Or it may stop as late as a rename confirmed not
/// applied and be rolled back, which reverses every seal where it was made,
/// under the source root; the undo of a committed entry finds them under the
/// destination root instead, so with a short destination root the rollback is
/// the larger. A failure on either writes `RecoveryRequired` in place of a
/// state frame the path would have written, so it needs no room of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeProjection {
    /// From the tree's first seal until the entry is committed.
    pub(crate) forward: u64,
    /// What the committed entry then holds, before its `RecoveryRequired`.
    pub(crate) committed: u64,
    /// The latest stop that is rolled back rather than committed: every frame
    /// up to a rename's outcome, then every seal reversed.
    pub(crate) rolled_back: u64,
}

impl TreeProjection {
    /// The room it needs before its first tree seal.
    pub(crate) fn needed(self) -> u64 {
        (self.forward + self.committed).max(self.rolled_back)
    }
}
