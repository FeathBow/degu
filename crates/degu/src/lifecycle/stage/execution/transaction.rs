use crate::lifecycle::trash::Trash;
use degu_core::finding::Finding;
use degu_core::oplog::{ObjectIdentity, OpOutcome, OpRecord};
use std::path::PathBuf;

use super::{CleanExecution, CleanSubject, StagedFailure};
use crate::lifecycle::identity::{EntryIdentity, RenameFailure};
use crate::lifecycle::operation_log::{OperationLog, TrashRecord, trash_record};

pub(crate) struct StageRequest<'a> {
    pub(crate) trash: &'a Trash,
    pub(crate) finding: &'a Finding,
    pub(crate) identity: &'a EntryIdentity,
    pub(crate) entry: PathBuf,
    pub(crate) reclamation_id: &'a str,
}

pub(crate) struct CleanFailure<'a> {
    pub(crate) log: &'a OperationLog,
    pub(crate) finding: &'a Finding,
    pub(crate) reason: String,
    pub(crate) reclamation_id: Option<String>,
}

pub(in crate::lifecycle::stage) enum StageOutcome {
    Committed(CommittedStage),
    Terminal(CleanExecution),
}

pub(in crate::lifecycle::stage) struct CommittedStage {
    subject: CleanSubject,
    entry: PathBuf,
    /// The staged object's verified identity, carried forward so a direct
    /// purge deletes exactly what was staged -- re-capturing from the trash
    /// path would authorize whatever object sits there by then.
    identity: EntryIdentity,
    reclamation_id: String,
}

impl StageOutcome {
    fn committed(
        finding: &Finding,
        entry: PathBuf,
        identity: EntryIdentity,
        reclamation_id: &str,
    ) -> Self {
        Self::Committed(CommittedStage {
            subject: CleanSubject::from_finding(finding),
            entry,
            identity,
            reclamation_id: reclamation_id.to_string(),
        })
    }

    fn terminal(execution: CleanExecution) -> Self {
        Self::Terminal(execution)
    }

    pub(in crate::lifecycle::stage) fn finish(self) -> CleanExecution {
        match self {
            Self::Committed(staged) => CleanExecution::staged(staged),
            Self::Terminal(execution) => execution,
        }
    }
}

impl CommittedStage {
    pub(in crate::lifecycle::stage) fn entry(&self) -> &std::path::Path {
        &self.entry
    }

    pub(in crate::lifecycle::stage) fn identity(&self) -> &EntryIdentity {
        &self.identity
    }

    pub(in crate::lifecycle::stage) fn reclamation_id(&self) -> &str {
        &self.reclamation_id
    }

    pub(super) fn into_parts(self) -> (CleanSubject, PathBuf) {
        (self.subject, self.entry)
    }
}

pub(in crate::lifecycle::stage) fn stage_finding_with_log(
    request: StageRequest<'_>,
    append: &mut dyn FnMut(&OpRecord) -> std::io::Result<()>,
    recheck: &dyn Fn(&Finding) -> Result<(), String>,
) -> StageOutcome {
    // Snapshot the restore-destination parent BEFORE the destructive rename and
    // before the pending record, while the source (and therefore its parent) is
    // present. The live restore check uses `Stable` (device+inode+kind), which
    // the rename does not change, so a pre-rename capture authenticates exactly
    // the same directory a later restore will find. This also lets the pending
    // record carry the parent, so a crash that leaves only the pending record
    // still reconciles into an authenticated restore. A capture failure here
    // fails closed: nothing is moved and no pending record is written.
    let destination_parent = match capture_destination_parent(request.finding.path()) {
        Ok(identity) => identity,
        Err(error) => {
            let reason = release_failed_reservation(
                &request,
                format!(
                    "could not record the restore destination parent for {}: {error}",
                    request.finding.path().display()
                ),
            );
            return StageOutcome::terminal(CleanExecution::stage_failed(request.finding, reason));
        }
    };

    let pending = trash_record(TrashRecord {
        finding: request.finding,
        trash_entry: Some(request.entry.clone()),
        outcome: OpOutcome::Pending,
        reclamation_id: Some(request.reclamation_id.to_string()),
        expected_identity: Some(request.identity.oplog_identity()),
        destination_parent: Some(destination_parent),
    });
    if let Err(err) = append(&pending) {
        let reason = release_failed_reservation(
            &request,
            format!("operation log append failed before staging: {err}"),
        );
        return StageOutcome::terminal(CleanExecution::stage_failed(request.finding, reason));
    }

    let outcome = commit_verified(&request, destination_parent, recheck);
    let final_record = trash_record(TrashRecord {
        finding: request.finding,
        trash_entry: Some(request.entry.clone()),
        outcome: clean_op_outcome(&outcome),
        reclamation_id: Some(request.reclamation_id.to_string()),
        expected_identity: clean_op_identity(&outcome),
        destination_parent: clean_op_destination_parent(&outcome),
    });
    if let Err(err) = append(&final_record) {
        return append_failure(&request, outcome, err);
    }
    complete_stage(request, outcome)
}

fn complete_stage(request: StageRequest<'_>, outcome: CommitOutcome) -> StageOutcome {
    match outcome {
        CommitOutcome::Staged {
            moved,
            cleanup_failure,
            ..
        } => match cleanup_failure {
            None => StageOutcome::committed(
                request.finding,
                request.entry,
                moved,
                request.reclamation_id,
            ),
            Some(reason) => StageOutcome::terminal(CleanExecution::staged_with_failure(
                request.finding,
                request.entry,
                StagedFailure {
                    reason,
                    final_log_append_failed: false,
                },
            )),
        },
        CommitOutcome::Failed(reason) => {
            StageOutcome::terminal(CleanExecution::stage_failed(request.finding, reason))
        }
        CommitOutcome::UnverifiedDestination { entry, reason } => StageOutcome::terminal(
            CleanExecution::unverified_destination(request.finding, entry, reason),
        ),
    }
}

enum CommitOutcome {
    Staged {
        moved: EntryIdentity,
        destination_parent: ObjectIdentity,
        cleanup_failure: Option<String>,
    },
    Failed(String),
    UnverifiedDestination {
        entry: PathBuf,
        reason: String,
    },
}

fn commit_verified(
    request: &StageRequest<'_>,
    destination_parent: ObjectIdentity,
    recheck: &dyn Fn(&Finding) -> Result<(), String>,
) -> CommitOutcome {
    let outcome = move_verified(request, destination_parent, recheck);
    match request.trash.release_reservation(&request.entry) {
        Ok(()) => outcome,
        Err(error) => outcome.with_cleanup_failure(error),
    }
}

fn move_verified(
    request: &StageRequest<'_>,
    destination_parent: ObjectIdentity,
    recheck: &dyn Fn(&Finding) -> Result<(), String>,
) -> CommitOutcome {
    let source = request.finding.path();
    match request.identity.matches(source) {
        Ok(true) => {}
        Ok(false) => {
            return CommitOutcome::Failed(format!(
                "entry identity changed before mount safety validation: {}",
                source.display()
            ));
        }
        Err(error) => return CommitOutcome::Failed(error.to_string()),
    }
    match degu_walk::validate_single_mount_tree(source) {
        // The recheck runs after the mount traversal, which is not constant
        // time: a protected alias created while a large tree is walked would
        // otherwise slip between the check and the rename.
        Ok(()) => match recheck(request.finding) {
            Err(reason) => CommitOutcome::Failed(format!(
                "protection re-check failed at the staging boundary: {reason}"
            )),
            Ok(()) => match request
                .identity
                .rename_verified_located(source, &request.entry)
            {
                // The destination parent was captured before this rename, while the
                // source was present; the rename removes the entry, not the parent,
                // and the live restore check uses `Stable` (device+inode+kind) which
                // the rename does not change, so the pre-captured value authenticates
                // exactly the directory a later restore will find.
                Ok(moved) => CommitOutcome::Staged {
                    moved,
                    destination_parent,
                    cleanup_failure: None,
                },
                Err(error) => commit_failure(error),
            },
        },
        Err(error) => CommitOutcome::Failed(format!(
            "mount safety validation failed before staging: {error}"
        )),
    }
}

fn capture_destination_parent(source: &std::path::Path) -> std::io::Result<ObjectIdentity> {
    let parent = source
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("entry has no parent directory: {}", source.display()),
            )
        })?;
    crate::lifecycle::identity::capture_parent_following(parent)
}

impl CommitOutcome {
    fn with_cleanup_failure(self, error: std::io::Error) -> Self {
        let cleanup = format!("trash reservation cleanup failed: {error}");
        match self {
            Self::Staged {
                moved,
                destination_parent,
                ..
            } => Self::Staged {
                moved,
                destination_parent,
                cleanup_failure: Some(cleanup),
            },
            Self::Failed(reason) => Self::Failed(format!("{reason}; {cleanup}")),
            Self::UnverifiedDestination { entry, reason } => Self::UnverifiedDestination {
                entry,
                reason: format!("{reason}; {cleanup}"),
            },
        }
    }
}

fn commit_failure(error: RenameFailure) -> CommitOutcome {
    match error {
        RenameFailure::Source(error) => CommitOutcome::Failed(error.to_string()),
        // Staging renames into a degu-controlled trash entry via
        // `rename_verified_located`, which never authenticates a parent, so this
        // arm is unreachable here; keep it total and treat it as a plain failure.
        RenameFailure::UnauthenticatedParent { parent, error } => CommitOutcome::Failed(format!(
            "destination parent {} could not be authenticated: {error}",
            parent.display()
        )),
        RenameFailure::UnverifiedDestination { destination, error } => {
            CommitOutcome::UnverifiedDestination {
                entry: destination,
                reason: error.to_string(),
            }
        }
    }
}

fn release_failed_reservation(request: &StageRequest<'_>, reason: String) -> String {
    match request.trash.release_reservation(&request.entry) {
        Ok(()) => reason,
        Err(error) => format!("{reason}; trash reservation cleanup failed: {error}"),
    }
}

pub(crate) fn record_clean_failure(request: CleanFailure<'_>) -> CleanExecution {
    let record = trash_record(TrashRecord {
        finding: request.finding,
        trash_entry: None,
        outcome: OpOutcome::Failed {
            reason: request.reason.clone(),
        },
        reclamation_id: request.reclamation_id,
        expected_identity: None,
        destination_parent: None,
    });
    let reason = match request.log.append(&record) {
        Ok(()) => request.reason,
        Err(error) => merge_log_failure(request.reason, error, "while recording stage failure"),
    };
    CleanExecution::stage_failed(request.finding, reason)
}

fn append_failure(
    request: &StageRequest<'_>,
    outcome: CommitOutcome,
    error: std::io::Error,
) -> StageOutcome {
    let execution = match outcome {
        CommitOutcome::Staged {
            moved: _,
            destination_parent: _,
            cleanup_failure,
        } => {
            let reason = match cleanup_failure {
                None => format!("operation log append failed: {error}"),
                Some(reason) => {
                    merge_log_failure(reason, error, "after reservation cleanup failure")
                }
            };
            CleanExecution::staged_with_failure(
                request.finding,
                request.entry.clone(),
                StagedFailure {
                    reason,
                    final_log_append_failed: true,
                },
            )
        }
        CommitOutcome::Failed(reason) => CleanExecution::stage_failed(
            request.finding,
            merge_log_failure(reason, error, "after stage failure"),
        ),
        CommitOutcome::UnverifiedDestination { entry, reason } => {
            CleanExecution::unverified_destination_with_log_failure(
                request.finding,
                entry,
                merge_log_failure(reason, error, "after stage failure"),
            )
        }
    };
    StageOutcome::terminal(execution)
}

fn merge_log_failure(reason: String, error: std::io::Error, context: &str) -> String {
    format!("{reason}; operation log append failed {context}: {error}")
}

fn clean_op_outcome(outcome: &CommitOutcome) -> OpOutcome {
    match outcome {
        CommitOutcome::Staged { .. } => OpOutcome::Ok,
        CommitOutcome::Failed(reason) | CommitOutcome::UnverifiedDestination { reason, .. } => {
            OpOutcome::Failed {
                reason: reason.clone(),
            }
        }
    }
}

fn clean_op_identity(outcome: &CommitOutcome) -> Option<ObjectIdentity> {
    match outcome {
        CommitOutcome::Staged { moved, .. } => Some(moved.oplog_identity()),
        CommitOutcome::Failed(_) | CommitOutcome::UnverifiedDestination { .. } => None,
    }
}

fn clean_op_destination_parent(outcome: &CommitOutcome) -> Option<ObjectIdentity> {
    match outcome {
        CommitOutcome::Staged {
            destination_parent, ..
        } => Some(*destination_parent),
        CommitOutcome::Failed(_) | CommitOutcome::UnverifiedDestination { .. } => None,
    }
}
