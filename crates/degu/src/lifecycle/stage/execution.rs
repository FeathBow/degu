use degu_core::finding::Finding;
use std::path::{Path, PathBuf};

mod failure;
mod transaction;
pub(crate) use failure::CleanExecutionFailure;
pub(super) use transaction::{
    CleanFailure, CommittedStage, StageOutcome, StageRequest, record_clean_failure,
    stage_finding_with_log,
};

pub(crate) struct CleanExecution {
    subject: CleanSubject,
    state: CleanState,
}

struct CleanSubject {
    path: PathBuf,
    resources: ResourceSnapshot,
}

#[derive(Clone, Copy)]
struct ResourceSnapshot {
    bytes_allocated: u64,
    inodes: u64,
}

enum CleanState {
    StageFailed {
        reason: String,
    },
    Quarantined {
        entry: Option<PathBuf>,
        reason: String,
    },
    RecoveryBlocked {
        entry: Option<PathBuf>,
        reason: String,
    },
    UnverifiedDestination {
        entry: PathBuf,
        reason: String,
        final_log_append_failed: bool,
    },
    Staged {
        entry: PathBuf,
    },
    ProductionStaged {
        entry: PathBuf,
    },
    StagedWithFailure {
        entry: PathBuf,
        failure: StagedFailure,
    },
    ProductionCommittedWithFailure {
        entry: PathBuf,
        reservation_cleanup_failure: Option<String>,
        jsonl_projection_failure: Option<String>,
    },
    PurgeFailed {
        entry: PathBuf,
        reason: String,
    },
    Purged {
        entry: PathBuf,
        final_log_failure: Option<String>,
    },
}

struct StagedFailure {
    reason: String,
    final_log_append_failed: bool,
}

impl CleanExecution {
    fn staged_with_failure(finding: &Finding, entry: PathBuf, failure: StagedFailure) -> Self {
        Self::with_state(finding, CleanState::StagedWithFailure { entry, failure })
    }

    fn stage_failed(finding: &Finding, reason: String) -> Self {
        Self::with_state(finding, CleanState::StageFailed { reason })
    }

    pub(super) fn production_staged(
        finding: &Finding,
        entry: PathBuf,
        reservation_cleanup_failure: Option<String>,
        jsonl_projection_failure: Option<String>,
    ) -> Self {
        if reservation_cleanup_failure.is_none() && jsonl_projection_failure.is_none() {
            Self::with_state(finding, CleanState::ProductionStaged { entry })
        } else {
            Self::with_state(
                finding,
                CleanState::ProductionCommittedWithFailure {
                    entry,
                    reservation_cleanup_failure,
                    jsonl_projection_failure,
                },
            )
        }
    }

    pub(super) fn production_purge_authorized_retained(
        finding: &Finding,
        entry: PathBuf,
        reason: String,
    ) -> Self {
        Self::with_state(finding, CleanState::PurgeFailed { entry, reason })
    }

    pub(super) fn production_purge_admission_failed(
        finding: &Finding,
        entry: PathBuf,
        reason: String,
    ) -> Self {
        Self::with_state(finding, CleanState::PurgeFailed { entry, reason })
    }

    pub(super) fn quarantined(finding: &Finding, entry: Option<PathBuf>, reason: String) -> Self {
        Self::with_state(finding, CleanState::Quarantined { entry, reason })
    }

    pub(super) fn recovery_blocked(
        finding: &Finding,
        entry: Option<PathBuf>,
        reason: String,
    ) -> Self {
        Self::with_state(finding, CleanState::RecoveryBlocked { entry, reason })
    }

    pub(super) fn plain_stage_failed(finding: &Finding, reason: String) -> Self {
        Self::stage_failed(finding, reason)
    }

    fn unverified_destination(finding: &Finding, entry: PathBuf, reason: String) -> Self {
        Self::with_state(
            finding,
            CleanState::UnverifiedDestination {
                entry,
                reason,
                final_log_append_failed: false,
            },
        )
    }

    fn unverified_destination_with_log_failure(
        finding: &Finding,
        entry: PathBuf,
        reason: String,
    ) -> Self {
        Self::with_state(
            finding,
            CleanState::UnverifiedDestination {
                entry,
                reason,
                final_log_append_failed: true,
            },
        )
    }

    fn with_state(finding: &Finding, state: CleanState) -> Self {
        Self {
            subject: CleanSubject::from_finding(finding),
            state,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.subject.path
    }

    pub(crate) fn bytes_allocated(&self) -> u64 {
        self.subject.resources.bytes_allocated
    }

    pub(crate) fn trash_entry(&self) -> Option<&Path> {
        match &self.state {
            CleanState::StageFailed { .. } => None,
            CleanState::Quarantined { entry, .. } | CleanState::RecoveryBlocked { entry, .. } => {
                entry.as_deref()
            }
            CleanState::UnverifiedDestination { entry, .. }
            | CleanState::Staged { entry, .. }
            | CleanState::ProductionStaged { entry, .. }
            | CleanState::StagedWithFailure { entry, .. }
            | CleanState::ProductionCommittedWithFailure { entry, .. }
            | CleanState::PurgeFailed { entry, .. }
            | CleanState::Purged { entry, .. } => Some(entry),
        }
    }

    pub(crate) fn failure_reason(&self) -> Option<&str> {
        self.failure().map(|failure| failure.reason())
    }

    pub(crate) fn failure(&self) -> Option<CleanExecutionFailure<'_>> {
        match &self.state {
            CleanState::StageFailed { reason } => {
                Some(CleanExecutionFailure::StageFailed { reason })
            }
            CleanState::Quarantined { entry, reason } => Some(CleanExecutionFailure::Quarantined {
                entry: entry.as_deref(),
                reason,
            }),
            CleanState::RecoveryBlocked { entry, reason } => {
                Some(CleanExecutionFailure::RecoveryBlocked {
                    entry: entry.as_deref(),
                    reason,
                })
            }
            CleanState::UnverifiedDestination { entry, reason, .. } => {
                Some(CleanExecutionFailure::UnverifiedDestination { entry, reason })
            }
            CleanState::StagedWithFailure { failure, .. } => Some(CleanExecutionFailure::Staged {
                reason: &failure.reason,
                final_log_append_failed: failure.final_log_append_failed,
            }),
            CleanState::ProductionCommittedWithFailure {
                reservation_cleanup_failure,
                jsonl_projection_failure,
                ..
            } => Some(CleanExecutionFailure::ProductionCommitted {
                reservation_cleanup_failure: reservation_cleanup_failure.as_deref(),
                jsonl_projection_failure: jsonl_projection_failure.as_deref(),
            }),
            CleanState::PurgeFailed { reason, .. } => {
                Some(CleanExecutionFailure::PurgeFailed { reason })
            }
            CleanState::Purged {
                final_log_failure: Some(reason),
                ..
            } => Some(CleanExecutionFailure::PurgedLog { reason }),
            CleanState::Staged { .. }
            | CleanState::ProductionStaged { .. }
            | CleanState::Purged {
                final_log_failure: None,
                ..
            } => None,
        }
    }

    pub(crate) fn failed(&self) -> bool {
        self.failure_reason().is_some()
    }

    pub(crate) fn purged(&self) -> bool {
        matches!(self.state, CleanState::Purged { .. })
    }

    pub(crate) fn state_label(&self) -> &'static str {
        match &self.state {
            CleanState::StageFailed { .. } => "stage_failed",
            CleanState::Quarantined { .. } => "quarantined",
            CleanState::RecoveryBlocked { .. } => "recovery_blocked",
            CleanState::UnverifiedDestination { .. } => "unverified_destination",
            CleanState::Staged { .. }
            | CleanState::ProductionStaged { .. }
            | CleanState::StagedWithFailure { .. }
            | CleanState::ProductionCommittedWithFailure { .. } => "staged",
            CleanState::PurgeFailed { .. } => "purge_failed",
            CleanState::Purged { .. } => "purged",
        }
    }

    pub(crate) fn has_trash_location(&self) -> bool {
        matches!(
            self.state,
            CleanState::Quarantined { entry: Some(_), .. }
                | CleanState::RecoveryBlocked { entry: Some(_), .. }
                | CleanState::UnverifiedDestination { .. }
                | CleanState::Staged { .. }
                | CleanState::ProductionStaged { .. }
                | CleanState::StagedWithFailure { .. }
                | CleanState::ProductionCommittedWithFailure { .. }
                | CleanState::PurgeFailed { .. }
        )
    }

    pub(crate) fn final_log_append_failed(&self) -> bool {
        matches!(
            self.state,
            CleanState::UnverifiedDestination {
                final_log_append_failed: true,
                ..
            } | CleanState::Purged {
                final_log_failure: Some(_),
                ..
            }
        ) || matches!(
            &self.state,
            CleanState::StagedWithFailure { failure, .. } if failure.final_log_append_failed
        ) || matches!(
            &self.state,
            CleanState::ProductionCommittedWithFailure {
                jsonl_projection_failure: Some(_),
                ..
            }
        )
    }

    pub(crate) fn reported_as_cleaned(&self, purge: bool) -> bool {
        if purge {
            self.purged()
        } else {
            matches!(
                self.state,
                CleanState::Staged { .. }
                    | CleanState::ProductionStaged { .. }
                    | CleanState::StagedWithFailure { .. }
                    | CleanState::ProductionCommittedWithFailure { .. }
            )
        }
    }

    pub(crate) fn sealed_staging_has_recovery_authority(&self) -> bool {
        matches!(
            self.state,
            CleanState::ProductionStaged { .. }
                | CleanState::ProductionCommittedWithFailure { .. }
                | CleanState::Quarantined { .. }
                | CleanState::RecoveryBlocked { .. }
        )
    }

    pub(crate) fn requires_manual_recovery(&self) -> bool {
        matches!(
            self.state,
            CleanState::Quarantined { .. }
                | CleanState::RecoveryBlocked { .. }
                | CleanState::UnverifiedDestination { .. }
        )
    }

    fn staged(staged: CommittedStage) -> Self {
        let (subject, entry) = staged.into_parts();
        Self {
            subject,
            state: CleanState::Staged { entry },
        }
    }

    pub(super) fn purge_failed(staged: CommittedStage, entry: PathBuf, reason: String) -> Self {
        let (subject, _) = staged.into_parts();
        Self {
            subject,
            state: CleanState::PurgeFailed { entry, reason },
        }
    }

    pub(super) fn from_purged(staged: CommittedStage, final_log_failure: Option<String>) -> Self {
        let (subject, entry) = staged.into_parts();
        Self {
            subject,
            state: CleanState::Purged {
                entry,
                final_log_failure,
            },
        }
    }
}

impl CleanSubject {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            path: finding.path().to_path_buf(),
            resources: ResourceSnapshot {
                bytes_allocated: finding.bytes_allocated(),
                inodes: finding.inodes(),
            },
        }
    }
}

pub(crate) fn cleaned_resources(executed: &[CleanExecution], purge: bool) -> (u64, u64) {
    executed
        .iter()
        .filter(|item| item.reported_as_cleaned(purge))
        .fold((0, 0), |(bytes, inodes), item| {
            let resources = item.subject.resources;
            (
                bytes.saturating_add(resources.bytes_allocated),
                inodes.saturating_add(resources.inodes),
            )
        })
}

#[cfg(test)]
mod tests;
