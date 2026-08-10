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
    UnverifiedDestination {
        entry: PathBuf,
        reason: String,
        final_log_append_failed: bool,
    },
    Staged {
        entry: PathBuf,
    },
    StagedWithFailure {
        entry: PathBuf,
        failure: StagedFailure,
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
            CleanState::UnverifiedDestination { entry, .. }
            | CleanState::Staged { entry, .. }
            | CleanState::StagedWithFailure { entry, .. }
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
            CleanState::UnverifiedDestination { entry, reason, .. } => {
                Some(CleanExecutionFailure::UnverifiedDestination { entry, reason })
            }
            CleanState::StagedWithFailure { failure, .. } => Some(CleanExecutionFailure::Staged {
                reason: &failure.reason,
                final_log_append_failed: failure.final_log_append_failed,
            }),
            CleanState::PurgeFailed { reason, .. } => {
                Some(CleanExecutionFailure::PurgeFailed { reason })
            }
            CleanState::Purged {
                final_log_failure: Some(reason),
                ..
            } => Some(CleanExecutionFailure::PurgedLog { reason }),
            CleanState::Staged { .. }
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
            CleanState::UnverifiedDestination { .. } => "unverified_destination",
            CleanState::Staged { .. } | CleanState::StagedWithFailure { .. } => "staged",
            CleanState::PurgeFailed { .. } => "purge_failed",
            CleanState::Purged { .. } => "purged",
        }
    }

    pub(crate) fn has_trash_location(&self) -> bool {
        matches!(
            self.state,
            CleanState::UnverifiedDestination { .. }
                | CleanState::Staged { .. }
                | CleanState::StagedWithFailure { .. }
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
        )
    }

    pub(crate) fn reported_as_cleaned(&self, purge: bool) -> bool {
        if purge {
            self.purged()
        } else {
            matches!(
                self.state,
                CleanState::Staged { .. } | CleanState::StagedWithFailure { .. }
            )
        }
    }

    pub(crate) fn requires_manual_recovery(&self) -> bool {
        matches!(self.state, CleanState::UnverifiedDestination { .. })
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
