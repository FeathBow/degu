use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum CleanExecutionFailure<'a> {
    StageFailed {
        reason: &'a str,
    },
    Quarantined {
        entry: Option<&'a Path>,
        reason: &'a str,
    },
    RecoveryBlocked {
        entry: Option<&'a Path>,
        reason: &'a str,
    },
    UnverifiedDestination {
        entry: &'a Path,
        reason: &'a str,
    },
    Staged {
        reason: &'a str,
        final_log_append_failed: bool,
    },
    ProductionCommitted {
        reservation_cleanup_failure: Option<&'a str>,
        jsonl_projection_failure: Option<&'a str>,
    },
    PurgeFailed {
        reason: &'a str,
    },
    PurgedLog {
        reason: &'a str,
    },
}

impl<'a> CleanExecutionFailure<'a> {
    pub(crate) fn reason(self) -> &'a str {
        match self {
            Self::StageFailed { reason }
            | Self::Quarantined { reason, .. }
            | Self::RecoveryBlocked { reason, .. }
            | Self::UnverifiedDestination { reason, .. }
            | Self::Staged { reason, .. }
            | Self::PurgeFailed { reason }
            | Self::PurgedLog { reason } => reason,
            Self::ProductionCommitted {
                reservation_cleanup_failure,
                jsonl_projection_failure,
            } => reservation_cleanup_failure
                .or(jsonl_projection_failure)
                .expect("production projection failure has at least one reason"),
        }
    }
}
