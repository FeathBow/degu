use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum CleanExecutionFailure<'a> {
    StageFailed {
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
            | Self::UnverifiedDestination { reason, .. }
            | Self::Staged { reason, .. }
            | Self::PurgeFailed { reason }
            | Self::PurgedLog { reason } => reason,
        }
    }
}
