use crate::lifecycle::{CleanExecution, CleanExecutionFailure};
use crate::presentation::{Severity, escape_terminal_text};
use std::path::Path;

pub(super) fn note(item: &CleanExecution) -> Option<(Severity, String)> {
    item.failure().map(|failure| render(item.path(), failure))
}

/// Failures that lost or endangered data are errors; failures whose payload
/// landed but whose bookkeeping did not are warnings.
fn render(path: &Path, failure: CleanExecutionFailure<'_>) -> (Severity, String) {
    let path = escaped_path(path);
    match failure {
        CleanExecutionFailure::StageFailed { reason } => (
            Severity::Error,
            format!("failed to stage {path}: {}", escape_terminal_text(reason)),
        ),
        CleanExecutionFailure::UnverifiedDestination { entry, reason } => (
            Severity::Error,
            format!(
                "moved {path} to {}, but destination verification failed; automatic rollback was not attempted, so inspect the destination and recover it manually only after confirming its identity: {}",
                escaped_path(entry),
                escape_terminal_text(reason)
            ),
        ),
        CleanExecutionFailure::Staged {
            reason,
            final_log_append_failed: true,
        } => (
            Severity::Warning,
            format!(
                "staged {path}, but the operation log write failed; entry recorded as pending: {}",
                escape_terminal_text(reason)
            ),
        ),
        CleanExecutionFailure::Staged {
            reason,
            final_log_append_failed: false,
        } => (
            Severity::Warning,
            format!(
                "staged {path}, but post-stage finalization failed: {}",
                escape_terminal_text(reason)
            ),
        ),
        CleanExecutionFailure::PurgeFailed { reason } => (
            Severity::Error,
            format!("failed to purge {path}: {}", escape_terminal_text(reason)),
        ),
        CleanExecutionFailure::PurgedLog { reason } => (
            Severity::Warning,
            format!(
                "purged {path}, but the operation log write failed after deletion; deletion is complete and cannot be undone: {}",
                escape_terminal_text(reason)
            ),
        ),
    }
}

fn escaped_path(path: &Path) -> String {
    escape_terminal_text(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_notes_escape_text_and_preserve_recovery_scope() {
        let (severity, staged) = render(
            Path::new("/cache\n\u{1b}[31m"),
            CleanExecutionFailure::StageFailed {
                reason: "probe failed\rretry",
            },
        );
        assert!(matches!(severity, Severity::Error));
        assert_eq!(
            staged,
            "failed to stage /cache\\n\\u{1b}[31m: probe failed\\rretry"
        );
        let (severity, unverified) = render(
            Path::new("/cache"),
            CleanExecutionFailure::UnverifiedDestination {
                entry: Path::new("/trash/0001-cache"),
                reason: "identity changed",
            },
        );
        assert!(matches!(severity, Severity::Error));
        assert!(unverified.contains("automatic rollback was not attempted"));
        assert!(unverified.contains("recover it manually only after confirming its identity"));
        let (severity, purged) = render(
            Path::new("/cache"),
            CleanExecutionFailure::PurgedLog { reason: "log full" },
        );
        assert!(matches!(severity, Severity::Warning));
        assert!(purged.contains("deletion is complete and cannot be undone"));
    }
}
