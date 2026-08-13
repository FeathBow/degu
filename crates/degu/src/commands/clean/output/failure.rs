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
        CleanExecutionFailure::Quarantined { entry, reason } => (
            Severity::Error,
            format!(
                "sealed staging quarantined {path}{}; the entry is retained and requires manual recovery. Do not run undo for this entry: {}",
                retained_entry(entry),
                escape_terminal_text(reason)
            ),
        ),
        CleanExecutionFailure::RecoveryBlocked { entry, reason } => (
            Severity::Error,
            match entry {
                Some(entry) => format!(
                    "sealed staging recovery blocked for {path} at {}; the entry is retained and requires manual recovery. Do not run undo for this entry: {}",
                    escaped_path(entry),
                    escape_terminal_text(reason)
                ),
                None => format!(
                    "sealed staging recovery blocked for {path}; WAL and reservation evidence are retained and require manual recovery. Do not run undo for this transaction: {}",
                    escape_terminal_text(reason)
                ),
            },
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
        CleanExecutionFailure::ProductionCommitted {
            reservation_cleanup_failure,
            jsonl_projection_failure,
        } => {
            let mut details = Vec::new();
            if let Some(reason) = reservation_cleanup_failure {
                details.push(format!(
                    "trash reservation cleanup failed (the reservation is housekeeping only): {}",
                    escape_terminal_text(reason)
                ));
            }
            if let Some(reason) = jsonl_projection_failure {
                details.push(format!(
                    "ops.jsonl projection failed (the WAL commit remains authoritative): {}",
                    escape_terminal_text(reason)
                ));
            }
            (
                Severity::Warning,
                format!(
                    "sealed staging durably committed {path}, but {}",
                    details.join("; ")
                ),
            )
        }
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

fn retained_entry(entry: Option<&Path>) -> String {
    entry.map_or_else(String::new, |entry| format!(" at {}", escaped_path(entry)))
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
        let (severity, quarantined) = render(
            Path::new("/cache"),
            CleanExecutionFailure::Quarantined {
                entry: Some(Path::new("/trash/0001-cache")),
                reason: "strong identity mismatch",
            },
        );
        assert!(matches!(severity, Severity::Error));
        assert!(quarantined.contains("entry is retained and requires manual recovery"));
        assert!(quarantined.contains("Do not run undo"));

        let (severity, blocked) = render(
            Path::new("/cache"),
            CleanExecutionFailure::RecoveryBlocked {
                entry: None,
                reason: "WAL append outcome uncertain",
            },
        );
        assert!(matches!(severity, Severity::Error));
        assert!(blocked.contains("WAL and reservation evidence are retained"));
        assert!(!blocked.contains(" at /trash/"));

        let (severity, projection) = render(
            Path::new("/cache"),
            CleanExecutionFailure::ProductionCommitted {
                reservation_cleanup_failure: Some("claim busy"),
                jsonl_projection_failure: Some("disk full"),
            },
        );
        assert!(matches!(severity, Severity::Warning));
        assert!(projection.contains("reservation cleanup failed"));
        assert!(projection.contains("housekeeping only"));
        assert!(projection.contains("ops.jsonl projection failed"));
        assert!(projection.contains("WAL commit remains authoritative"));

        let (severity, purged) = render(
            Path::new("/cache"),
            CleanExecutionFailure::PurgedLog { reason: "log full" },
        );
        assert!(matches!(severity, Severity::Warning));
        assert!(purged.contains("deletion is complete and cannot be undone"));
    }
}
