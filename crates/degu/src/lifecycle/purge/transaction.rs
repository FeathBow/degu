use std::path::{Path, PathBuf};

use degu_core::oplog::OpOutcome;

use super::super::operation_log::{OperationLog, PurgeRecord, purge_record};
use super::PurgeReport;
use super::claim::{ClaimFailure, ClaimedTrashEntry, FailureLocation, LocatedFailure};

pub(super) struct PurgeOperation {
    pub(super) entry: PathBuf,
    command: String,
    reclamation_id: Option<String>,
}

impl PurgeOperation {
    pub(super) fn new(command: &str, entry: PathBuf, reclamation_id: Option<&str>) -> Self {
        Self {
            command: command.to_string(),
            entry,
            reclamation_id: reclamation_id.map(str::to_string),
        }
    }
}

pub(super) fn append_record(
    log: &OperationLog,
    operation: &PurgeOperation,
    outcome: OpOutcome,
) -> std::io::Result<()> {
    log.append(&purge_record(PurgeRecord {
        command: &operation.command,
        entry: &operation.entry,
        reclamation_id: operation.reclamation_id.as_deref(),
        outcome,
    }))
}

pub(super) fn report_claim_failure(
    planned: PathBuf,
    failure: ClaimFailure,
    report: &mut PurgeReport,
) {
    let (actual, source, identity_changed) = failure.into_parts();
    let reason = if identity_changed {
        format!(
            "trash entry identity changed after confirmation; inspect the entry at {}: {source}",
            actual.display()
        )
    } else {
        format!(
            "purge claim for {} could not be established; inspect the entry at {}: {source}",
            planned.display(),
            actual.display()
        )
    };
    report.failed.push((actual, reason));
}

pub(super) fn purge_claimed(
    mut operation: PurgeOperation,
    claimed: ClaimedTrashEntry,
    mut append: impl FnMut(&PurgeOperation, OpOutcome) -> std::io::Result<()>,
) -> PurgeReport {
    let mut report = PurgeReport::default();
    if let Err(error) = append(&operation, OpOutcome::Pending) {
        return pending_failure(operation.entry, claimed, error);
    }
    let outcome = match claimed.purge() {
        Ok(()) => OpOutcome::Ok,
        Err(failure) => failed_outcome(&mut operation, failure),
    };
    let append_result = append(&operation, outcome.clone());
    record_outcome(operation.entry.clone(), outcome, &mut report);
    if let Err(error) = append_result {
        report.failed.push((
            operation.entry,
            format!("operation log append failed: {error}"),
        ));
    }
    report
}

pub(super) fn failed_outcome(operation: &mut PurgeOperation, failure: LocatedFailure) -> OpOutcome {
    let (actual, error, _) = failure.into_parts();
    operation.entry = actual;
    OpOutcome::Failed {
        reason: error.to_string(),
    }
}

fn pending_failure(
    entry: PathBuf,
    claimed: ClaimedTrashEntry,
    append_error: std::io::Error,
) -> PurgeReport {
    let (entry, detail) = match claimed.restore() {
        Ok(()) => (entry, "the purge claim was restored".to_string()),
        Err(failure) => {
            let (actual, error, location) = failure.into_parts();
            let detail = restore_failure_detail(&actual, error, location);
            (actual, detail)
        }
    };
    let mut report = PurgeReport::default();
    report.failed.push((
        entry,
        format!("operation log append failed before deletion: {append_error}; {detail}"),
    ));
    report
}

fn restore_failure_detail(
    actual: &Path,
    error: std::io::Error,
    location: FailureLocation,
) -> String {
    match location {
        FailureLocation::Source => format!(
            "the purge claim restore did not complete; inspect the claim source at {}: {error}",
            actual.display()
        ),
        FailureLocation::UnauthenticatedParent => format!(
            "the purge claim restore was refused because the destination parent {} could not be authenticated; the claim was not moved: {error}",
            actual.display()
        ),
        FailureLocation::UnverifiedDestination => format!(
            "the purge claim restore could not be verified; inspect the unverified destination at {}: {error}",
            actual.display()
        ),
        FailureLocation::Current => {
            format!("inspect the current entry at {}: {error}", actual.display())
        }
    }
}

fn record_outcome(entry: PathBuf, outcome: OpOutcome, report: &mut PurgeReport) {
    tracing::info!(
        target: "degu",
        path = %entry.display(),
        outcome = outcome_label(&outcome),
        "trash entry purged"
    );
    match outcome {
        OpOutcome::Ok => report.purged.push(entry),
        OpOutcome::Failed { reason } => report.failed.push((entry, reason)),
        OpOutcome::Pending => unreachable!("purge final record cannot be pending"),
    }
}

fn outcome_label(outcome: &OpOutcome) -> &'static str {
    match outcome {
        OpOutcome::Pending => "pending",
        OpOutcome::Ok => "ok",
        OpOutcome::Failed { .. } => "failed",
    }
}
