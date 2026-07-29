use degu_core::ecosystem::DetectCtx;
use std::path::{Path, PathBuf};

use super::super::purge::{PlannedTrashEntry, PurgeBatch, PurgeReport, purge_trash_entries};
use super::execution::{CleanExecution, CommittedStage, StageOutcome};

pub(super) fn execute(ctx: &DetectCtx, outcome: StageOutcome) -> CleanExecution {
    match outcome {
        StageOutcome::Committed(staged) => execute_committed(ctx, staged),
        StageOutcome::Terminal(execution) => execution,
    }
}

fn execute_committed(ctx: &DetectCtx, staged: CommittedStage) -> CleanExecution {
    let entry = staged.entry().to_path_buf();
    match purge_fresh_entry(ctx, &staged) {
        Ok(report) => apply_report(staged, report),
        Err(reason) => CleanExecution::purge_failed(staged, entry, reason),
    }
}

fn purge_fresh_entry(ctx: &DetectCtx, staged: &CommittedStage) -> Result<PurgeReport, String> {
    let entry = staged.entry();
    let trash_root = entry.parent().ok_or_else(|| {
        format!(
            "staged entry has no managed trash root: {}",
            entry.display()
        )
    })?;
    let batch = PurgeBatch::new(ctx, "clean", trash_root)
        .with_reclamation_id(Some(staged.reclamation_id()));
    let planned = PlannedTrashEntry::new(entry.to_path_buf(), staged.identity().clone());
    Ok(purge_trash_entries(batch, vec![planned]))
}

pub(super) fn apply_report(staged: CommittedStage, report: PurgeReport) -> CleanExecution {
    let entry = staged.entry();
    let purged = report.purged.iter().any(|purged| purged == entry);
    let failure = combined_failure(entry, report.failed);
    if purged {
        return CleanExecution::from_purged(staged, failure.map(|failure| failure.reason));
    }
    let failure = failure.unwrap_or_else(|| PurgeFailure {
        entry: entry.to_path_buf(),
        reason: format!("failed to purge {}", entry.display()),
    });
    CleanExecution::purge_failed(staged, failure.entry, failure.reason)
}

struct PurgeFailure {
    entry: PathBuf,
    reason: String,
}

fn combined_failure(entry: &Path, failures: Vec<(PathBuf, String)>) -> Option<PurgeFailure> {
    let retained_entry = failures.first()?.0.clone();
    let reasons = failures
        .into_iter()
        .map(|(path, reason)| {
            if path == entry {
                reason
            } else {
                format!("{}: {reason}", path.display())
            }
        })
        .collect::<Vec<_>>();
    Some(PurgeFailure {
        entry: retained_entry,
        reason: reasons.join("; "),
    })
}
