mod report;
mod restore;
mod selection;

use anyhow::Result;
use degu_core::ecosystem::DetectCtx;

use super::journal::OperationLog;
use restore::restore_selection;
use selection::select_actionable_undo_group;

pub(crate) use report::{
    UndoAmbiguousEntry, UndoEntry, UndoFailedEntry, UndoLogFailure, UndoReport,
};

pub(crate) fn undo_latest(ctx: &DetectCtx) -> Result<Option<UndoReport>> {
    let log = OperationLog::new(ctx);
    let records = log.read()?;
    let Some(selection) = select_actionable_undo_group(&records) else {
        return Ok(None);
    };
    let reclamation_label = selection
        .reclamation_id
        .clone()
        .unwrap_or_else(|| "-".to_string());
    let span = tracing::info_span!(target: "degu", "undo", reclamation_id = %reclamation_label);
    let _guard = span.enter();
    let report = restore_selection(&log, selection)?;
    trace_summary(&report, &reclamation_label);
    Ok(Some(report))
}

fn trace_summary(report: &UndoReport, reclamation_label: &str) {
    tracing::info!(
        target: "degu",
        restored = report.restored.len(),
        failed = report.failure_count(),
        log_failures = report.log_failures.len(),
        gone = report.gone.len(),
        ambiguous = report.ambiguous.len(),
        reclamation_id = %reclamation_label,
        "undo summary"
    );
}
