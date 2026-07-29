use std::path::{Path, PathBuf};

use crate::lifecycle::trash::Trash;
use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;

use super::claims::interrupted_purge_claims;
use super::expiry::{ExpiryContext, should_purge_expired_entry};
use super::operation_log::OperationLog;
use super::reconcile::reconciled_trash_info;
use super::storage::trash_roots;

mod claim;
mod housekeeping;
mod plan;
#[cfg(test)]
mod tests;
mod transaction;
use claim::ClaimedTrashEntry;
use housekeeping::purge_expired_claims;
pub(crate) use plan::PlannedTrashEntry;
use plan::PurgePlanBatch;
pub(crate) use plan::{ExpiryPlan, TrashPurgePlan};
use transaction::{PurgeOperation, append_record, purge_claimed, report_claim_failure};

#[derive(Default)]
pub(crate) struct PurgeReport {
    pub(crate) purged: Vec<PathBuf>,
    pub(crate) failed: Vec<(PathBuf, String)>,
}

impl PurgeReport {
    fn extend(&mut self, report: Self) {
        self.purged.extend(report.purged);
        self.failed.extend(report.failed);
    }
}

pub(crate) struct PurgeBatch<'a> {
    ctx: &'a DetectCtx,
    command: &'a str,
    trash_root: &'a Path,
    reclamation_id: Option<&'a str>,
}

impl<'a> PurgeBatch<'a> {
    pub(crate) fn new(ctx: &'a DetectCtx, command: &'a str, trash_root: &'a Path) -> Self {
        Self {
            ctx,
            command,
            trash_root,
            reclamation_id: None,
        }
    }

    pub(crate) fn with_reclamation_id(self, reclamation_id: Option<&'a str>) -> Self {
        Self {
            reclamation_id,
            ..self
        }
    }
}

pub(crate) fn plan_expired_trash(ctx: &DetectCtx) -> Result<ExpiryPlan> {
    let records = OperationLog::new(ctx).read()?;
    let recorded = reconciled_trash_info(&records);
    let expiry = ExpiryContext::new(&recorded, jiff::Timestamp::now());
    let mut batches = Vec::new();

    for root in trash_roots(ctx)? {
        let trash = Trash::new(root.clone());
        let entries = trash
            .entries_matching(|entry, meta| should_purge_expired_entry(entry, meta, expiry))
            .with_context(|| format!("failed to select expired trash in {}", root.display()))?;
        let entries = entries
            .into_iter()
            .map(PlannedTrashEntry::capture)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("failed to snapshot expired trash in {}", root.display()))?;
        batches.push(PurgePlanBatch {
            trash_root: root,
            entries,
        });
    }
    Ok(ExpiryPlan { batches })
}

pub(crate) fn execute_expiry_plan(ctx: &DetectCtx, plan: &ExpiryPlan) -> PurgeReport {
    let mut all = PurgeReport::default();
    for batch in &plan.batches {
        all.extend(purge_trash_entries(
            PurgeBatch::new(ctx, "clean", &batch.trash_root),
            batch.entries.clone(),
        ));
        if let Err(err) = purge_expired_claims(&batch.trash_root) {
            all.failed
                .push((batch.trash_root.join(".claims"), err.to_string()));
        }
    }
    all
}

pub(crate) fn plan_all_trash(ctx: &DetectCtx) -> Result<TrashPurgePlan> {
    let mut batches = Vec::new();
    for root in trash_roots(ctx)? {
        let trash = Trash::new(root.clone());
        let mut selected = interrupted_purge_claims(&root).with_context(|| {
            format!("failed to select interrupted purges in {}", root.display())
        })?;
        selected.extend(
            trash
                .entries_matching(|_, _| true)
                .with_context(|| format!("failed to select trash in {}", root.display()))?,
        );
        let entries = selected
            .into_iter()
            .map(PlannedTrashEntry::capture)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("failed to snapshot trash in {}", root.display()))?;
        batches.push(PurgePlanBatch {
            trash_root: root,
            entries,
        });
    }
    Ok(TrashPurgePlan { batches })
}

pub(crate) fn execute_purge_plan(
    ctx: &DetectCtx,
    command: &str,
    plan: TrashPurgePlan,
) -> PurgeReport {
    let mut all = PurgeReport::default();
    for batch in plan.batches {
        all.extend(purge_trash_entries(
            PurgeBatch::new(ctx, command, &batch.trash_root),
            batch.entries,
        ));
        if let Err(error) = purge_expired_claims(&batch.trash_root) {
            all.failed
                .push((batch.trash_root.join(".claims"), error.to_string()));
        }
    }
    all
}

pub(crate) fn purge_trash_entries(
    batch: PurgeBatch<'_>,
    entries: Vec<PlannedTrashEntry>,
) -> PurgeReport {
    let run = PurgeRun::new(batch);
    let mut report = PurgeReport::default();
    for entry in entries {
        let path = entry.path().to_path_buf();
        match ClaimedTrashEntry::acquire(entry, run.batch.trash_root) {
            Ok(claimed) => run.purge(claimed, &mut report),
            Err(error) => report_claim_failure(path, error, &mut report),
        }
    }
    report
}

struct PurgeRun<'a> {
    batch: PurgeBatch<'a>,
    log: OperationLog,
}

impl<'a> PurgeRun<'a> {
    fn new(batch: PurgeBatch<'a>) -> Self {
        let log = OperationLog::new(batch.ctx);
        Self { batch, log }
    }

    fn purge(&self, claimed: ClaimedTrashEntry, report: &mut PurgeReport) {
        let entry = claimed.original().to_path_buf();
        let operation = PurgeOperation::new(self.batch.command, entry, self.batch.reclamation_id);
        let result = purge_claimed(operation, claimed, |operation, outcome| {
            append_record(&self.log, operation, outcome)
        });
        report.extend(result);
    }
}
