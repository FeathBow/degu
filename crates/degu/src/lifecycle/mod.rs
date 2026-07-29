mod claims;
mod entries;
mod expiry;
mod operation_log;
mod reconcile;
mod stage;
mod state_read;
mod storage;
mod summary;
mod trash;

use anyhow::Result;
use degu_core::ecosystem::DetectCtx;

pub(crate) use entries::TrashEntry;
pub(crate) use stage::CapturedCleanPlan;

pub(crate) struct Lifecycle {
    ctx: DetectCtx,
}

impl Lifecycle {
    pub(crate) fn new(ctx: &DetectCtx) -> Self {
        Self { ctx: ctx.clone() }
    }

    pub(crate) fn trash_summary(&self) -> Result<Option<summary::TrashSummary>> {
        summary::trash_summary(&self.ctx)
    }

    pub(crate) fn trash_entries(&self) -> Result<Vec<TrashEntry>> {
        entries::trash_entries(&self.ctx)
    }

    pub(crate) fn operations(&self) -> Result<Vec<degu_core::oplog::OpRecord>> {
        operation_log::OperationLog::new(&self.ctx).read()
    }
}
