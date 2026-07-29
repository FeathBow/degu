mod claims;
mod entries;
mod expiry;
mod identity;
mod operation_log;
mod purge;
mod reconcile;
mod stage;
mod state_read;
mod storage;
mod summary;
mod trash;

use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::safety::Guard;
use std::path::{Path, PathBuf};

pub(crate) use entries::TrashEntry;
pub(crate) use expiry::TRASH_RETENTION_DAYS;
pub(crate) use identity::EntryIdentity;
pub(crate) use purge::{ExpiryPlan, PurgeReport, TrashPurgePlan};
pub(crate) use stage::{
    CapturedCleanPlan, CleanExecution, CleanExecutionFailure, cleaned_resources,
};

pub(crate) struct Lifecycle {
    ctx: DetectCtx,
}

impl Lifecycle {
    pub(crate) fn new(ctx: &DetectCtx) -> Self {
        Self { ctx: ctx.clone() }
    }

    pub(crate) fn resolve_trash_dir(&self, path: &Path) -> Result<PathBuf, String> {
        storage::resolve_trash_dir(&self.ctx, path)
    }

    pub(crate) fn trash_dir(&self) -> PathBuf {
        storage::trash_dir_state(&self.ctx)
    }

    pub(crate) fn trash_summary(&self) -> Result<Option<summary::TrashSummary>> {
        summary::trash_summary(&self.ctx)
    }

    pub(crate) fn trash_entries(&self) -> Result<Vec<TrashEntry>> {
        entries::trash_entries(&self.ctx)
    }

    pub(crate) fn plan_expired(&self) -> Result<ExpiryPlan> {
        purge::plan_expired_trash(&self.ctx)
    }

    pub(crate) fn operations(&self) -> Result<Vec<degu_core::oplog::OpRecord>> {
        operation_log::OperationLog::new(&self.ctx).read()
    }

    pub(crate) fn lock(self) -> Result<MutationSession> {
        let mutation_lock = storage::acquire_mutation_lock(&self.ctx)?;
        Ok(MutationSession {
            lifecycle: self,
            _mutation_lock: mutation_lock,
        })
    }
}

pub(crate) struct MutationSession {
    lifecycle: Lifecycle,
    _mutation_lock: std::fs::File,
}

impl MutationSession {
    pub(crate) fn add_trash_roots_to_guard(
        &self,
        findings: &[Finding],
        guard: &mut Guard,
    ) -> Result<()> {
        storage::add_resolved_trash_roots_to_guard(&self.lifecycle.ctx, findings, guard)
    }

    pub(crate) fn execute_clean(
        &self,
        plan: &CapturedCleanPlan,
        purge: bool,
        recheck: &dyn Fn(&Finding) -> Result<(), String>,
    ) -> Vec<CleanExecution> {
        stage::execute_clean(&self.lifecycle.ctx, plan, purge, recheck)
    }

    pub(crate) fn plan_purge_all(&self) -> Result<TrashPurgePlan> {
        purge::plan_all_trash(&self.lifecycle.ctx)
    }

    pub(crate) fn execute_purge_all(&self, plan: TrashPurgePlan) -> PurgeReport {
        purge::execute_purge_plan(&self.lifecycle.ctx, "trash purge", plan)
    }

    pub(crate) fn plan_expired(&self) -> Result<ExpiryPlan> {
        purge::plan_expired_trash(&self.lifecycle.ctx)
    }

    pub(crate) fn execute_expiry(&self, plan: &ExpiryPlan) -> PurgeReport {
        purge::execute_expiry_plan(&self.lifecycle.ctx, plan)
    }
}
