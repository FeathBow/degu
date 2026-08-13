mod claims;
mod entries;
mod expiry;
mod identity;
mod journal;
mod purge;
mod reconcile;
mod records;
mod stage;
mod storage;
mod summary;
mod trash;
mod undo;

#[cfg(test)]
mod startup_tests;

use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::safety::Guard;
use degu_core::sealed_staging::{ReadyStagingEngine, SealedStagingEngine, StartupRecoveryAnchors};
use degu_core::store_activation::{MutationStoreActivation, UnsupportedNeverActivatedLease};
use std::path::{Path, PathBuf};

pub(crate) use entries::TrashEntry;
pub(crate) use expiry::TRASH_RETENTION_DAYS;
pub(crate) use identity::EntryIdentity;
pub(crate) use purge::{ExpiryPlan, PurgeReport, TrashPurgePlan};
pub(crate) use stage::{
    CapturedCleanPlan, CleanExecution, CleanExecutionFailure, cleaned_resources,
};
pub(crate) use undo::{UndoAmbiguousEntry, UndoEntry, UndoFailedEntry, UndoLogFailure, UndoReport};

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
        journal::OperationLog::new(&self.ctx).read()
    }

    pub(crate) fn lock(self) -> Result<MutationSession> {
        let mutation_lock = storage::acquire_mutation_lock(&self.ctx)?;
        let (sealed_staging, unsupported_legacy_lease) =
            match storage::sealed_staging_store_for_mutation(&self.ctx)? {
                MutationStoreActivation::Activated(activated) => {
                    let store_path = activated.locator().to_path_buf();
                    let (engine, report) =
                    SealedStagingEngine::open(activated.store()).with_context(|| {
                        format!(
                            "failed to lease and replay activated sealed-staging recovery store {}",
                            store_path.display()
                        )
                    })?;
                    // The first production anchor policy is deliberately narrow:
                    // locators must have been recorded relative to canonical HOME
                    // on one certified local mount. Redirected/cross-mount roots stay
                    // blocked until a later association slice consumes a mount-root policy.
                    let recovery_home = self.ctx.home.clone();
                    let (ready, _) = engine
                .recover_startup(report, |_, _| {
                    let open_home = || {
                        rustix::fs::open(
                            &recovery_home,
                            rustix::fs::OFlags::RDONLY
                                | rustix::fs::OFlags::DIRECTORY
                                | rustix::fs::OFlags::NOFOLLOW
                                | rustix::fs::OFlags::CLOEXEC,
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(std::io::Error::from)
                    };
                    Ok(StartupRecoveryAnchors::new(open_home()?, open_home()?))
                })
                .with_context(|| {
                    format!(
                        "sealed-staging startup recovery did not reach a safe terminal state in {}",
                        store_path.display()
                    )
                })?;
                    (Some(ready), None)
                }
                MutationStoreActivation::UnsupportedNeverActivated(lease) => (None, Some(lease)),
            };
        Ok(MutationSession {
            lifecycle: self,
            _mutation_lock: mutation_lock,
            _sealed_staging: sealed_staging,
            _unsupported_legacy_lease: unsupported_legacy_lease,
        })
    }
}

pub(crate) struct MutationSession {
    lifecycle: Lifecycle,
    _mutation_lock: std::fs::File,
    // When activated, retains the exact WAL lease for the entire production
    // mutation session. `None` is allowed only for authenticated
    // UnsupportedNeverActivated. Forward staging remains deliberately unwired.
    _sealed_staging: Option<ReadyStagingEngine>,
    _unsupported_legacy_lease: Option<UnsupportedNeverActivatedLease>,
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

    pub(crate) fn undo_latest(&self) -> Result<Option<UndoReport>> {
        undo::undo_latest(&self.lifecycle.ctx)
    }
}
