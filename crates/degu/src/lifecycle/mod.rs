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
use degu_core::activation::{MutationStoreActivation, UnsupportedNeverActivatedLease};
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::safety::Guard;
use degu_core::sealed_staging::{
    ForwardDirectoryIdentityProbe, ReadyStagingEngine, SealedStagingEngine, StartupRecoveryAnchors,
    VerifiedPurgeRequest, probe_forward_directory_identity,
};
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

    pub(crate) fn add_trash_roots_to_guard(
        &self,
        findings: &[Finding],
        guard: &mut Guard,
    ) -> Result<()> {
        storage::add_resolved_trash_roots_to_guard(&self.ctx, findings, guard)
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
        self.lock_with_forward_clean(false)
    }

    pub(crate) fn lock_for_clean(self, _direct_purge: bool) -> Result<MutationSession> {
        // Both restorable clean and explicit clean --purge must enter the exact
        // forward coordinator. It may mint PurgeAuthority but cannot consume it.
        self.lock_with_forward_clean(true)
    }

    fn lock_with_forward_clean(self, forward_clean: bool) -> Result<MutationSession> {
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
                    // blocked because this path consumes no mount-root association policy.
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
            sealed_staging,
            forward_clean,
            authority_purged: std::collections::HashSet::new(),
            _unsupported_legacy_lease: unsupported_legacy_lease,
        })
    }
}

pub(crate) struct MutationSession {
    lifecycle: Lifecycle,
    _mutation_lock: std::fs::File,
    // When activated, retains the exact WAL lease for the entire production
    // mutation session. `None` is allowed only for authenticated
    // UnsupportedNeverActivated. Direct purge keeps the lease for conflict
    // checks but deliberately does not grant the forward coordinator deletion.
    sealed_staging: Option<ReadyStagingEngine>,
    forward_clean: bool,
    // Exact sealed entries already removed through held authority. Legacy code
    // reports these complete and never claims the now-absent pathname.
    authority_purged: std::collections::HashSet<PathBuf>,
    _unsupported_legacy_lease: Option<UnsupportedNeverActivatedLease>,
}

impl MutationSession {
    pub(crate) fn uses_sealed_staging_for_clean(&self) -> bool {
        self.forward_clean
            && self.sealed_staging.is_some()
            && !(cfg!(debug_assertions) && integration_test_legacy_clean())
    }

    pub(crate) fn add_trash_roots_to_guard(
        &self,
        findings: &[Finding],
        guard: &mut Guard,
    ) -> Result<()> {
        storage::add_resolved_trash_roots_to_guard(&self.lifecycle.ctx, findings, guard)
    }

    pub(crate) fn execute_clean(
        &mut self,
        plan: &CapturedCleanPlan,
        purge: bool,
        recheck: &dyn Fn(&Finding) -> Result<(), String>,
    ) -> Result<Vec<CleanExecution>> {
        let uses_sealed_staging = self.uses_sealed_staging_for_clean();
        let sealed_staging = if uses_sealed_staging {
            self.sealed_staging.as_mut()
        } else {
            None
        };
        stage::execute_clean(&self.lifecycle.ctx, plan, purge, recheck, sealed_staging)
    }

    pub(crate) fn plan_purge_all(&self) -> Result<TrashPurgePlan> {
        purge::plan_all_trash(&self.lifecycle.ctx)
    }

    /// Post-confirmation classification and sealed execution. Each matching
    /// entry is removed only through freshly rebound authority; any recovery
    /// block stops the remaining batch before legacy claim or housekeeping.
    pub(crate) fn authorize_purge_all(&mut self, plan: &TrashPurgePlan) -> Option<String> {
        for path in plan.entries() {
            if let Some(reason) = self.classify_explicit_purge(path) {
                return Some(format!(
                    "{reason}; no later claim, deletion, or housekeeping was attempted for this batch"
                ));
            }
        }
        None
    }

    pub(crate) fn execute_explicit_purge_all(&mut self, mut plan: TrashPurgePlan) -> PurgeReport {
        let blocked = self.authorize_purge_all(&plan);
        let purged = plan.take_already_purged(&self.authority_purged);
        if let Some(reason) = blocked {
            return PurgeReport {
                purged,
                failed: plan
                    .entries()
                    .map(|path| (path.to_path_buf(), reason.clone()))
                    .collect(),
            };
        }
        let mut report = PurgeReport {
            purged,
            failed: Vec::new(),
        };
        let legacy = self.execute_purge_all(plan);
        report.purged.extend(legacy.purged);
        report.failed.extend(legacy.failed);
        report
    }

    pub(crate) fn execute_purge_all(&self, plan: TrashPurgePlan) -> PurgeReport {
        let blocker = |path: &Path| self.sealed_entry_block(path);
        purge::execute_purge_plan(&self.lifecycle.ctx, "trash purge", plan, &blocker)
    }

    pub(crate) fn plan_expired(&self) -> Result<ExpiryPlan> {
        purge::plan_expired_trash(&self.lifecycle.ctx)
    }

    pub(crate) fn execute_expiry(&mut self, plan: &ExpiryPlan) -> PurgeReport {
        for path in plan.entries().map(Path::to_path_buf).collect::<Vec<_>>() {
            if let Some(reason) = self.classify_explicit_purge(&path) {
                let reason =
                    format!("{reason}; no later expiry mutation or housekeeping was attempted");
                let (purged, failed): (Vec<_>, Vec<_>) = plan
                    .entries()
                    .map(Path::to_path_buf)
                    .partition(|path| self.authority_purged.contains(path));
                return PurgeReport {
                    purged,
                    failed: failed
                        .into_iter()
                        .map(|path| (path, reason.clone()))
                        .collect(),
                };
            }
        }
        let blocker = |path: &Path| self.sealed_entry_block(path);
        purge::execute_expiry_plan(&self.lifecycle.ctx, plan, &blocker, &self.authority_purged)
    }

    pub(crate) fn undo_latest(&mut self) -> Result<Option<UndoReport>> {
        // Snapshot only the legacy namespace blocker before mutably borrowing
        // the exact engine. Verified undo consumes WAL-minted tokens, never
        // this path projection.
        let canonical_home = std::fs::canonicalize(&self.lifecycle.ctx.home).ok();
        let sealed_destinations = self
            .sealed_staging
            .as_ref()
            .into_iter()
            .flat_map(ReadyStagingEngine::production_entries)
            .filter(|entry| sealed_mutation_authority_active(entry.state()))
            .map(|entry| {
                (
                    canonical_home.as_ref().map(|home| {
                        home.join(entry.destination_parent().relative_path())
                            .join(entry.destination_basename())
                    }),
                    entry.root_identity(),
                )
            })
            .collect::<Vec<_>>();
        let home_authenticated = canonical_home.is_some();
        let blocker =
            |path: &Path| sealed_legacy_undo_block(path, &sealed_destinations, home_authenticated);
        undo::undo_latest(&self.lifecycle.ctx, self.sealed_staging.as_mut(), &blocker)
    }

    /// Returns a blocker for any sealed candidate that was not durably purged.
    /// An unassociated legacy entry returns `None`; every sealed admission or
    /// execution failure remains outside the legacy claim/delete path.
    fn classify_explicit_purge(&mut self, path: &Path) -> Option<String> {
        let engine = self.sealed_staging.as_mut()?;
        let entries = engine.production_entries();
        if entries.is_empty() {
            return None;
        }
        let canonical_home = match std::fs::canonicalize(&self.lifecycle.ctx.home) {
            Ok(home) => home,
            Err(error) => {
                return Some(format!(
                    "sealed staging could not authenticate canonical HOME for explicit purge: {error}"
                ));
            }
        };
        let normalized = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => match std::fs::canonicalize(parent) {
                Ok(parent) => parent.join(name),
                Err(error) => {
                    return Some(format!(
                        "sealed staging could not authenticate the explicit purge parent: {error}"
                    ));
                }
            },
            _ => return Some("sealed staging rejected an unlocatable explicit purge entry".into()),
        };
        let Some(entry) = entries.into_iter().find(|entry| {
            canonical_home
                .join(entry.destination_parent().relative_path())
                .join(entry.destination_basename())
                == normalized
        }) else {
            return self.sealed_entry_block(path);
        };
        if !matches!(
            entry.state(),
            degu_core::authority::TransactionState::VerifiedCommitted
                | degu_core::authority::TransactionState::Purgeable
        ) {
            return sealed_mutation_authority_active(entry.state()).then(|| {
                format!(
                    "sealed staging transaction is {:?} and cannot admit explicit purge",
                    entry.state()
                )
            });
        }
        let open_home = || {
            rustix::fs::open(
                &canonical_home,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)
        };
        let (source_anchor, destination_anchor) = match (open_home(), open_home()) {
            (Ok(source), Ok(destination)) => (source, destination),
            (Err(error), _) | (_, Err(error)) => {
                return Some(format!(
                    "failed to retain explicit purge HOME anchors: {error}"
                ));
            }
        };
        let request = VerifiedPurgeRequest::new(
            entry.transaction(),
            entry.reclamation_id().to_owned(),
            source_anchor,
            destination_anchor,
        );
        match engine.request_verified_purge(request) {
            Ok(authority) => {
                // The next operation immediately consumes the one-use authority;
                // no path, JSONL, or diagnostic step intervenes.
                match engine.execute_verified_purge(authority) {
                    Ok(commit) => {
                        debug_assert_eq!(commit.transaction(), entry.transaction());
                        self.authority_purged.insert(path.to_path_buf());
                        None
                    }
                    Err(error) => Some(format!(
                        "sealed staging explicit purge execution failed during {} ({:?}): {error}",
                        error.stage(),
                        error.disposition()
                    )),
                }
            }
            Err(error) => Some(format!(
                "sealed staging explicit purge admission failed during {} ({:?}): {error}",
                error.stage(),
                error.disposition()
            )),
        }
    }

    /// Returns a reason only when the exact leased WAL prevents this legacy
    /// entry from being mutated. Absence of an association preserves legacy
    /// behavior; inspection uncertainty fails closed.
    fn sealed_entry_block(&self, path: &Path) -> Option<String> {
        let engine = self.sealed_staging.as_ref()?;
        let entries = engine.production_entries();
        if entries.is_empty() {
            return None;
        }
        let canonical_home = match std::fs::canonicalize(&self.lifecycle.ctx.home) {
            Ok(home) => home,
            Err(error) => {
                return Some(format!(
                    "sealed-staging authority could not authenticate canonical HOME before mutation: {error}; no claim, rename, or deletion was attempted"
                ));
            }
        };
        let normalized = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => match std::fs::canonicalize(parent) {
                Ok(parent) => parent.join(name),
                Err(error) => {
                    return Some(format!(
                        "sealed-staging authority could not authenticate the entry parent before mutation: {error}; no claim, rename, or deletion was attempted"
                    ));
                }
            },
            _ => {
                return Some(
                    "sealed-staging authority rejected an unlocatable entry; no claim, rename, or deletion was attempted".to_string(),
                );
            }
        };

        for entry in entries
            .into_iter()
            .filter(|entry| sealed_mutation_authority_active(entry.state()))
        {
            let expected = canonical_home
                .join(entry.destination_parent().relative_path())
                .join(entry.destination_basename());
            if normalized == expected {
                return Some(format!(
                    "sealed-staging WAL retains exclusive mutation authority for reclamation '{}' ({:?}); no claim, rename, or deletion was attempted",
                    entry.reclamation_id(),
                    entry.state()
                ));
            }
            match probe_forward_directory_identity(path, entry.root_identity()) {
                ForwardDirectoryIdentityProbe::Match => {
                    return Some(format!(
                        "sealed-staging WAL retains exclusive mutation authority for the exact object in reclamation '{}' ({:?}); no claim, rename, or deletion was attempted",
                        entry.reclamation_id(),
                        entry.state()
                    ));
                }
                ForwardDirectoryIdentityProbe::Mismatch => {}
                ForwardDirectoryIdentityProbe::Uncertain(error) => {
                    return Some(format!(
                        "sealed-staging authority could not strongly inspect this entry: {error}; no claim, rename, or deletion was attempted"
                    ));
                }
            }
        }
        None
    }
}

fn sealed_mutation_authority_active(state: degu_core::authority::TransactionState) -> bool {
    !matches!(
        state,
        degu_core::authority::TransactionState::Restored
            | degu_core::authority::TransactionState::RolledBack
            | degu_core::authority::TransactionState::Purged
    )
}

fn sealed_legacy_undo_block(
    path: &Path,
    sealed_destinations: &[(Option<PathBuf>, degu_core::seal_wal::StrongObjectIdentity)],
    home_authenticated: bool,
) -> Option<String> {
    let normalized = path
        .parent()
        .zip(path.file_name())
        .and_then(|(parent, name)| {
            std::fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(name))
        });
    if let Some(path) = normalized.as_ref()
        && sealed_destinations
            .iter()
            .any(|(expected, _)| expected.as_ref() == Some(path))
    {
        return Some("sealed staging WAL retains exclusive authority for this entry".to_string());
    }
    for (_, identity) in sealed_destinations {
        match probe_forward_directory_identity(path, *identity) {
            ForwardDirectoryIdentityProbe::Match => {
                return Some(
                    "sealed staging WAL retains exclusive authority for this exact object"
                        .to_string(),
                );
            }
            ForwardDirectoryIdentityProbe::Mismatch => {}
            ForwardDirectoryIdentityProbe::Uncertain(error) => {
                return Some(format!(
                    "sealed staging authority could not strongly inspect this legacy undo path: {error}"
                ));
            }
        }
    }
    if (!home_authenticated || normalized.is_none()) && !sealed_destinations.is_empty() {
        Some(
            "sealed staging authority could not authenticate HOME or this legacy undo path"
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(debug_assertions)]
fn integration_test_legacy_clean() -> bool {
    std::env::var_os("DEGU_INTEGRATION_TEST_LEGACY_CLEAN").is_some()
}

#[cfg(not(debug_assertions))]
fn integration_test_legacy_clean() -> bool {
    false
}
