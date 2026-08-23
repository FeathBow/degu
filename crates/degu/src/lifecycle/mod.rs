mod claims;
mod entries;
mod expiry;
mod identity;
mod journal;
mod mount;
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
use degu_core::activation::{
    ActivatedReadyStagingEngine, MutationStoreActivation, UnsupportedNeverActivatedLease,
};
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::safety::Guard;
use degu_core::staging::{
    ForwardDirectoryIdentityProbe, VerifiedPurgeRequest, probe_forward_directory_identity,
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
                    let (engine, report) = activated.open_staging().with_context(|| {
                        format!(
                            "failed to lease and replay activated sealed-staging recovery store {}",
                            store_path.display()
                        )
                    })?;
                    // v11 transactions reopen their recorded mount-domain
                    // anchor; v10 transactions retain the canonical-HOME arm.
                    // In both cases the pathname only obtains candidate FDs for
                    // the core's fresh mount, identity, ACL, and binding checks.
                    let recovery_home = self.ctx.home.clone();
                    let (ready, _) = engine
                        .recover_startup(report, |_, metadata| {
                            mount::metadata_anchors(&recovery_home, metadata)
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
    sealed_staging: Option<ActivatedReadyStagingEngine>,
    forward_clean: bool,
    // Exact sealed entries already removed through held authority. Legacy code
    // reports these complete and never claims the now-absent pathname.
    authority_purged: std::collections::HashSet<PathBuf>,
    _unsupported_legacy_lease: Option<UnsupportedNeverActivatedLease>,
}

#[derive(Debug)]
enum SealedPurgeOutcome {
    Legacy,
    Purged,
    RetainedUnsupported(String),
    Blocked(String),
}

#[derive(Default)]
struct SealedPurgeBatchOutcome {
    retained: std::collections::HashMap<PathBuf, String>,
    blocked: Option<String>,
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
            self.sealed_staging.as_deref_mut()
        } else {
            None
        };
        stage::execute_clean(&self.lifecycle.ctx, plan, purge, recheck, sealed_staging)
    }

    pub(crate) fn plan_purge_all(&self) -> Result<TrashPurgePlan> {
        purge::plan_all_trash(&self.lifecycle.ctx)
    }

    /// Post-confirmation classification and sealed execution. Unsupported
    /// proof topologies are retained per entry and do not prevent unrelated
    /// work. A recovery blocker still stops the batch before any later legacy
    /// claim, deletion, or housekeeping.
    pub(crate) fn execute_explicit_purge_all(&mut self, mut plan: TrashPurgePlan) -> PurgeReport {
        let sealed = self.execute_sealed_purge_batch(plan.entries());
        let purged = plan.take_already_purged(&self.authority_purged);
        if let Some(reason) = sealed.blocked {
            return PurgeReport {
                purged,
                failed: plan
                    .entries()
                    .map(|path| {
                        let reason = sealed.retained.get(path).unwrap_or(&reason).clone();
                        (path.to_path_buf(), reason)
                    })
                    .collect(),
            };
        }
        let blocker = |path: &Path| {
            sealed
                .retained
                .get(path)
                .cloned()
                .or_else(|| self.sealed_entry_block(path))
        };
        let mut report = PurgeReport {
            purged,
            failed: Vec::new(),
        };
        let legacy = purge::execute_purge_plan(&self.lifecycle.ctx, "trash purge", plan, &blocker);
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
        let sealed = self.execute_sealed_purge_batch(plan.entries());
        if let Some(reason) = sealed.blocked {
            let (purged, failed): (Vec<_>, Vec<_>) = plan
                .entries()
                .map(Path::to_path_buf)
                .partition(|path| self.authority_purged.contains(path));
            return PurgeReport {
                purged,
                failed: failed
                    .into_iter()
                    .map(|path| {
                        let reason = sealed.retained.get(&path).unwrap_or(&reason).clone();
                        (path, reason)
                    })
                    .collect(),
            };
        }
        let blocker = |path: &Path| {
            sealed
                .retained
                .get(path)
                .cloned()
                .or_else(|| self.sealed_entry_block(path))
        };
        purge::execute_expiry_plan(&self.lifecycle.ctx, plan, &blocker, &self.authority_purged)
    }

    fn execute_sealed_purge_batch<'a>(
        &mut self,
        paths: impl Iterator<Item = &'a Path>,
    ) -> SealedPurgeBatchOutcome {
        let mut outcome = SealedPurgeBatchOutcome::default();
        for path in paths.map(Path::to_path_buf).collect::<Vec<_>>() {
            match self.execute_sealed_purge_entry(&path) {
                SealedPurgeOutcome::Legacy => {}
                SealedPurgeOutcome::Purged => {
                    self.authority_purged.insert(path);
                }
                SealedPurgeOutcome::RetainedUnsupported(reason) => {
                    outcome.retained.insert(path, reason);
                }
                SealedPurgeOutcome::Blocked(reason) => {
                    outcome.blocked = Some(format!(
                        "{reason}; no later claim, deletion, or housekeeping was attempted for this batch"
                    ));
                    break;
                }
            }
        }
        outcome
    }

    pub(crate) fn undo_latest(&mut self) -> Result<Option<UndoReport>> {
        // Snapshot only the legacy namespace blocker before mutably borrowing
        // the exact engine. Verified undo consumes WAL-minted tokens, never
        // this path projection.
        let sealed_destinations = self
            .sealed_staging
            .as_ref()
            .into_iter()
            .flat_map(|engine| engine.production_entries())
            .filter(|entry| sealed_mutation_authority_active(entry.state()))
            .map(|entry| {
                (
                    mount::entry_anchor(&self.lifecycle.ctx.home, &entry)
                        .ok()
                        .map(|anchor| {
                            anchor
                                .join(entry.destination_parent().relative_path())
                                .join(entry.destination_basename())
                        }),
                    entry.root_identity(),
                )
            })
            .collect::<Vec<_>>();
        let anchors_authenticated = sealed_destinations
            .iter()
            .all(|(destination, _)| destination.is_some());
        let blocker = |path: &Path| {
            sealed_legacy_undo_block(path, &sealed_destinations, anchors_authenticated)
        };
        undo::undo_latest(
            &self.lifecycle.ctx,
            self.sealed_staging.as_deref_mut(),
            &blocker,
        )
    }

    /// Executes the sealed portion of one purge decision. Unsupported hardlink
    /// topology is a typed retained result; all uncertainty remains a
    /// fail-closed blocker and an unassociated entry remains legacy work.
    fn execute_sealed_purge_entry(&mut self, path: &Path) -> SealedPurgeOutcome {
        let Some(engine) = self.sealed_staging.as_mut() else {
            return SealedPurgeOutcome::Legacy;
        };
        let entries = engine.production_entries();
        if entries.is_empty() {
            return SealedPurgeOutcome::Legacy;
        }
        let normalized = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => match std::fs::canonicalize(parent) {
                Ok(parent) => parent.join(name),
                Err(error) => {
                    return SealedPurgeOutcome::Blocked(format!(
                        "sealed staging could not authenticate the explicit purge parent: {error}"
                    ));
                }
            },
            _ => {
                return SealedPurgeOutcome::Blocked(
                    "sealed staging rejected an unlocatable explicit purge entry".into(),
                );
            }
        };
        let mut matched = None;
        for entry in entries
            .into_iter()
            .filter(|entry| sealed_mutation_authority_active(entry.state()))
        {
            let anchor = match mount::entry_anchor(&self.lifecycle.ctx.home, &entry) {
                Ok(anchor) => anchor,
                Err(error) => {
                    return SealedPurgeOutcome::Blocked(format!(
                        "sealed staging could not authenticate a mount-domain anchor for explicit purge: {error}"
                    ));
                }
            };
            let expected = anchor
                .join(entry.destination_parent().relative_path())
                .join(entry.destination_basename());
            if expected == normalized {
                matched = Some((entry, anchor));
                break;
            }
        }
        let Some((entry, anchor)) = matched else {
            return self
                .sealed_entry_block(path)
                .map_or(SealedPurgeOutcome::Legacy, SealedPurgeOutcome::Blocked);
        };
        if !matches!(
            entry.state(),
            degu_core::authority::TransactionState::VerifiedCommitted
                | degu_core::authority::TransactionState::Purgeable
        ) {
            return if sealed_mutation_authority_active(entry.state()) {
                SealedPurgeOutcome::Blocked(format!(
                    "sealed staging transaction is {:?} and cannot admit explicit purge",
                    entry.state()
                ))
            } else {
                SealedPurgeOutcome::Legacy
            };
        }
        let (source_anchor, destination_anchor) = match mount::open_pair_fds(&anchor) {
            Ok(anchors) => anchors,
            Err(error) => {
                return SealedPurgeOutcome::Blocked(format!(
                    "failed to retain explicit purge mount-domain anchors: {error}"
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
                        SealedPurgeOutcome::Purged
                    }
                    Err(error) => SealedPurgeOutcome::Blocked(format!(
                        "sealed staging explicit purge execution failed during {} ({:?}): {error}",
                        error.stage(),
                        error.disposition()
                    )),
                }
            }
            Err(error)
                if matches!(
                    error.disposition(),
                    degu_core::staging::VerifiedPurgeFailureDisposition::NotStarted
                ) && error.is_unsupported_internal_hard_links() =>
            {
                SealedPurgeOutcome::RetainedUnsupported(format!(
                    "retained and remains undoable because permanent purge is unsupported: {error}"
                ))
            }
            Err(error) => SealedPurgeOutcome::Blocked(format!(
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
            let anchor = match mount::entry_anchor(&self.lifecycle.ctx.home, &entry) {
                Ok(anchor) => anchor,
                Err(error) => {
                    return Some(format!(
                        "sealed-staging authority could not authenticate a mount-domain anchor: {error}; no claim, rename, or deletion was attempted"
                    ));
                }
            };
            let expected = anchor
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
    sealed_destinations: &[(Option<PathBuf>, degu_core::seal::wal::StrongObjectIdentity)],
    anchors_authenticated: bool,
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
    if (!anchors_authenticated || normalized.is_none()) && !sealed_destinations.is_empty() {
        Some(
            "sealed staging authority could not authenticate a mount-domain anchor or this legacy undo path"
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
