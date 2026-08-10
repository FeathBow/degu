mod scan;

use self::scan::RootScan;
use super::adapters::{
    ExclusionClaims, PreparedAdapter, PreparedAdapters, RootResolutionPolicy, prepare_adapters,
};
use super::progress::ScanRootProgress;
use super::roots::artifact_roots;
use super::{Collection, CollectionRequest, CollectionSection};
use crate::selection::SourceSelection;
use anyhow::Result;
use degu_adapters::discovery::{ProjectSources, ValidatedProjectRoot};
use degu_adapters::{AdapterScope, CachedirTagProbe, RegisteredAdapter};
use degu_core::config::Config;
use degu_core::ecosystem::{DetectCtx, Root, RootProvenance, ScanPriority};
use degu_core::safety::ProtectionPolicy;
use std::collections::HashSet;
use std::path::PathBuf;

pub(super) struct Collector<'a> {
    ctx: &'a DetectCtx,
    config: &'a Config,
    progress: &'a ScanRootProgress,
}

impl<'a> Collector<'a> {
    pub(super) fn new(
        ctx: &'a DetectCtx,
        config: &'a Config,
        progress: &'a ScanRootProgress,
    ) -> Self {
        Self {
            ctx,
            config,
            progress,
        }
    }

    pub(super) fn collect(self, request: CollectionRequest) -> Result<Collection> {
        let artifacts = if request.sources.includes_project_sources() {
            artifact_roots(self.ctx, request.project_roots, self.config)?
        } else {
            Vec::new()
        };
        let mut collection = Collection::new(
            request.sources.selects_findings(),
            request.sources.selects_runtime(),
        );
        if self.ctx.deadline_elapsed() {
            collection.mark_all_requested_truncated();
            return Ok(collection.finish());
        }
        let prepared = self.prepare_registered_adapters(&request.sources, &artifacts)?;
        if prepared.truncated || self.ctx.deadline_elapsed() {
            collection.mark_all_requested_truncated();
            return Ok(collection.finish());
        }
        mark_incomplete_adapters(&prepared.enabled, &mut collection)?;
        let project_sources = request.sources.project_sources();
        let schedule = scan_schedule(self.ctx, &prepared, &artifacts, project_sources);
        self.progress.set_total(schedule.len());
        let scope = DiscoveryScope {
            claimed_roots: &prepared.claimed_roots,
            exclusion_claims: &prepared.exclusion_claims,
            sources: project_sources,
        };
        self.scan_roots(&schedule, scope, &mut collection)?;
        Ok(collection.finish())
    }

    fn scan_roots(
        &self,
        schedule: &[PreparedRoot<'_>],
        scope: DiscoveryScope<'_>,
        collection: &mut Collection,
    ) -> Result<()> {
        for (index, item) in schedule.iter().enumerate() {
            if self.ctx.deadline_elapsed() {
                mark_pending_roots(&schedule[index..], collection);
                return Ok(());
            }
            collection.begin_root(self.progress);
            let result = self.scan_scheduled_root(item, scope)?;
            let truncated = result.scan.is_truncated();
            collection.add(result)?;
            if truncated {
                mark_pending_roots(&schedule[index + 1..], collection);
                return Ok(());
            }
        }
        Ok(())
    }

    fn prepare_registered_adapters(
        &self,
        sources: &SourceSelection,
        artifacts: &[ValidatedProjectRoot],
    ) -> Result<PreparedAdapters> {
        let disabled = self
            .config
            .disable
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        prepare_adapters(
            self.ctx,
            &disabled,
            RootResolutionPolicy {
                sources,
                project_claims: !artifacts.is_empty(),
            },
        )
    }

    fn scan_scheduled_root(
        &self,
        item: &PreparedRoot<'_>,
        scope: DiscoveryScope<'_>,
    ) -> Result<RootScan> {
        match item {
            PreparedRoot::Project { root, .. } => self.scan_artifact_root(root, scope),
            PreparedRoot::Adapter { adapter, root, .. } => {
                self.scan_adapter_root(AdapterRootScan {
                    registration: &adapter.registration,
                    root,
                    claims: scope.exclusion_claims,
                })
            }
        }
    }
}

struct AdapterRootScan<'a> {
    registration: &'a RegisteredAdapter,
    root: &'a Root,
    claims: &'a ExclusionClaims,
}

enum PreparedRoot<'a> {
    Project {
        root: &'a ValidatedProjectRoot,
        priority: ScanPriority,
    },
    Adapter {
        adapter: &'a PreparedAdapter,
        root: &'a Root,
        priority: ScanPriority,
    },
}

impl PreparedRoot<'_> {
    fn priority(&self) -> ScanPriority {
        match self {
            Self::Project { priority, .. } => *priority,
            Self::Adapter { priority, .. } => *priority,
        }
    }

    fn scope(&self) -> AdapterScope {
        match self {
            Self::Project { .. } => AdapterScope::Cache,
            Self::Adapter { adapter, .. } => adapter.registration.scope(),
        }
    }

    fn path(&self) -> &std::path::Path {
        match self {
            Self::Project { root, .. } => root.as_path(),
            Self::Adapter { root, .. } => &root.path,
        }
    }
}

#[derive(Clone, Copy)]
struct DiscoveryScope<'a> {
    claimed_roots: &'a [PathBuf],
    exclusion_claims: &'a ExclusionClaims,
    sources: degu_adapters::discovery::ProjectSources,
}

impl Collection {
    fn new(findings_selected: bool, runtime_selected: bool) -> Self {
        Self {
            findings: CollectionSection::new(findings_selected),
            runtime: CollectionSection::new(runtime_selected),
            roots: 0,
        }
    }

    fn begin_root(&mut self, progress: &ScanRootProgress) {
        self.roots = self.roots.saturating_add(1);
        progress.begin_root(self.roots);
    }

    fn mark_incomplete(&mut self, scope: AdapterScope) -> Result<()> {
        self.section_mut(scope).mark_incomplete()
    }

    fn mark_truncated(&mut self, scope: AdapterScope) {
        self.section_mut(scope).mark_truncated_if_requested();
    }

    fn mark_all_requested_truncated(&mut self) {
        self.findings.mark_truncated_if_requested();
        self.runtime.mark_truncated_if_requested();
    }

    fn add(&mut self, result: RootScan) -> Result<()> {
        self.section_mut(result.scope).record(
            result.findings,
            result.scan,
            result.incomplete_regions,
        )
    }

    fn section_mut(&mut self, scope: AdapterScope) -> &mut CollectionSection {
        match scope {
            AdapterScope::Cache => &mut self.findings,
            AdapterScope::Runtime => &mut self.runtime,
        }
    }

    fn finish(self) -> Self {
        Self {
            findings: self.findings.finish(),
            runtime: self.runtime.finish(),
            roots: self.roots,
        }
    }
}

fn mark_incomplete_adapters(
    adapters: &[PreparedAdapter],
    collection: &mut Collection,
) -> Result<()> {
    for adapter in adapters {
        if adapter.incomplete {
            collection.mark_incomplete(adapter.registration.scope())?;
        }
    }
    Ok(())
}

fn scan_schedule<'a>(
    ctx: &DetectCtx,
    prepared: &'a PreparedAdapters,
    projects: &'a [ValidatedProjectRoot],
    sources: ProjectSources,
) -> Vec<PreparedRoot<'a>> {
    let projects = projects.iter().map(|root| PreparedRoot::Project {
        root,
        priority: sources.scan_priority(),
    });
    let adapters = prepared.enabled.iter().flat_map(|adapter| {
        adapter.roots.iter().map(move |root| PreparedRoot::Adapter {
            adapter,
            root,
            priority: adapter.registration.ecosystem().scan_priority(root),
        })
    });
    let mut schedule = projects.chain(adapters).collect::<Vec<_>>();
    apply_root_authority_floor(ctx, &mut schedule);
    schedule.sort_by_key(PreparedRoot::priority);
    let preferred = schedule
        .iter()
        .filter(|root| root.priority() == ScanPriority::Preferred)
        .count();
    tracing::debug!(
        target: "degu",
        preferred,
        deferred = schedule.len() - preferred,
        "scan schedule prepared"
    );
    for root in &schedule {
        tracing::debug!(target: "degu", root = %root.path().display(), priority = ?root.priority(), "scheduled root");
    }
    schedule
}

// Ordering only: cleanup authority re-checks the tag and the mixed-state
// constraints after the scan, so nothing decided here can widen authority.
fn apply_root_authority_floor(ctx: &DetectCtx, schedule: &mut [PreparedRoot<'_>]) {
    // Policy or path resolution errors surface as hard failures in the scan
    // itself; the floor only loses an ordering hint.
    let mixed_state = (!ctx.deadline_elapsed())
        .then(|| ProtectionPolicy::for_mixed_state_ai(&ctx.home).ok())
        .flatten();
    for item in schedule {
        if ctx.deadline_elapsed() {
            break;
        }
        let PreparedRoot::Adapter { root, priority, .. } = item else {
            continue;
        };
        if *priority == ScanPriority::Deferred {
            continue;
        }
        if let Some(policy) = &mixed_state
            && let Ok(lexical) = std::path::absolute(&root.path)
            && matches!(policy.contains(&lexical), Ok(Some(_)))
        {
            tracing::debug!(
                root = %root.path.display(),
                "mixed-state ai root deferred behind actionable roots"
            );
            *priority = ScanPriority::Deferred;
            continue;
        }
        if root.provenance != RootProvenance::Redirect {
            continue;
        }
        match degu_adapters::probe_for_scheduling(&root.path, ctx) {
            CachedirTagProbe::Match => {}
            CachedirTagProbe::Miss | CachedirTagProbe::Incomplete => {
                tracing::debug!(
                    root = %root.path.display(),
                    "unverified redirect root deferred behind actionable roots"
                );
                *priority = ScanPriority::Deferred;
            }
            // The scan loop observes the same elapsed deadline and truncates.
            CachedirTagProbe::Truncated => break,
        }
    }
}

fn mark_pending_roots(roots: &[PreparedRoot<'_>], collection: &mut Collection) {
    for root in roots {
        collection.mark_truncated(root.scope());
    }
}
