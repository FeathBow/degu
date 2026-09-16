mod adapters;
mod metrics;
mod progress;
mod protection;
mod roots;
mod section;
mod walk;

use crate::selection::SourceSelection;
use anyhow::Result;
use degu_core::config::Config;
use degu_core::ecosystem::DetectCtx;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

pub(crate) use adapters::validate_clean_plan_disablement;
use metrics::{elapsed_ms, max_rss_bytes};
use progress::{ScanIndicator, ScanRootProgress};
pub(crate) use section::{CollectionSection, ScanStatus};

pub(crate) struct CollectionRequest {
    pub(crate) project_roots: ProjectRoots,
    pub(crate) sources: SourceSelection,
    indicator_color_enabled: bool,
}

impl CollectionRequest {
    pub(crate) fn scan(
        roots: Vec<PathBuf>,
        sources: SourceSelection,
        indicator_color_enabled: bool,
    ) -> Self {
        Self {
            project_roots: ProjectRoots::ReadOnlyDiscovery(roots),
            sources,
            indicator_color_enabled,
        }
    }

    pub(crate) fn clean(
        roots: Vec<PathBuf>,
        sources: SourceSelection,
        indicator_color_enabled: bool,
    ) -> Self {
        Self {
            project_roots: ProjectRoots::CleanupAuthorized(roots),
            sources,
            indicator_color_enabled,
        }
    }
}

pub(crate) enum ProjectRoots {
    ReadOnlyDiscovery(Vec<PathBuf>),
    CleanupAuthorized(Vec<PathBuf>),
}

pub(crate) struct Collection {
    pub(crate) findings: CollectionSection,
    pub(crate) runtime: CollectionSection,
    pub(crate) roots: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ScanCompleteness {
    pub(crate) findings: ScanStatus,
    pub(crate) runtime: ScanStatus,
}

impl ScanCompleteness {
    pub(crate) fn is_truncated(self) -> bool {
        self.findings.is_truncated() || self.runtime.is_truncated()
    }

    pub(crate) fn is_incomplete(self) -> bool {
        self.findings.is_incomplete() || self.runtime.is_incomplete()
    }

    pub(crate) fn unvisited_dirs(&self) -> u64 {
        self.findings
            .unvisited_dirs()
            .saturating_add(self.runtime.unvisited_dirs())
    }
}

pub(crate) fn collect_profiled(
    ctx: &DetectCtx,
    config: &Config,
    request: CollectionRequest,
) -> Result<Collection> {
    let started = Instant::now();
    let progress = Arc::new(degu_walk::Progress::default());
    let root_progress = ScanRootProgress::new();
    let indicator = ScanIndicator::start(
        Arc::clone(&progress),
        &root_progress,
        request.indicator_color_enabled,
    );
    let ctx = ctx.clone().with_progress(Some(Arc::clone(&progress)));
    let collection = walk::Collector::new(&ctx, config, &root_progress).collect(request);
    let indicator = indicator.stop_and_clear();
    let collection = collection?;
    indicator?;
    log_profile(&collection, &progress, started);
    Ok(collection)
}

fn log_profile(collection: &Collection, progress: &degu_walk::Progress, started: Instant) {
    let roots = collection.roots;
    let cache = collection.findings.profile();
    let runtime = collection.runtime.profile();
    let findings = cache.findings.saturating_add(runtime.findings);
    let total_inodes = cache.total_inodes.saturating_add(runtime.total_inodes);
    let completeness = ScanCompleteness {
        findings: cache.status,
        runtime: runtime.status,
    };
    let truncated = completeness.is_truncated();
    let incomplete = completeness.is_incomplete();
    let progress = progress.snapshot();
    let stat_ops = progress.stat_ops;
    let readdir_ops = progress.readdir_ops;
    let elapsed_ms = elapsed_ms(started.elapsed());
    if let Some(max_rss_bytes) = max_rss_bytes() {
        tracing::info!(
            target: "degu",
            roots,
            findings,
            total_inodes,
            truncated,
            incomplete,
            stat_ops,
            readdir_ops,
            elapsed_ms,
            max_rss_bytes,
            "scan phase complete"
        );
    } else {
        tracing::info!(
            target: "degu",
            roots,
            findings,
            total_inodes,
            truncated,
            incomplete,
            stat_ops,
            readdir_ops,
            elapsed_ms,
            "scan phase complete"
        );
    }
}
