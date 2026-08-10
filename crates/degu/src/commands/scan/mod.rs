mod output;
mod summary;

pub(crate) const NO_STORAGE_DETECTED: &str = "No storage detected by degu.";
pub(crate) const NO_RUNTIME_LOCATIONS_DETECTED: &str = "No node-runtime locations detected.";

use super::CollectionRunOptions;
use crate::cli::ScanArgs;
use crate::collection::{CollectionRequest, ScanCompleteness, collect_profiled};
use crate::commands::scope::ScanScope;
use crate::configuration::{deadline_from_budget, load_config, resolve_max_concurrency};
use crate::findings::{FilteredFinding, PreparedFindingFilter};
use crate::runtime::Ui;
use crate::selection::SourceSelection;
use anyhow::Result;
use degu_core::ecosystem::{DetectCtx, IncompleteRegions};
use degu_core::finding::Finding;

pub(super) struct ScanReport {
    pub(super) ctx: DetectCtx,
    pub(super) findings: Vec<Finding>,
    pub(super) runtime_findings: Vec<Finding>,
    pub(super) hidden: Vec<FilteredFinding>,
    pub(super) runtime_hidden: Vec<FilteredFinding>,
    pub(super) completeness: ScanCompleteness,
    /// Findings-section incompleteness provenance: suggested commands that a
    /// fresh clean would refuse are withheld with it. Never serialized (the
    /// JSON schema is frozen).
    pub(super) incomplete_regions: IncompleteRegions,
    pub(super) has_effective_project_roots: bool,
    pub(super) json: bool,
    pub(super) details: bool,
    pub(super) summary: bool,
    pub(super) scope: ScanScope,
    pub(super) ui: Ui,
    /// Collection wall time, measured once at the command boundary;
    /// renderers only format it.
    pub(super) elapsed: Option<std::time::Duration>,
}

impl ScanReport {
    fn truncated(&self) -> bool {
        self.completeness.is_truncated()
    }

    fn incomplete(&self) -> bool {
        self.completeness.is_incomplete()
    }

    fn is_lower_bound(&self) -> bool {
        self.truncated() || self.incomplete()
    }

    fn findings_lower_bound(&self) -> bool {
        self.completeness.findings.is_lower_bound()
    }

    fn runtime_lower_bound(&self) -> bool {
        self.completeness.runtime.is_lower_bound()
    }
}

struct ScanRequest {
    details: bool,
    summary: bool,
    run: CollectionRunOptions,
    scope: ScanScope,
    ui: Ui,
}

impl ScanRequest {
    fn new(args: ScanArgs, ui: Ui) -> Self {
        let scope = ScanScope::from_args(&args);
        Self {
            details: args.details,
            summary: args.summary,
            run: CollectionRunOptions::new(args.output, args.limits, ui.colors),
            scope,
            ui,
        }
    }
}

pub(crate) fn run(args: ScanArgs, ui: Ui) -> Result<()> {
    if args.details && args.summary && !args.output.json {
        anyhow::bail!("--details cannot be used with --summary unless --json is also set");
    }
    let started = std::time::Instant::now();
    let mut report = prepare(ScanRequest::new(args, ui))?;
    report.elapsed = Some(started.elapsed());
    output::print(&report)
}

fn prepare(request: ScanRequest) -> Result<ScanReport> {
    let ctx = DetectCtx::from_process()?;
    let config = load_config(&ctx)?;
    let runtime_enabled = request.scope.runtime_requested() || config.runtime;
    let has_effective_project_roots =
        request.scope.has_explicit_roots() || !config.roots.is_empty();
    let sources =
        SourceSelection::from_only(request.scope.only_ids(), runtime_enabled, &config.disable)?;
    let collection_request = CollectionRequest::scan(
        request.scope.roots().to_vec(),
        sources,
        request.run.indicator_color_enabled,
    );
    let ctx = ctx.with_max_concurrency(resolve_max_concurrency(
        request.run.max_concurrency,
        &config,
    ));
    let ctx = ctx.with_deadline(deadline_from_budget(request.run.budget)?);
    let collection = collect_profiled(&ctx, &config, collection_request)?;
    let (findings, findings_status, incomplete_regions) = collection.findings.into_parts();
    // Runtime findings are never cleanable, so no suggested command gates on
    // the runtime section's provenance; it is dropped here (and never
    // serialized).
    let (runtime_findings, runtime_status, _) = collection.runtime.into_parts();
    let completeness = ScanCompleteness {
        findings: findings_status,
        runtime: runtime_status,
    };
    let filter = PreparedFindingFilter::prepare(request.scope.filters(), &[], &findings)?;
    let findings = filter.select(findings)?;
    let runtime_findings = filter.select(runtime_findings)?;
    Ok(ScanReport {
        ctx,
        findings: findings.included,
        runtime_findings: runtime_findings.included,
        hidden: findings.excluded,
        runtime_hidden: runtime_findings.excluded,
        completeness,
        incomplete_regions,
        has_effective_project_roots,
        json: request.run.json,
        details: request.details,
        summary: request.summary,
        scope: request.scope,
        ui: request.ui,
        elapsed: None,
    })
}
