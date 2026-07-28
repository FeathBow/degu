mod output;

use super::CollectionRunOptions;
use crate::cli::ScanArgs;
use crate::collection::{CollectionRequest, ScanCompleteness, collect_profiled};
use crate::commands::scope::ScanScope;
use crate::configuration::{deadline_from_budget, load_config, resolve_max_concurrency};
use crate::runtime::Ui;
use crate::source_selection::SourceSelection;
use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;

pub(super) struct ScanReport {
    pub(super) findings: Vec<Finding>,
    pub(super) runtime_findings: Vec<Finding>,
    pub(super) completeness: ScanCompleteness,
    pub(super) json: bool,
}

struct ScanRequest {
    run: CollectionRunOptions,
    scope: ScanScope,
}

impl ScanRequest {
    fn new(args: ScanArgs, ui: Ui) -> Self {
        let scope = ScanScope::from_args(&args);
        Self {
            run: CollectionRunOptions::new(args.output, args.limits, ui.colors),
            scope,
        }
    }
}

pub(crate) fn run(args: ScanArgs, ui: Ui) -> Result<()> {
    let report = prepare(ScanRequest::new(args, ui))?;
    output::print(&report)
}

fn prepare(request: ScanRequest) -> Result<ScanReport> {
    let ctx = DetectCtx::from_process()?;
    let config = load_config(&ctx)?;
    let runtime_enabled = request.scope.runtime_requested() || config.runtime;
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
    let (findings, findings_status, _) = collection.findings.into_parts();
    let (runtime_findings, runtime_status, _) = collection.runtime.into_parts();
    let completeness = ScanCompleteness {
        findings: findings_status,
        runtime: runtime_status,
    };
    Ok(ScanReport {
        findings,
        runtime_findings,
        completeness,
        json: request.run.json,
    })
}
