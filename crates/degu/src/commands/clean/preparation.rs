use super::super::CollectionRunOptions;
use super::preview::PreviewStagingAssessment;
use crate::cli::CleanArgs;
use crate::collection::{
    CollectionRequest, ScanStatus, collect_profiled, validate_clean_plan_disablement,
};
use crate::commands::regions::{self, DisjointnessFailure};
use crate::commands::scope::CleanScope;
use crate::configuration::{deadline_from_budget, load_config, resolve_max_concurrency};
use crate::findings::Filters;
use crate::findings::{FilterReason, FilteredFinding, PreparedFindingFilter};
use crate::lifecycle::{CapturedCleanPlan, Lifecycle, MutationSession};
use crate::runtime::Ui;
use crate::selection::SourceSelection;
use anyhow::Result;
use degu_core::config::Config;
use degu_core::ecosystem::{DetectCtx, IncompleteRegion, IncompleteRegions, RegionCause};
use degu_core::finding::{DispositionMode, Finding};
use degu_core::plan::Plan;
use degu_core::safety::Guard;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(super) struct CleanSettings {
    pub(super) json: bool,
    pub(super) details: bool,
    pub(super) yes: bool,
    pub(super) dry_run: bool,
    pub(super) purge: bool,
    pub(super) ui: Ui,
}

pub(super) struct PreparedClean {
    pub(super) ctx: DetectCtx,
    pub(super) config: Config,
    pub(super) plan: CapturedCleanPlan,
    /// Present only for dry-run previews and indexed exactly like `plan.items()`.
    /// These are display/API facts, never execution inputs.
    pub(super) staging_preflight: Option<Box<[PreviewStagingAssessment]>>,
    pub(super) exclusions: CleanExclusions,
    pub(super) scan_status: ScanStatus,
    /// Protected-cause regions the completeness gate consulted and skipped;
    /// zero when the gate never ran or the scan recorded none. Human output
    /// discloses the exclusion; JSON stays frozen.
    pub(super) protected_regions_excluded: usize,
    /// Count of planned findings dropped for a non-UTF-8 path, reported as omitted.
    pub(super) unrepresentable: usize,
    pub(super) settings: CleanSettings,
    pub(super) scope: CleanScope,
}

impl PreparedClean {
    /// Whole-scan status; honest only for displays that summarize what the
    /// scan saw outside the plan (exclusions, outside-selection totals).
    pub(super) fn scan_lower_bound(&self) -> bool {
        self.scan_status.is_lower_bound()
    }

    /// The plan's own display bound: only the selected items' measurements
    /// mark the plan's totals as lower bounds. A proceeding clean guarantees
    /// them complete even when the wider scan was not.
    pub(super) fn plan_lower_bound(&self) -> bool {
        self.plan
            .items()
            .iter()
            .any(Finding::measurement_incomplete)
    }

    pub(super) fn preview_assessments(&self) -> &[PreviewStagingAssessment] {
        self.staging_preflight.as_deref().unwrap_or(&[])
    }

    pub(super) fn preview_assessment(
        &self,
        finding: &Finding,
    ) -> Option<&PreviewStagingAssessment> {
        let assessments = self.staging_preflight.as_deref()?;
        self.plan
            .items()
            .iter()
            .position(|item| item.path() == finding.path())
            .and_then(|index| assessments.get(index))
    }

    pub(super) fn preview_tree_policy_assessed(&self) -> Vec<&Finding> {
        match &self.staging_preflight {
            None => self.plan.items().iter().collect(),
            Some(assessments) => self
                .plan
                .items()
                .iter()
                .zip(assessments)
                .filter_map(|(finding, assessment)| {
                    assessment.is_tree_policy_assessed().then_some(finding)
                })
                .collect(),
        }
    }

    pub(super) fn lock(&self) -> Result<MutationSession> {
        Lifecycle::new(&self.ctx).lock_for_clean(self.settings.purge)
    }

    pub(super) fn revalidate(&self, session: &MutationSession) -> Result<()> {
        validate_clean_plan_disablement(&self.ctx, &self.config, self.plan.items())?;
        self.plan.validate_path_separation()?;
        let mut guard = build_guard(&self.ctx, &self.config)?;
        session.add_trash_roots_to_guard(self.plan.items(), &mut guard)?;
        for (finding, identity) in self.plan.items_with_identities() {
            if !identity.matches(finding.path())? {
                anyhow::bail!(
                    "clean item identity changed after planning: {}",
                    finding.path().display()
                );
            }
            guard.check(finding.path())?;
        }
        Ok(())
    }

    /// Re-runs the dynamic protection checks for one finding at its rename
    /// boundary. A guard canonicalizes protected paths when it is built, so a
    /// protected path that became an alias of this source after revalidate()
    /// is only visible to a freshly built guard, not to the plan-wide check.
    pub(super) fn recheck_finding(&self, finding: &Finding) -> Result<()> {
        let single = std::slice::from_ref(finding);
        validate_clean_plan_disablement(&self.ctx, &self.config, single)?;
        let mut guard = build_guard(&self.ctx, &self.config)?;
        Lifecycle::new(&self.ctx).add_trash_roots_to_guard(single, &mut guard)?;
        guard.check(finding.path())?;
        Ok(())
    }
}

struct CleanRequest {
    run: CollectionRunOptions,
    settings: CleanSettings,
    scope: CleanScope,
    exact_review: Option<PathBuf>,
}

impl CleanRequest {
    fn new(args: CleanArgs, ui: Ui) -> Self {
        let scope = CleanScope::from_args(&args);
        let exact_review = args.review.clone();
        let run = CollectionRunOptions::new(args.output, args.limits, ui.colors);
        Self {
            settings: CleanSettings {
                json: run.json,
                details: args.details,
                yes: args.yes,
                dry_run: args.dry_run,
                purge: args.purge,
                ui,
            },
            run,
            scope,
            exact_review,
        }
    }
}

pub(super) fn prepare(args: CleanArgs, ui: Ui) -> Result<PreparedClean> {
    let request = CleanRequest::new(args, ui);
    // Accepted, not a conflict: unattended recipes toggle --dry-run while
    // keeping --yes, so the combination only earns a notice.
    if request.settings.dry_run && request.settings.yes {
        crate::presentation::print_stderr_note(
            crate::presentation::Severity::Warning,
            "--yes has no effect in a dry run.",
            ui.colors,
        );
    }
    let ctx = DetectCtx::from_process()?;
    let config = load_config(&ctx)?;
    let sources = SourceSelection::from_only(request.scope.only_ids(), false, &config.disable)?;
    let collection_request = CollectionRequest::clean(
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
    let (findings, scan_status, incomplete_regions) = collection.findings.into_parts();
    validate_exact_review(request.exact_review.as_deref(), &findings)?;
    let FilteredCleanFindings {
        planned,
        exclusions,
    } = filter_findings(
        findings,
        request.scope.filters(),
        request.scope.paths(),
        request.scope.include_review(),
    )?;
    let (planned, unrepresentable) = partition_representable(planned);
    let staging_preflight = request.settings.dry_run.then(|| {
        planned
            .iter()
            .map(|finding| PreviewStagingAssessment::assess(finding, request.scope.has_paths()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    });
    let plan = capture_clean_plan(
        planned,
        &exclusions,
        scan_status,
        &incomplete_regions,
        &request.scope,
        staging_preflight.as_deref(),
    )?;
    // Only a gate that actually ran (incomplete scan, non-empty plan) can
    // have excluded protected regions from its completeness proof.
    let protected_regions_excluded = if scan_status.is_incomplete() && !plan.items().is_empty() {
        incomplete_regions.protected_regions()
    } else {
        0
    };
    // Guard identity is independent of sealed-staging availability. Preview
    // must check the complete plan just like execution, including blocked,
    // deferred, and unavailable items.
    validate_guard(&ctx, &config, plan.items())?;
    validate_invocation(request.settings)?;
    Ok(PreparedClean {
        ctx,
        config,
        plan,
        staging_preflight,
        exclusions,
        scan_status,
        protected_regions_excluded,
        unrepresentable,
        settings: request.settings,
        scope: request.scope,
    })
}

/// Split off findings whose path is not valid UTF-8: they cannot be serialized
/// or shown without loss, so they must never enter the executable plan.
fn partition_representable(findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    let mut representable = Vec::with_capacity(findings.len());
    let mut dropped = 0;
    for finding in findings {
        if finding.path().to_str().is_some() {
            representable.push(finding);
        } else {
            dropped += 1;
        }
    }
    (representable, dropped)
}

fn validate_exact_review(review: Option<&Path>, findings: &[Finding]) -> Result<()> {
    let Some(review) = review else {
        return Ok(());
    };
    let canonical_review = std::fs::canonicalize(review).map_err(|source| {
        anyhow::Error::new(source).context(format!(
            "failed to canonicalize --review {}",
            review.display()
        ))
    })?;
    let mut matches = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.disposition().mode == DispositionMode::OptIn)
    {
        let canonical_finding = std::fs::canonicalize(finding.path()).map_err(|source| {
            anyhow::Error::new(source).context(format!(
                "failed to canonicalize Needs review finding {}",
                finding.path().display()
            ))
        })?;
        if canonical_finding == canonical_review {
            matches.push(finding);
        }
    }
    match matches.as_slice() {
        [_] => Ok(()),
        [] => anyhow::bail!(
            "--review {} must name exactly one Needs review finding; parent directories and Ready to clean or Not managed locations are not accepted",
            review.display()
        ),
        _ => anyhow::bail!(
            "--review {} is ambiguous across multiple Needs review findings",
            review.display()
        ),
    }
}

struct FilteredCleanFindings {
    planned: Vec<Finding>,
    exclusions: CleanExclusions,
}

pub(super) struct CleanExclusions {
    policy_visible: Vec<Finding>,
    filter_hidden: Vec<FilteredFinding>,
}

impl CleanExclusions {
    pub(super) fn policy_visible(&self) -> &[Finding] {
        &self.policy_visible
    }

    pub(super) fn filter_hidden(&self) -> impl Iterator<Item = &Finding> {
        self.filter_hidden.iter().map(|hidden| &hidden.finding)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.policy_visible.iter().chain(self.filter_hidden())
    }

    /// Every finding the --path selection matched, before --older-than,
    /// --min-size, and --top trimmed the result. Those filters run after
    /// path matching, so an exclusion reason other than `Path` proves a
    /// path hit.
    pub(super) fn path_hits(&self) -> impl Iterator<Item = &Finding> {
        self.policy_visible.iter().chain(
            self.filter_hidden
                .iter()
                .filter(|hidden| hidden.reason != FilterReason::Path)
                .map(|hidden| &hidden.finding),
        )
    }
}

fn filter_findings(
    findings: Vec<Finding>,
    filters: &Filters,
    paths: &[PathBuf],
    include_review: bool,
) -> Result<FilteredCleanFindings> {
    let filter = PreparedFindingFilter::prepare(filters, paths, &findings)?;
    let (plan_candidates, policy_candidates): (Vec<_>, Vec<_>) =
        findings.into_iter().partition(|finding| {
            finding.disposition().mode == DispositionMode::Eligible
                || (include_review && finding.disposition().mode == DispositionMode::OptIn)
        });
    let policy = filter.select(policy_candidates)?;
    let planned = filter.select(plan_candidates)?;
    let mut filter_hidden = policy.excluded;
    for excluded in planned.excluded {
        tracing::debug!(
            target: "degu",
            ecosystem = excluded.finding.ecosystem(),
            path = %excluded.finding.path().display(),
            reason = excluded.reason.as_str(),
            "clean finding excluded by filter"
        );
        filter_hidden.push(excluded);
    }
    Ok(FilteredCleanFindings {
        planned: planned.included,
        exclusions: CleanExclusions {
            policy_visible: policy.included,
            filter_hidden,
        },
    })
}

fn capture_clean_plan(
    planned: Vec<Finding>,
    exclusions: &CleanExclusions,
    status: ScanStatus,
    incomplete_regions: &IncompleteRegions,
    scope: &CleanScope,
    preview: Option<&[PreviewStagingAssessment]>,
) -> Result<CapturedCleanPlan> {
    if status.is_truncated() {
        anyhow::bail!(
            "scan hit the time budget before completing; refusing to clean on partial results (re-run without --budget)"
        );
    }
    refuse_incomplete_selection(&planned, exclusions, scope)?;
    if status.is_incomplete() && !planned.is_empty() {
        if incomplete_regions.protected_prunes_only() {
            // Pre-descent, name-based, one-directional protection: hidden content can
            // never grant eligibility or change plan membership, so the whole plan
            // proceeds (prune-containing findings were already refused above).
            note_protected_regions_skipped(incomplete_regions);
        } else if scope.has_paths() {
            // Per-item measurement completeness (checked above) is not
            // enough to relax the whole-scope refusal: an incompletely
            // classified ancestor region would, in the complete world, have
            // claimed its whole subtree and vetoed a selected descendant.
            // Incompleteness can change eligibility, not just measurements, so
            // proceeding requires provenance proving every incompletely measured
            // region disjoint from each selected path itself -- not merely the
            // findings it produced, since an unmeasured region inside a selected
            // path could gain a finding in the complete world and change plan
            // membership.
            let selected = scope
                .paths()
                .iter()
                .map(|path| path.as_path())
                .chain(planned.iter().map(Finding::path))
                .chain(exclusions.path_hits().map(Finding::path))
                .collect::<Vec<_>>();
            refuse_incompleteness_overlapping_selection(&selected, incomplete_regions)?;
            note_protected_regions_skipped(incomplete_regions);
        } else {
            return Err(refuse_incomplete_scope(incomplete_regions));
        }
    }
    let plan = Plan::new(planned, scope.include_review())?;
    if let Some(preview) = preview {
        if !plan
            .items()
            .iter()
            .zip(preview)
            .all(|(finding, assessment)| finding.path() == assessment.path())
            || plan.items().len() != preview.len()
        {
            anyhow::bail!("staging preview assessment does not match captured clean plan");
        }
        CapturedCleanPlan::capture_preview(plan, scope.has_paths())
    } else if scope.has_paths() {
        CapturedCleanPlan::capture_atomic_selection(plan)
    } else {
        CapturedCleanPlan::capture(plan)
    }
}

/// Observability mirror of the --path relaxation info: names how many
/// deliberately protected regions the completeness gate skipped.
fn note_protected_regions_skipped(regions: &IncompleteRegions) {
    let skipped = regions.protected_regions();
    if skipped == 0 {
        return;
    }
    tracing::info!(
        target: "degu",
        protected_regions = skipped,
        "completeness gate skipped deliberately protected regions; a pre-descent name-based prune cannot change plan membership"
    );
}

/// Cap on how many recorded regions the whole-scope refusal prints. The
/// sample itself is already bounded at [`IncompleteRegions::SAMPLE_CAP`], but a
/// full 32-line dump buries the actionable `--path` hint, so the message shows
/// the first few and discloses the rest as a count.
const PRINTED_REGION_CAP: usize = 10;

/// Whole-scope incompleteness refusal (no `--path`). Lists the recorded
/// measurement-cause regions so the remedy names real locations instead of
/// pointing at scan warnings the clean never prints; deliberately protected
/// regions never block the plan, so naming them here would misdirect the
/// remedy. The recorded sample is the same provenance the `--path`
/// relaxation consumes, so the message can only ever name locations the
/// scan actually flagged.
fn refuse_incomplete_scope(regions: &IncompleteRegions) -> anyhow::Error {
    let sample = regions
        .sample()
        .iter()
        .filter(|region| region.cause() == RegionCause::Measurement)
        .map(IncompleteRegion::path)
        .collect::<Vec<_>>();
    if sample.is_empty() {
        // Only unlocated or overflow events: nothing to name, so mirror the
        // honesty of the `NoRecordedRegion`/`Unsampled` arms rather than print
        // an empty list or promise `-vv` output that does not exist for these
        // events.
        return anyhow::anyhow!(
            "scan could not fully inspect or classify every location in this scope, but recorded no specific location; refusing to clean on incomplete results (narrow the clean with --path to fully measured locations)"
        );
    }
    let mut listed = sample
        .iter()
        .take(PRINTED_REGION_CAP)
        .map(|region| region.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    // Sampled regions past the print cap and overflow events both had real
    // paths, dropped only for the sample bound; only unlocated events truly
    // lack one. Disclose each honestly so the named list never reads complete.
    let more_recorded = (sample.len().saturating_sub(PRINTED_REGION_CAP) as u64)
        .saturating_add(regions.overflowed());
    if more_recorded > 0 {
        listed.push_str(&format!(" (and {more_recorded} more recorded location(s))"));
    }
    let unlocated = regions.unlocated();
    if unlocated > 0 {
        listed.push_str(&format!(
            " (and {unlocated} location(s) with no recorded path)"
        ));
    }
    anyhow::anyhow!(
        "scan could not fully inspect or classify every location in this scope; refusing to clean on incomplete results (incomplete: {listed}; narrow the clean with --path to fully measured locations)"
    )
}

/// Per-item completeness gate at the mutation boundary: a location may only
/// be cleaned when its own subtree was fully measured. Disposition policy
/// already demotes incompletely measured findings to report-only, but the
/// plan must not depend on that distant invariant to stay fail-closed. The
/// --path check runs over the unfiltered path-hit set: --older-than,
/// --min-size, and --top must not hide an incompletely measured hit whose
/// lower-bound measurements undershoot their thresholds.
fn refuse_incomplete_selection(
    planned: &[Finding],
    exclusions: &CleanExclusions,
    scope: &CleanScope,
) -> Result<()> {
    let path_selected: Vec<&Finding> = if scope.has_paths() {
        exclusions.path_hits().collect()
    } else {
        Vec::new()
    };
    let incomplete = planned
        .iter()
        .chain(path_selected)
        .filter(|finding| finding.measurement_incomplete())
        .collect::<Vec<_>>();
    if incomplete.is_empty() {
        return Ok(());
    }
    for finding in &incomplete {
        tracing::warn!(
            target: "degu",
            ecosystem = finding.ecosystem(),
            path = %finding.path().display(),
            skipped = finding.skipped(),
            truncated = finding.truncated(),
            unvisited_dirs = finding.unvisited_dirs(),
            "selected clean location was not fully measured"
        );
    }
    let paths = incomplete
        .iter()
        .map(|finding| finding.path().display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "scan could not fully inspect or classify every selected path; refusing to clean on incomplete results (not fully measured: {paths}; make these locations fully readable, then rerun the clean)"
    );
}

/// The --path relaxation of the whole-scope incompleteness refusal is earned
/// by provenance, never inferred: every incomplete region must be proven
/// disjoint from every selected location by [`regions::prove_disjoint`], and
/// any failure to prove it refuses the clean.
fn refuse_incompleteness_overlapping_selection(
    selected: &[&Path],
    regions: &IncompleteRegions,
) -> Result<()> {
    match regions::prove_disjoint(selected, regions) {
        Ok(()) => {
            tracing::info!(
                target: "degu",
                regions = regions.sample().len(),
                "scan incomplete only in regions verified disjoint from every selected location; proceeding with the --path selection"
            );
            Ok(())
        }
        Err(failure) => Err(disjointness_refusal(failure, regions)),
    }
}

fn disjointness_refusal(
    failure: DisjointnessFailure,
    regions: &IncompleteRegions,
) -> anyhow::Error {
    match failure {
        DisjointnessFailure::Unsampled { count } => {
            tracing::warn!(
                target: "degu",
                unsampled = count,
                sampled = regions.sample().len(),
                "incompleteness provenance is unknown for events outside the recorded region sample"
            );
            anyhow::anyhow!(
                "scan reported {count} incompleteness event(s) whose location could not be accounted for; refusing to clean on incomplete results (nothing further can be shown for these events)"
            )
        }
        DisjointnessFailure::NoRecordedRegion => anyhow::anyhow!(
            "scan reported incompleteness without any recorded region; refusing to clean on incomplete results"
        ),
        DisjointnessFailure::UnresolvableSelection { path, source } => {
            anyhow::Error::new(source).context(format!(
                "failed to canonicalize selected clean location {}; refusing to clean on incomplete results",
                path.display()
            ))
        }
        DisjointnessFailure::UnresolvableRegion { region, source } => {
            anyhow::Error::new(source).context(format!(
                "failed to canonicalize incompletely scanned region {}; refusing to clean on incomplete results",
                region.display()
            ))
        }
        DisjointnessFailure::Overlap {
            region,
            selected,
            overlap,
        } => {
            let relation = overlap.description();
            tracing::warn!(
                target: "degu",
                region = %region.display(),
                selected = %selected.display(),
                relation,
                "incompletely scanned region overlaps the --path selection"
            );
            anyhow::anyhow!(
                "scan could not fully inspect or classify {}, which {} {}; refusing to clean on incomplete results (its complete-world classification could change what this selection matches; make that region fully readable or narrow the clean away from it, then rerun the clean)",
                region.display(),
                relation,
                selected.display()
            )
        }
    }
}

fn validate_guard(ctx: &DetectCtx, config: &Config, findings: &[Finding]) -> Result<()> {
    let findings = findings.iter().collect::<Vec<_>>();
    validate_guard_refs(ctx, config, &findings)
}

fn validate_guard_refs(ctx: &DetectCtx, config: &Config, findings: &[&Finding]) -> Result<()> {
    let guard = build_guard(ctx, config)?;
    for finding in findings {
        guard.check_identity(finding.path())?;
    }
    Ok(())
}

fn build_guard(ctx: &DetectCtx, config: &Config) -> Result<Guard> {
    let mut guard = Guard::with_defaults(&ctx.home)?;
    for protected in &config.protect {
        guard.add(ctx.home.join(protected))?;
    }
    Ok(guard)
}

fn validate_invocation(settings: CleanSettings) -> Result<()> {
    if settings.json && !settings.yes && !settings.dry_run {
        anyhow::bail!("--json requires --yes or --dry-run");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{refuse_incomplete_scope, refuse_incompleteness_overlapping_selection};
    use degu_core::ecosystem::{IncompleteRegions, RegionCause};
    use std::path::{Path, PathBuf};

    const REFUSAL_TOKEN: &str = "refusing to clean on incomplete results";

    fn refusal(selected: &[&Path], regions: &IncompleteRegions) -> String {
        refuse_incompleteness_overlapping_selection(selected, regions)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn provenance_overflow_beyond_the_sample_bound_fails_closed() {
        let mut regions = IncompleteRegions::default();
        for index in 0..=IncompleteRegions::SAMPLE_CAP {
            regions.record(
                &PathBuf::from(format!("/degu-test-region-{index}")),
                RegionCause::Measurement,
            );
        }
        assert!(regions.unsampled() > 0);

        let message = refusal(&[Path::new("/degu-test-selected")], &regions);

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
        assert!(
            message.contains("could not be accounted for"),
            "message: {message}"
        );
    }

    #[test]
    fn unlocated_provenance_fails_closed() {
        let mut regions = IncompleteRegions::default();
        regions.record_unlocated();

        let message = refusal(&[Path::new("/degu-test-selected")], &regions);

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
    }

    #[test]
    fn incompleteness_without_any_recorded_region_fails_closed() {
        let regions = IncompleteRegions::default();

        let message = refusal(&[Path::new("/degu-test-selected")], &regions);

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
    }

    #[test]
    fn whole_scope_refusal_names_the_recorded_region() {
        let mut regions = IncompleteRegions::default();
        regions.record(Path::new("/degu-test-region"), RegionCause::Measurement);

        let message = refuse_incomplete_scope(&regions).to_string();

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
        assert!(message.contains("/degu-test-region"), "message: {message}");
    }

    #[test]
    fn whole_scope_refusal_counts_overflow_as_recorded_not_pathless() {
        let mut regions = IncompleteRegions::default();
        for index in 0..=IncompleteRegions::SAMPLE_CAP {
            regions.record(
                &PathBuf::from(format!("/degu-test-region-{index}")),
                RegionCause::Measurement,
            );
        }
        assert!(regions.overflowed() > 0 && regions.unlocated() == 0);

        let message = refuse_incomplete_scope(&regions).to_string();

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
        assert!(
            message.contains("more recorded location(s)"),
            "message: {message}"
        );
        assert!(
            !message.contains("no recorded path"),
            "overflow events had paths: {message}"
        );
    }

    #[test]
    fn whole_scope_refusal_discloses_unlocated_events_as_pathless() {
        let mut regions = IncompleteRegions::default();
        regions.record(Path::new("/degu-test-region"), RegionCause::Measurement);
        regions.record_unlocated();
        regions.record_unlocated();

        let message = refuse_incomplete_scope(&regions).to_string();

        assert!(
            message.contains("2 location(s) with no recorded path"),
            "message: {message}"
        );
    }

    #[test]
    fn whole_scope_refusal_stays_honest_without_a_recorded_region() {
        let mut regions = IncompleteRegions::default();
        regions.record_unlocated();

        let message = refuse_incomplete_scope(&regions).to_string();

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
        assert!(
            message.contains("recorded no specific location"),
            "message: {message}"
        );
    }

    #[test]
    fn whole_scope_refusal_lists_only_measurement_regions() {
        let mut regions = IncompleteRegions::default();
        regions.record(
            Path::new("/degu-test-measurement-region"),
            RegionCause::Measurement,
        );
        regions.record(
            Path::new("/degu-test-protected-region"),
            RegionCause::Protected,
        );

        let message = refuse_incomplete_scope(&regions).to_string();

        assert!(
            message.contains("/degu-test-measurement-region"),
            "message: {message}"
        );
        assert!(
            !message.contains("/degu-test-protected-region"),
            "protected prunes never block the plan, so naming them misdirects the remedy: {message}"
        );
    }

    #[test]
    fn region_inside_a_selected_location_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let item = root.path().join("target");
        let region = item.join("debug");
        std::fs::create_dir_all(&region).unwrap();
        let mut regions = IncompleteRegions::default();
        regions.record(&region, RegionCause::Measurement);

        let message = refusal(&[item.as_path()], &regions);

        assert!(message.contains(REFUSAL_TOKEN), "message: {message}");
        assert!(
            message.contains("lies inside the selected location"),
            "message: {message}"
        );
        // The remedy states what to do before rerunning, never a bare "retry".
        assert!(
            message.contains("rerun the clean") && !message.contains("; then retry)"),
            "message: {message}"
        );
    }

    /// A protected region is never consulted for disjointness: even one that
    /// cannot be canonicalized and lexically overlaps the selection must not
    /// refuse, while a measurement region elsewhere still proves out.
    #[test]
    fn protected_regions_are_not_consulted_for_disjointness() {
        let root = tempfile::tempdir().unwrap();
        let item = root.path().join("target");
        let disjoint = root.path().join("elsewhere");
        std::fs::create_dir_all(&item).unwrap();
        std::fs::create_dir_all(&disjoint).unwrap();
        let mut regions = IncompleteRegions::default();
        regions.record(&disjoint, RegionCause::Measurement);
        // Nonexistent and inside the selection: consulted at all, it would
        // fail canonicalization or overlap.
        regions.record(&item.join("degu-test-pruned"), RegionCause::Protected);

        assert!(
            refuse_incompleteness_overlapping_selection(&[item.as_path()], &regions).is_ok(),
            "protected regions must neither refuse nor be canonicalized"
        );
    }

    #[test]
    fn protected_prunes_only_fails_closed_on_an_empty_ledger() {
        let mut protected = IncompleteRegions::default();
        protected.record(Path::new("/degu-test-prune"), RegionCause::Protected);
        assert!(protected.protected_prunes_only());

        let empty = IncompleteRegions::default();
        assert!(
            !empty.protected_prunes_only(),
            "an incomplete scan without records broke conservation and must keep refusing"
        );

        let mut mixed = protected;
        mixed.record(Path::new("/degu-test-unreadable"), RegionCause::Measurement);
        assert!(!mixed.protected_prunes_only());
    }
}
