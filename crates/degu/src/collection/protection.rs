use anyhow::{Context, Result};
use degu_core::ecosystem::{DetectCtx, IncompleteRegions, RegionCause, Root, RootProvenance};
use degu_core::finding::{
    AuthorityConstraint, Finding, FindingCandidate, FindingSource, finalize_findings,
    finalize_findings_with_constraint,
};
use degu_core::safety::ProtectionPolicy;

pub(super) fn finding_source(ecosystem: &str, root: &Root, finding_count: usize) -> FindingSource {
    match root.provenance {
        RootProvenance::WellKnown => FindingSource::WellKnownRoot,
        RootProvenance::Redirect if degu_adapters::has_valid_cachedir_tag(&root.path) => {
            tracing::debug!(target: "degu", ecosystem, root = %root.path.display(), "redirect root corroborated by CACHEDIR.TAG");
            FindingSource::RedirectRoot {
                has_valid_cachedir_tag: true,
            }
        }
        RootProvenance::Redirect => {
            if finding_count > 0 {
                tracing::debug!(target: "degu", ecosystem, root = %root.path.display(), findings = finding_count, "redirect root is not corroborated as a cache");
            }
            FindingSource::RedirectRoot {
                has_valid_cachedir_tag: false,
            }
        }
    }
}

pub(super) fn apply_mixed_state_constraints(
    root: &Root,
    candidates: &mut [FindingCandidate],
    ctx: &DetectCtx,
    regions: &mut IncompleteRegions,
) -> Result<Option<AuthorityConstraint>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let policy = ProtectionPolicy::for_mixed_state_ai(&ctx.home)?;
    let lexical = std::path::absolute(&root.path)
        .with_context(|| format!("failed to resolve adapter root {}", root.path.display()))?;
    if policy.contains(&lexical)?.is_some() {
        return Ok(Some(AuthorityConstraint::MixedStateAiToolDirectory));
    }
    apply_candidate_policy(candidates, &policy, regions)?;
    Ok(None)
}

pub(super) fn apply_candidate_constraints(
    candidates: &mut [FindingCandidate],
    ctx: &DetectCtx,
    regions: &mut IncompleteRegions,
) -> Result<()> {
    let policy = ProtectionPolicy::for_mixed_state_ai(&ctx.home)?;
    apply_candidate_policy(candidates, &policy, regions)
}

// This runs after ScanOutcome::from_candidates has already derived regions,
// so a boundary marked here must record its own region to keep every
// incompleteness event accounted. It records Measurement, not Protected:
// this is a post-hoc identity constraint on an already measured candidate,
// not a pre-descent walker prune, and only ScanOutcome::from_candidates may
// state the Protected cause.
fn apply_candidate_policy(
    candidates: &mut [FindingCandidate],
    policy: &ProtectionPolicy,
    regions: &mut IncompleteRegions,
) -> Result<()> {
    for candidate in candidates {
        if candidate_is_protected(policy, candidate)? {
            candidate.protected_boundaries = candidate.protected_boundaries.max(1);
            regions.record(&candidate.path, RegionCause::Measurement);
        }
    }
    Ok(())
}

fn candidate_is_protected(policy: &ProtectionPolicy, candidate: &FindingCandidate) -> Result<bool> {
    let lexical = std::path::absolute(&candidate.path)
        .with_context(|| format!("failed to resolve finding {}", candidate.path.display()))?;
    Ok(policy.identity_overlap(&lexical)?.is_some())
}

pub(super) fn finalize_candidates(
    candidates: Vec<FindingCandidate>,
    source: FindingSource,
    constraint: Option<AuthorityConstraint>,
) -> Vec<Finding> {
    match constraint {
        Some(constraint) => finalize_findings_with_constraint(candidates, source, constraint),
        None => finalize_findings(candidates, source),
    }
}
