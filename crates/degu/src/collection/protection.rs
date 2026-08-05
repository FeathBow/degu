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

/// Flag every candidate whose finding root sits directly under an untrusted
/// (group/world-writable, non-sticky) parent, so it is demoted to report-only.
/// Such a parent lets a foreign writer swap the root name into degu's trash
/// between validation and the staging rename; a shared parent that is sticky (or
/// not other-writable) is left alone. The parent lives above every measured
/// tree, so this cannot ride the walk and runs here on the finalized paths.
/// Fails closed: an unreadable parent mode marks the candidate unsafe.
pub(super) fn flag_untrusted_parents(candidates: &mut [FindingCandidate]) {
    for candidate in candidates {
        candidate.parent_grants_foreign_mutation = parent_grants_foreign_mutation(&candidate.path);
    }
}

fn parent_grants_foreign_mutation(path: &std::path::Path) -> bool {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        // No parent to trust means no verifiable namespace: fail closed.
        return true;
    };
    // A readable, trusted parent is the only pass; every error is a refusal.
    degu_walk::validate_trusted_parent_namespace(parent).is_err()
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

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[cfg(test)]
mod tests {
    use super::{finalize_candidates, flag_untrusted_parents};
    use degu_core::finding::{
        DispositionMode, FindingCandidate, FindingKind, FindingSource, Ownership, Recovery,
        RegenCost,
    };
    use degu_core::safety::SHARED_WRITABLE_PARENT_REASON;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn candidate(path: PathBuf) -> FindingCandidate {
        FindingCandidate {
            ecosystem: "test".to_string(),
            path,
            kind: FindingKind::PackageCache,
            bytes_apparent: 4096,
            bytes_allocated: 4096,
            age_days: Some(30),
            bytes_hardlinked: 0,
            inodes: 1,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            shared_writable_dirs: 0,
            parent_grants_foreign_mutation: false,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery: Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            ownership: Ownership::Standalone,
            hazard: None,
            rationale: "test fixture".to_string(),
        }
    }

    fn cache_under_parent(dir: &Path, parent_mode: u32) -> PathBuf {
        let parent = dir.join("parent");
        std::fs::create_dir_all(&parent).unwrap();
        let source = parent.join("cache");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(parent_mode)).unwrap();
        source
    }

    #[test]
    fn scan_demotes_a_tree_under_a_non_sticky_shared_parent_to_report_only() {
        let dir = tempfile::tempdir().unwrap();
        let source = cache_under_parent(dir.path(), 0o777);
        let mut candidates = vec![candidate(source)];

        flag_untrusted_parents(&mut candidates);
        assert!(candidates[0].parent_grants_foreign_mutation);
        let finding = finalize_candidates(candidates, FindingSource::WellKnownRoot, None)
            .pop()
            .unwrap();

        assert_eq!(finding.disposition().mode, DispositionMode::ReportOnly);
        assert_eq!(
            finding.disposition().reason.as_deref(),
            Some(SHARED_WRITABLE_PARENT_REASON)
        );
    }

    #[test]
    fn scan_does_not_demote_a_tree_under_a_sticky_shared_parent_for_the_parent_reason() {
        let dir = tempfile::tempdir().unwrap();
        let source = cache_under_parent(dir.path(), 0o1777);
        let mut candidates = vec![candidate(source)];

        flag_untrusted_parents(&mut candidates);
        assert!(
            !candidates[0].parent_grants_foreign_mutation,
            "sticky is modeled, not treated as plain 0777"
        );
        let finding = finalize_candidates(candidates, FindingSource::WellKnownRoot, None)
            .pop()
            .unwrap();
        assert_ne!(
            finding.disposition().reason.as_deref(),
            Some(SHARED_WRITABLE_PARENT_REASON)
        );
    }

    #[test]
    fn scan_leaves_a_normal_owned_parent_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let source = cache_under_parent(dir.path(), 0o755);
        let mut candidates = vec![candidate(source)];

        flag_untrusted_parents(&mut candidates);
        assert!(!candidates[0].parent_grants_foreign_mutation);
    }
}
