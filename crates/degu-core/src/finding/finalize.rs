use super::*;

/// Variants in ascending protective precedence: `Ord`/`max` select the stronger
/// constraint, so a credential boundary always outranks AI-tool state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityConstraint {
    MixedStateAiToolDirectory,
    SharedWritableDirectory,
    ProtectedCredentialDirectory,
}

impl FindingSource {
    fn confidence(self) -> Confidence {
        match self {
            Self::WellKnownRoot | Self::ProjectRoot => Confidence::Verified,
            Self::RedirectRoot {
                has_valid_cachedir_tag: true,
            } => Confidence::Verified,
            Self::RedirectRoot {
                has_valid_cachedir_tag: false,
            } => Confidence::Unverified,
        }
    }
}

impl Finding {
    fn from_candidate(
        candidate: FindingCandidate,
        confidence: Confidence,
        constraint: Option<AuthorityConstraint>,
    ) -> Self {
        // Take the stronger of the caller's constraint and the candidate's own
        // evidence, so an explicit AI constraint cannot mask a credential boundary.
        let constraint = [constraint, synthesize_constraint(&candidate)]
            .into_iter()
            .flatten()
            .max();
        let disposition = finalized_disposition(&candidate, confidence, constraint);
        Self {
            ecosystem: candidate.ecosystem,
            path: candidate.path,
            kind: candidate.kind,
            bytes_apparent: candidate.bytes_apparent,
            bytes_allocated: candidate.bytes_allocated,
            age_days: candidate.age_days,
            bytes_hardlinked: candidate.bytes_hardlinked,
            inodes: candidate.inodes,
            skipped: candidate
                .skipped
                .saturating_add(candidate.protected_boundaries),
            truncated: candidate.truncated,
            unvisited_dirs: candidate.unvisited_dirs,
            recovery: candidate.recovery,
            ownership: candidate.ownership,
            hazard: candidate.hazard,
            confidence,
            disposition,
            rationale: candidate.rationale,
        }
    }
}

/// A descendant credential directory outranks AI-tool state: both demote the
/// enclosing finding, but the reason must name what was actually found.
fn synthesize_constraint(candidate: &FindingCandidate) -> Option<AuthorityConstraint> {
    if candidate.protected_credential_boundaries > 0 {
        return Some(AuthorityConstraint::ProtectedCredentialDirectory);
    }
    if candidate.shared_writable_dirs > 0 {
        return Some(AuthorityConstraint::SharedWritableDirectory);
    }
    (candidate.protected_boundaries > 0).then_some(AuthorityConstraint::MixedStateAiToolDirectory)
}

fn finalized_disposition(
    candidate: &FindingCandidate,
    confidence: Confidence,
    constraint: Option<AuthorityConstraint>,
) -> Disposition {
    if let Some(reason) = constraint.map(constraint_reason) {
        return Disposition {
            mode: DispositionMode::ReportOnly,
            reason: Some(reason.to_string()),
        };
    }
    crate::disposition::derive(crate::disposition::DispositionFacts::from_candidate(
        candidate, confidence,
    ))
}

fn constraint_reason(constraint: AuthorityConstraint) -> &'static str {
    match constraint {
        AuthorityConstraint::MixedStateAiToolDirectory => crate::safety::MIXED_STATE_AI_TOOL_REASON,
        AuthorityConstraint::SharedWritableDirectory => crate::safety::SHARED_WRITABLE_REASON,
        AuthorityConstraint::ProtectedCredentialDirectory => {
            crate::safety::PROTECTED_CREDENTIAL_REASON
        }
    }
}

/// Consumes adapter candidates and constructs the only externally visible state.
pub fn finalize_findings(candidates: Vec<FindingCandidate>, source: FindingSource) -> Vec<Finding> {
    finalize(candidates, source, None)
}

pub fn finalize_findings_with_constraint(
    candidates: Vec<FindingCandidate>,
    source: FindingSource,
    constraint: AuthorityConstraint,
) -> Vec<Finding> {
    finalize(candidates, source, Some(constraint))
}

fn finalize(
    candidates: Vec<FindingCandidate>,
    source: FindingSource,
    constraint: Option<AuthorityConstraint>,
) -> Vec<Finding> {
    let confidence = source.confidence();
    candidates
        .into_iter()
        .map(|candidate| Finding::from_candidate(candidate, confidence, constraint))
        .collect()
}
