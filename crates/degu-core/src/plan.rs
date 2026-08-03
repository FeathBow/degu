use crate::finding::{DispositionMode, Finding};
use crate::safety::paths_overlap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Plan {
    items: Vec<Finding>,
}

#[derive(Debug)]
pub struct InvalidPlan {
    pub violation: PlanViolation,
    pub offending_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanViolation {
    Unauthorized,
    Overlapping,
}

impl std::fmt::Display for InvalidPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self.violation {
            PlanViolation::Unauthorized => "unauthorized findings",
            PlanViolation::Overlapping => "overlapping paths",
        };
        write!(
            f,
            "clean plan contains {reason}: {}",
            display_paths(&self.offending_paths)
        )
    }
}

impl std::error::Error for InvalidPlan {}

impl Plan {
    pub fn new(items: Vec<Finding>, opt_in_allowed: bool) -> Result<Self, InvalidPlan> {
        let offending_paths = items
            .iter()
            .filter(|finding| !authorized(finding, opt_in_allowed))
            .map(|finding| finding.path().to_path_buf())
            .collect::<Vec<_>>();

        if !offending_paths.is_empty() {
            return Err(InvalidPlan {
                violation: PlanViolation::Unauthorized,
                offending_paths,
            });
        }

        let offending_paths = overlapping_paths(&items);
        if !offending_paths.is_empty() {
            return Err(InvalidPlan {
                violation: PlanViolation::Overlapping,
                offending_paths,
            });
        }

        Ok(Self { items })
    }

    pub fn items(&self) -> &[Finding] {
        &self.items
    }

    pub fn total_bytes_allocated(&self) -> u64 {
        self.items.iter().fold(0, |total, finding| {
            total.saturating_add(finding.bytes_allocated())
        })
    }

    pub fn total_inodes(&self) -> u64 {
        self.items
            .iter()
            .fold(0, |total, finding| total.saturating_add(finding.inodes()))
    }
}

fn overlapping_paths(items: &[Finding]) -> Vec<PathBuf> {
    let mut offending = Vec::new();
    for (index, finding) in items.iter().enumerate() {
        for other in items.iter().skip(index + 1) {
            if paths_overlap(finding.path(), other.path()) {
                offending.extend([finding.path().to_path_buf(), other.path().to_path_buf()]);
            }
        }
    }
    offending.sort_unstable();
    offending.dedup();
    offending
}

fn display_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn authorized(finding: &Finding, opt_in_allowed: bool) -> bool {
    match finding.disposition().mode {
        DispositionMode::Eligible => true,
        DispositionMode::OptIn => opt_in_allowed,
        DispositionMode::ReportOnly => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{
        FindingCandidate, FindingKind, FindingSource, Hazard, Ownership, Recovery, RegenCost,
        finalize_findings,
    };

    fn candidate(path: &str, recovery: Recovery, hazard: Option<Hazard>) -> FindingCandidate {
        FindingCandidate {
            ecosystem: "test".to_string(),
            path: PathBuf::from(path),
            kind: FindingKind::Other,
            bytes_apparent: 0,
            bytes_allocated: 0,
            age_days: None,
            bytes_hardlinked: 0,
            inodes: 0,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            shared_writable_dirs: 0,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery,
            ownership: Ownership::Standalone,
            hazard,
            rationale: "test".to_string(),
        }
    }

    fn finding(path: &str, recovery: Recovery, hazard: Option<Hazard>) -> Finding {
        finalize(candidate(path, recovery, hazard))
    }

    fn finding_with_resources(path: &str, bytes_allocated: u64, inodes: u64) -> Finding {
        let mut candidate = candidate(path, cheap(), None);
        candidate.bytes_allocated = bytes_allocated;
        candidate.inodes = inodes;
        finalize(candidate)
    }

    fn finalize(candidate: FindingCandidate) -> Finding {
        finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
            .pop()
            .expect("one finalized finding")
    }

    fn cheap() -> Recovery {
        Recovery::Regenerable {
            cost: RegenCost::Cheap,
        }
    }

    fn costly() -> Recovery {
        Recovery::Regenerable {
            cost: RegenCost::Costly,
        }
    }

    #[test]
    fn report_only_is_rejected() {
        let items = vec![finding("/tmp/report-only", Recovery::UserAsset, None)];
        let err = Plan::new(items, true).unwrap_err();

        assert_eq!(err.violation, PlanViolation::Unauthorized);
        assert_eq!(err.offending_paths, vec![PathBuf::from("/tmp/report-only")]);
    }

    #[test]
    fn opt_in_without_permission_is_rejected() {
        let items = vec![finding("/tmp/opt-in", costly(), None)];
        let err = Plan::new(items, false).unwrap_err();

        assert_eq!(err.violation, PlanViolation::Unauthorized);
        assert_eq!(err.offending_paths, vec![PathBuf::from("/tmp/opt-in")]);
    }

    #[test]
    fn opt_in_with_permission_and_eligible_are_accepted() {
        let items = vec![
            finding("/tmp/opt-in", cheap(), Some(Hazard::BreaksConsumers)),
            finding("/tmp/eligible", cheap(), None),
        ];
        let plan = Plan::new(items, true).unwrap();

        assert_eq!(plan.items().len(), 2);
    }

    #[test]
    fn totals_saturate_at_u64_max() {
        let items = vec![
            finding_with_resources("/tmp/large", u64::MAX, u64::MAX),
            finding_with_resources("/var/extra", 1, 1),
        ];
        let plan = Plan::new(items, false).unwrap();

        assert_eq!(plan.total_bytes_allocated(), u64::MAX);
        assert_eq!(plan.total_inodes(), u64::MAX);
    }

    #[test]
    fn duplicate_paths_are_rejected() {
        let items = vec![
            finding("/tmp/shared", cheap(), None),
            finding("/tmp/shared", costly(), None),
        ];

        let err = Plan::new(items, true).unwrap_err();

        assert_eq!(err.violation, PlanViolation::Overlapping);
        assert_eq!(err.offending_paths, vec![PathBuf::from("/tmp/shared")]);
    }

    #[test]
    fn ancestor_and_descendant_paths_are_rejected() {
        let items = vec![
            finding("/tmp/cache", cheap(), None),
            finding("/tmp/cache/nested", costly(), None),
        ];

        let err = Plan::new(items, true).unwrap_err();

        assert_eq!(err.violation, PlanViolation::Overlapping);
        assert_eq!(
            err.offending_paths,
            vec![
                PathBuf::from("/tmp/cache"),
                PathBuf::from("/tmp/cache/nested")
            ]
        );
    }
}
