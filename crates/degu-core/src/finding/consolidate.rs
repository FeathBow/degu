use super::Finding;
use crate::disposition::authority_rank;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn consolidate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_path = BTreeMap::<PathBuf, Finding>::new();
    for finding in findings {
        match by_path.entry(finding.path.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(finding);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().merge_same_path(finding);
            }
        }
    }
    by_path.into_values().collect()
}

impl Finding {
    fn merge_same_path(&mut self, other: Self) {
        let replace_authority = authority_precedes(&other, self);
        self.bytes_apparent = self.bytes_apparent.max(other.bytes_apparent);
        self.bytes_allocated = self.bytes_allocated.max(other.bytes_allocated);
        self.age_days = conservative_age(self.age_days, other.age_days);
        self.bytes_hardlinked = self.bytes_hardlinked.max(other.bytes_hardlinked);
        self.inodes = self.inodes.max(other.inodes);
        self.skipped = self.skipped.max(other.skipped);
        self.truncated |= other.truncated;
        self.unvisited_dirs = self.unvisited_dirs.max(other.unvisited_dirs);
        // Keep the stricter finding's finalized disposition wholesale: it already
        // encodes any AuthorityConstraint, which the fact fields do not carry.
        if replace_authority {
            self.replace_authority(&other);
        }
    }

    fn replace_authority(&mut self, other: &Self) {
        self.ecosystem.clone_from(&other.ecosystem);
        self.kind = other.kind;
        self.recovery = other.recovery;
        self.ownership = other.ownership;
        self.hazard = other.hazard;
        self.confidence = other.confidence;
        self.disposition.clone_from(&other.disposition);
        self.rationale.clone_from(&other.rationale);
    }
}

/// Ecosystem name only breaks an exact safety-disposition tie (stable presentation).
fn authority_precedes(candidate: &Finding, current: &Finding) -> bool {
    let candidate_rank = authority_rank(&candidate.disposition);
    let current_rank = authority_rank(&current.disposition);
    candidate_rank > current_rank
        || (candidate_rank == current_rank && candidate.ecosystem < current.ecosystem)
}

fn conservative_age(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{
        AuthorityConstraint, DispositionMode, FindingCandidate, FindingKind, FindingSource, Hazard,
        Ownership, Recovery, RegenCost, finalize_findings, finalize_findings_with_constraint,
    };

    fn constrained_finding(
        ecosystem: &str,
        constraint: AuthorityConstraint,
        protected_boundaries: u64,
        protected_credential_boundaries: u64,
    ) -> Finding {
        finalize_findings_with_constraint(
            vec![FindingCandidate {
                ecosystem: ecosystem.to_string(),
                path: PathBuf::from("/cache"),
                kind: FindingKind::Other,
                bytes_apparent: 4096,
                bytes_allocated: 4096,
                age_days: Some(1),
                bytes_hardlinked: 0,
                inodes: 1,
                skipped: 0,
                truncated: false,
                unvisited_dirs: 0,
                shared_writable_dirs: 0,
                parent_grants_foreign_mutation: false,
                protected_boundaries,
                protected_credential_boundaries,
                recovery: cheap(),
                ownership: Ownership::Standalone,
                hazard: None,
                rationale: ecosystem.to_string(),
            }],
            FindingSource::WellKnownRoot,
            constraint,
        )
        .pop()
        .unwrap()
    }

    #[test]
    fn same_path_keeps_strictest_authority_and_largest_observation() {
        let eligible = finding(FindingSpec::new("pip", "/cache", cheap()).with_size(8192, 7));
        let review = finding(FindingSpec::new("torch", "/cache", costly()).with_size(4096, 3));

        let findings = consolidate_findings(vec![eligible, review]);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.ecosystem(), "torch");
        assert_eq!(finding.disposition().mode, DispositionMode::OptIn);
        assert_eq!(finding.bytes_allocated(), 8192);
        assert_eq!(finding.inodes(), 7);
    }

    #[test]
    fn report_only_authority_wins_over_cleanup_authority() {
        let eligible = finding(FindingSpec::new("pip", "/cache", cheap()).with_size(8192, 7));
        let user_asset = finding(
            FindingSpec::new("workspace", "/cache", Recovery::UserAsset).with_size(4096, 3),
        );

        let findings = consolidate_findings(vec![eligible, user_asset]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].disposition().mode, DispositionMode::ReportOnly);
        assert_eq!(findings[0].ecosystem(), "workspace");
    }

    #[test]
    fn same_path_preserves_conservative_scan_observations() {
        let complete = finding(FindingSpec::new("pip", "/cache", cheap()).with_scan(
            ScanObservation {
                age_days: Some(30),
                bytes_hardlinked: 100,
                skipped: 2,
                truncated: false,
                unvisited_dirs: 1,
            },
        ));
        let partial = finding(FindingSpec::new("torch", "/cache", cheap()).with_scan(
            ScanObservation {
                age_days: None,
                bytes_hardlinked: 200,
                skipped: 5,
                truncated: true,
                unvisited_dirs: 3,
            },
        ));

        let finding = consolidate_findings(vec![complete, partial]).pop().unwrap();

        assert_eq!(finding.age_days(), None);
        assert_eq!(finding.bytes_hardlinked(), 200);
        assert_eq!(finding.skipped(), 5);
        assert!(finding.truncated());
        assert_eq!(finding.unvisited_dirs(), 3);
    }

    #[test]
    fn equal_modes_keep_the_stricter_safety_fact_regardless_of_name() {
        // Hazardous ecosystem sorts last, so a name tie-break would drop the hazard.
        let costly = finding(FindingSpec::new("aaa", "/cache", costly()));
        let hazardous = finding(
            FindingSpec::new("zzz", "/cache", cheap()).with_hazard(Hazard::BreaksConsumers),
        );

        let finding = consolidate_findings(vec![costly, hazardous]).pop().unwrap();

        assert_eq!(finding.ecosystem(), "zzz");
        assert_eq!(finding.recovery(), cheap());
        assert_eq!(finding.hazard(), Some(Hazard::BreaksConsumers));
        assert_eq!(finding.disposition().mode, DispositionMode::OptIn);
        assert_eq!(
            finding.disposition().reason.as_deref(),
            Some(crate::disposition::BREAKS_CONSUMERS)
        );
    }

    #[test]
    fn constraint_report_only_survives_merge_and_stays_unplannable() {
        use crate::plan::Plan;

        // Clean facts derive to Eligible; the ReportOnly comes only from the
        // constraint, which the fact fields do not carry — a re-derive would re-authorize it.
        let constrained = || {
            constrained_finding(
                "aitool",
                AuthorityConstraint::MixedStateAiToolDirectory,
                0,
                0,
            )
        };
        let eligible = || finding(FindingSpec::new("pip", "/cache", cheap()).with_size(8192, 7));

        for order in [
            vec![constrained(), eligible()],
            vec![eligible(), constrained()],
        ] {
            let merged = consolidate_findings(order);
            assert_eq!(merged.len(), 1);
            assert_eq!(merged[0].disposition().mode, DispositionMode::ReportOnly);
            assert!(Plan::new(merged, false).is_err());
        }
    }

    #[test]
    fn credential_constraint_outranks_ai_constraint_regardless_of_name() {
        // Credential ecosystem sorts last, so a name tie-break would surface the AI reason.
        let ai = || {
            constrained_finding(
                "aaa-ai",
                AuthorityConstraint::MixedStateAiToolDirectory,
                0,
                0,
            )
        };
        let credential = || {
            constrained_finding(
                "zzz-credential",
                AuthorityConstraint::ProtectedCredentialDirectory,
                0,
                0,
            )
        };

        for order in [vec![ai(), credential()], vec![credential(), ai()]] {
            let merged = consolidate_findings(order).pop().unwrap();
            assert_eq!(merged.disposition().mode, DispositionMode::ReportOnly);
            assert_eq!(
                merged.disposition().reason.as_deref(),
                Some(crate::safety::PROTECTED_CREDENTIAL_REASON)
            );
            assert_eq!(merged.ecosystem(), "zzz-credential");
        }
    }

    #[test]
    fn explicit_ai_constraint_yields_to_a_synthesized_credential_boundary() {
        // Entry point: an explicit AI constraint must not mask the candidate's own
        // credential evidence at finalization.
        let finding = constrained_finding(
            "mixed",
            AuthorityConstraint::MixedStateAiToolDirectory,
            1,
            1,
        );
        assert_eq!(finding.disposition().mode, DispositionMode::ReportOnly);
        assert_eq!(
            finding.disposition().reason.as_deref(),
            Some(crate::safety::PROTECTED_CREDENTIAL_REASON)
        );
    }

    struct FindingSpec<'a> {
        ecosystem: &'a str,
        path: &'a str,
        bytes_allocated: u64,
        inodes: u64,
        scan: ScanObservation,
        recovery: Recovery,
        hazard: Option<Hazard>,
    }

    impl<'a> FindingSpec<'a> {
        fn new(ecosystem: &'a str, path: &'a str, recovery: Recovery) -> Self {
            Self {
                ecosystem,
                path,
                bytes_allocated: 0,
                inodes: 0,
                scan: ScanObservation::default(),
                recovery,
                hazard: None,
            }
        }

        fn with_size(self, bytes_allocated: u64, inodes: u64) -> Self {
            Self {
                bytes_allocated,
                inodes,
                ..self
            }
        }

        fn with_scan(self, scan: ScanObservation) -> Self {
            Self { scan, ..self }
        }

        fn with_hazard(self, hazard: Hazard) -> Self {
            Self {
                hazard: Some(hazard),
                ..self
            }
        }
    }

    struct ScanObservation {
        age_days: Option<u64>,
        bytes_hardlinked: u64,
        skipped: u64,
        truncated: bool,
        unvisited_dirs: u64,
    }

    impl Default for ScanObservation {
        fn default() -> Self {
            Self {
                age_days: Some(1),
                bytes_hardlinked: 0,
                skipped: 0,
                truncated: false,
                unvisited_dirs: 0,
            }
        }
    }

    fn finding(spec: FindingSpec<'_>) -> Finding {
        finalize_findings(
            vec![FindingCandidate {
                ecosystem: spec.ecosystem.to_string(),
                path: PathBuf::from(spec.path),
                kind: FindingKind::Other,
                bytes_apparent: spec.bytes_allocated,
                bytes_allocated: spec.bytes_allocated,
                age_days: spec.scan.age_days,
                bytes_hardlinked: spec.scan.bytes_hardlinked,
                inodes: spec.inodes,
                skipped: spec.scan.skipped,
                truncated: spec.scan.truncated,
                unvisited_dirs: spec.scan.unvisited_dirs,
                shared_writable_dirs: 0,
                parent_grants_foreign_mutation: false,
                protected_boundaries: 0,
                protected_credential_boundaries: 0,
                recovery: spec.recovery,
                ownership: Ownership::Standalone,
                hazard: spec.hazard,
                rationale: spec.ecosystem.to_string(),
            }],
            FindingSource::WellKnownRoot,
        )
        .pop()
        .unwrap()
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
}
