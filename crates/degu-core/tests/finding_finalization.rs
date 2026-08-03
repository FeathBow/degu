use degu_core::finding::{
    AuthorityConstraint, Confidence, DispositionMode, FindingCandidate, FindingKind, FindingSource,
    Hazard, Ownership, Recovery, RegenCost, finalize_findings, finalize_findings_with_constraint,
};
use degu_core::plan::Plan;
use degu_core::safety::{MIXED_STATE_AI_TOOL_REASON, SHARED_WRITABLE_REASON};
use std::path::PathBuf;

fn candidate(path: &str) -> FindingCandidate {
    FindingCandidate {
        ecosystem: "test".to_string(),
        path: PathBuf::from(path),
        kind: FindingKind::PackageCache,
        bytes_apparent: 2048,
        bytes_allocated: 4096,
        age_days: Some(7),
        bytes_hardlinked: 512,
        inodes: 3,
        skipped: 0,
        truncated: false,
        unvisited_dirs: 0,
        shared_writable_dirs: 0,
        protected_boundaries: 0,
        protected_credential_boundaries: 0,
        recovery: Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        ownership: Ownership::Standalone,
        hazard: Some(Hazard::BreaksConsumers),
        rationale: "test candidate".to_string(),
    }
}

fn finalize(path: &str, source: FindingSource) -> degu_core::finding::Finding {
    finalize_findings(vec![candidate(path)], source)
        .pop()
        .expect("one finalized finding")
}

#[test]
fn source_evidence_derives_confidence_and_disposition() {
    let cases = [
        (
            FindingSource::WellKnownRoot,
            Confidence::Verified,
            DispositionMode::OptIn,
        ),
        (
            FindingSource::RedirectRoot {
                has_valid_cachedir_tag: true,
            },
            Confidence::Verified,
            DispositionMode::OptIn,
        ),
        (
            FindingSource::RedirectRoot {
                has_valid_cachedir_tag: false,
            },
            Confidence::Unverified,
            DispositionMode::ReportOnly,
        ),
        (
            FindingSource::ProjectRoot,
            Confidence::Verified,
            DispositionMode::OptIn,
        ),
    ];

    for (source, confidence, mode) in cases {
        let finding = finalize("/cache", source);
        assert_eq!(finding.confidence(), confidence);
        assert_eq!(finding.disposition().mode, mode);
    }
}

#[test]
fn incomplete_measurements_remove_cleanup_authority() {
    let cases = [
        FindingCandidate {
            skipped: 1,
            hazard: None,
            ..candidate("/cache/skipped")
        },
        FindingCandidate {
            truncated: true,
            hazard: None,
            ..candidate("/cache/truncated")
        },
        FindingCandidate {
            unvisited_dirs: 1,
            hazard: None,
            ..candidate("/cache/unvisited")
        },
    ];
    for candidate in cases {
        let finding = finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
            .pop()
            .unwrap();
        assert_eq!(finding.disposition().mode, DispositionMode::ReportOnly);
        assert!(finding.measurement_incomplete());
        assert_eq!(
            finding.disposition().reason.as_deref(),
            Some("measurement incomplete: some paths were not measured")
        );
    }
}

#[test]
fn shared_writable_directories_remove_authority_without_falsifying_measurement() {
    let finding = finalize_findings(
        vec![FindingCandidate {
            hazard: None,
            shared_writable_dirs: 1,
            ..candidate("/cache/shared")
        }],
        FindingSource::WellKnownRoot,
    )
    .pop()
    .unwrap();

    assert_eq!(finding.disposition().mode, DispositionMode::ReportOnly);
    assert_eq!(
        finding.disposition().reason.as_deref(),
        Some(SHARED_WRITABLE_REASON)
    );
    assert!(!finding.measurement_incomplete());
}

#[test]
fn mixed_state_constraint_precedes_adapter_cleanup_authority() {
    let findings = finalize_findings_with_constraint(
        vec![FindingCandidate {
            hazard: None,
            protected_boundaries: 1,
            protected_credential_boundaries: 0,
            ..candidate("/cache/protected")
        }],
        FindingSource::WellKnownRoot,
        AuthorityConstraint::MixedStateAiToolDirectory,
    );

    assert_eq!(findings[0].disposition().mode, DispositionMode::ReportOnly);
    assert_eq!(
        findings[0].disposition().reason.as_deref(),
        Some(MIXED_STATE_AI_TOOL_REASON)
    );
    assert_eq!(findings[0].skipped(), 1);
    assert!(findings[0].measurement_incomplete());
    assert!(Plan::new(findings, true).is_err());
}
