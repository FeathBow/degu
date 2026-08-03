use degu_core::finding::{
    Finding, FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
    finalize_findings,
};
use std::path::PathBuf;

pub(super) const HOME: &str = "/home/researcher";
const FIXTURE_BYTES: u64 = 16 * 1024;
const FIXTURE_AGE_DAYS: u64 = 42;
const FIXTURE_INODES: u64 = 7;

pub(super) fn huggingface_findings() -> Vec<Finding> {
    [
        "models--meta-llama--Llama-3.3-70B-Instruct-experimental-checkpoint-alpha",
        "models--meta-llama--Llama-3.3-70B-Instruct-experimental-checkpoint-beta",
        "models--研究--模型-e\u{301}-🧪-checkpoint-gamma",
    ]
    .into_iter()
    .map(|name| {
        test_finding(
            "huggingface",
            PathBuf::from(HOME)
                .join(".cache/huggingface/hub")
                .join(name),
            FindingKind::ModelCache,
        )
    })
    .collect()
}

pub(super) fn control_character_finding() -> Finding {
    let name = "models--escape-\u{1b}[2J-newline-\n-carriage-\r-tab-\t-backslash-\\literal-bidi-\u{202e}-zero-\u{200b}-joiner-\u{2060}-bom-\u{feff}-line-\u{2028}-paragraph-\u{2029}-combining-e\u{301}txt";
    test_finding(
        "huggingface",
        PathBuf::from(HOME)
            .join(".cache/huggingface/hub")
            .join(name),
        FindingKind::ModelCache,
    )
}

pub(super) fn conda_findings() -> Vec<Finding> {
    [
        "llm-finetuning-cuda-12-4-pytorch-2-6-production-alpha",
        "llm-finetuning-cuda-12-4-pytorch-2-6-production-beta",
    ]
    .into_iter()
    .map(|name| {
        test_finding(
            "conda",
            PathBuf::from(HOME).join(".conda/envs").join(name),
            FindingKind::Environment,
        )
    })
    .collect()
}

pub(super) fn oversized_source_finding() -> Finding {
    test_finding(
        "a-source-name-wide-enough-to-leave-no-readable-path-budget-in-a-120-column-table-at-all",
        PathBuf::from(HOME).join(".cache/some-tool"),
        FindingKind::PackageCache,
    )
}

pub(super) fn truncated_finding() -> Finding {
    let mut candidate = test_candidate(
        "pip",
        PathBuf::from(HOME).join(".cache/pip"),
        FindingKind::PackageCache,
    );
    candidate.truncated = true;
    finalize_test_candidate(candidate)
}

pub(super) fn skipped_finding() -> Finding {
    let mut candidate = test_candidate(
        "pip",
        PathBuf::from(HOME).join(".cache/pip"),
        FindingKind::PackageCache,
    );
    candidate.skipped = 1;
    finalize_test_candidate(candidate)
}

fn test_finding(ecosystem: &str, path: PathBuf, kind: FindingKind) -> Finding {
    finalize_test_candidate(test_candidate(ecosystem, path, kind))
}

fn test_candidate(ecosystem: &str, path: PathBuf, kind: FindingKind) -> FindingCandidate {
    let recovery = match kind {
        FindingKind::Environment => Recovery::UserAsset,
        _ => Recovery::Regenerable {
            cost: RegenCost::Costly,
        },
    };
    FindingCandidate {
        ecosystem: ecosystem.to_string(),
        path,
        kind,
        bytes_apparent: FIXTURE_BYTES,
        bytes_allocated: FIXTURE_BYTES,
        age_days: Some(FIXTURE_AGE_DAYS),
        bytes_hardlinked: 0,
        inodes: FIXTURE_INODES,
        skipped: 0,
        truncated: false,
        unvisited_dirs: 0,
        shared_writable_dirs: 0,
        protected_boundaries: 0,
        protected_credential_boundaries: 0,
        recovery,
        ownership: Ownership::Standalone,
        hazard: None,
        rationale: "realistic narrow-terminal fixture".to_string(),
    }
}

fn finalize_test_candidate(candidate: FindingCandidate) -> Finding {
    finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
        .pop()
        .unwrap()
}
