use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::FindingFacts;

pub struct Shm;

impl Ecosystem for Shm {
    fn id(&self) -> &'static str {
        "shm"
    }

    fn roots(&self, _ctx: &DetectCtx) -> RootOutcome {
        RootOutcome::default()
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        super::FACTS
    }

    fn platform_requirement(&self) -> Option<&'static str> {
        Some("Linux")
    }

    fn scan(&self, _root: &Root, _ctx: &DetectCtx) -> ScanOutcome {
        ScanOutcome::default()
    }
}
