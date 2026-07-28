use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery};

const RATIONALE: &str = "podman shared image layers and live container state; measure and review, then use podman system prune; degu will not touch it";

pub struct Podman;

impl Ecosystem for Podman {
    fn id(&self) -> &'static str {
        "podman"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let root = ctx.xdg_data().join("containers/storage");
        crate::resolve_existing_roots(ctx, self.id(), vec![root])
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        // Container storage holds live container state alongside image layers --
        // not regenerable as a whole, so report-only rather than a cache.
        (Recovery::UserAsset, Ownership::ToolCoordinated, None)
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::ContainerCache,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}
