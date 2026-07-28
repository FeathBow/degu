use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery};

const RATIONALE: &str = "orbstack machine and container data; measure and review, then prune from inside orbstack or with docker system prune; degu will not touch it";

pub struct Orbstack;

impl Ecosystem for Orbstack {
    fn id(&self) -> &'static str {
        "orbstack"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let root = Root::well_known(
            ctx.home
                .join("Library/Group Containers/HUAQ24HBR6.dev.orbstack/data"),
        );
        crate::resolve_existing_roots(ctx, self.id(), vec![root])
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        // OrbStack machine and container data is user state, not a regenerable
        // cache -- report-only.
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
