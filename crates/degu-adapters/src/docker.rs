use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery};

const RATIONALE: &str = "docker images and live container and volume state; measure and review, then use docker system df and docker system prune; degu will not touch it";

pub struct Docker;

impl Ecosystem for Docker {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            Root::well_known(ctx.home.join("Library/Containers/com.docker.docker/Data")),
            ctx.xdg_data().join("docker"),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        // The Docker data dir holds the VM disk image with all volumes and
        // container state -- not regenerable, so report-only rather than a cache.
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
