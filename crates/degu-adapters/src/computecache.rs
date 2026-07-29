use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "NVIDIA driver ComputeCache JIT cache; driver-managed and regenerable, but can matter under tight home quotas";

pub struct Computecache;

impl Ecosystem for Computecache {
    fn id(&self) -> &'static str {
        "computecache"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("CUDA_CACHE_PATH")
                .map(|dir| Root::redirect("CUDA_CACHE_PATH", PathBuf::from(dir)))
                .unwrap_or_else(|| Root::well_known(ctx.home.join(".nv/ComputeCache"))),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "CUDA_CACHE_PATH",
            subdir: "nv-computecache",
            role: None,
        }]
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            Ownership::Standalone,
            None,
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::BuildArtifact,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}
