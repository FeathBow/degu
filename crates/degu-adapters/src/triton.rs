use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "Triton compile cache; deleting costs kernel recompilation";

pub struct Triton;

impl Ecosystem for Triton {
    fn id(&self) -> &'static str {
        "triton"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("TRITON_CACHE_DIR")
                .map(|dir| Root::redirect("TRITON_CACHE_DIR", PathBuf::from(dir)))
                .unwrap_or_else(|| Root::well_known(ctx.home.join(".triton/cache"))),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "TRITON_CACHE_DIR",
            subdir: "triton",
        }]
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Costly,
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
