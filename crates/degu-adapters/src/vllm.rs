use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str =
    "vLLM compile cache; deleting costs cold-start recompilation per model, not source data";

pub struct Vllm;

impl Ecosystem for Vllm {
    fn id(&self) -> &'static str {
        "vllm"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("VLLM_CACHE_ROOT")
                .map(|dir| Root::redirect("VLLM_CACHE_ROOT", PathBuf::from(dir)))
                .unwrap_or_else(|| ctx.xdg_cache().join("vllm")),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "VLLM_CACHE_ROOT",
            subdir: "vllm",
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
