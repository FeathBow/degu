use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "PyTorch cache root may contain hub models and checkpoints; regenerable, but re-download costs real transfer";

pub struct Torch;

impl Ecosystem for Torch {
    fn id(&self) -> &'static str {
        "torch"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("TORCH_HOME")
                .map(|dir| Root::redirect("TORCH_HOME", PathBuf::from(dir)))
                .unwrap_or_else(|| ctx.xdg_cache().join("torch")),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "TORCH_HOME",
            subdir: "torch",
            role: None,
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
                kind: FindingKind::ModelCache,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}
