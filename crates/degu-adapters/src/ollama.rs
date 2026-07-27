use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery};
use std::path::PathBuf;

pub struct Ollama;

impl Ecosystem for Ollama {
    fn id(&self) -> &'static str {
        "ollama"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("OLLAMA_MODELS")
                .map(|dir| Root::redirect("OLLAMA_MODELS", PathBuf::from(dir)))
                .unwrap_or_else(|| Root::well_known(ctx.home.join(".ollama/models"))),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (Recovery::UserAsset, Ownership::ToolCoordinated, None)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "OLLAMA_MODELS",
            subdir: "ollama",
        }]
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::ModelCache,
                facts: self.stated_facts(root),
                rationale: "mixed Ollama model store containing pulled and locally created models; local models may have no recoverable source, so degu reports the store but never deletes it",
            },
        )
    }
}
