use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Hazard, Ownership, Recovery};

const RATIONALE: &str = "mixed VS Code remote state, including server binaries, extensions, settings, and extension data; manage it through VS Code or Cursor";

pub struct Vscode;

impl Ecosystem for Vscode {
    fn id(&self) -> &'static str {
        "vscode"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            Root::well_known(ctx.home.join(".vscode-server")),
            Root::well_known(ctx.home.join(".vscode-server-insiders")),
            Root::well_known(ctx.home.join(".cursor-server")),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::UserAsset,
            Ownership::ToolCoordinated,
            Some(Hazard::ActiveUse),
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::Other,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}
