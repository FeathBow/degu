use degu_core::ecosystem::{
    DetectCtx, Ecosystem, RelocationRefusal, Root, RootOutcome, ScanOutcome,
};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

pub struct Cargo;

const CARGO_HOME_RELOCATION_REFUSAL_REASON: &str =
    "CARGO_HOME also carries installed binaries and credentials, so degu leaves it unchanged";

impl Ecosystem for Cargo {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn relocation_refusals(&self) -> Vec<RelocationRefusal> {
        vec![RelocationRefusal {
            var: "CARGO_HOME",
            reason: CARGO_HOME_RELOCATION_REFUSAL_REASON,
        }]
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let home = ctx
            .env("CARGO_HOME")
            .map(|home| Root::redirect("CARGO_HOME", PathBuf::from(home)))
            .unwrap_or_else(|| Root::well_known(ctx.home.join(".cargo")));

        let candidates = vec![home.clone().join("registry"), home.join("git")];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
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
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale: "cargo registry and git caches are re-fetched on the next build; installed binaries and project sources are unaffected",
            },
        )
    }
}
