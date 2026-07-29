use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "helm chart repository indexes and chart archives; re-fetched transparently on next helm repo update or install, credentials live under helm config home";

pub struct Helm;

impl Ecosystem for Helm {
    fn id(&self) -> &'static str {
        "helm"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidate = ctx
            .env("HELM_CACHE_HOME")
            .map(|dir| Root::redirect("HELM_CACHE_HOME", PathBuf::from(dir)))
            .unwrap_or_else(|| crate::xdg_cache_or_platform(ctx, "helm"));
        crate::resolve_existing_roots(ctx, self.id(), [candidate])
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "HELM_CACHE_HOME",
            subdir: "helm",
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
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}
