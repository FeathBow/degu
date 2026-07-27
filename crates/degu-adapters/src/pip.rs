use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

pub struct Pip;

impl Ecosystem for Pip {
    fn id(&self) -> &'static str {
        "pip"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let mut candidates = Vec::new();
        if let Some(dir) = ctx.env("PIP_CACHE_DIR") {
            candidates.push(Root::redirect("PIP_CACHE_DIR", PathBuf::from(dir)));
        } else {
            candidates.push(crate::xdg_cache_or_platform(ctx, "pip"));
        }
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "PIP_CACHE_DIR",
            subdir: "pip",
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
                rationale: "pip download cache; rebuilt automatically on next install, installed environments unaffected",
            },
        )
    }
}
