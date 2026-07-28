use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

pub struct Uv;

impl Ecosystem for Uv {
    fn id(&self) -> &'static str {
        "uv"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let mut candidates = Vec::new();
        if let Some(dir) = ctx.env("UV_CACHE_DIR") {
            candidates.push(Root::redirect("UV_CACHE_DIR", PathBuf::from(dir)));
        } else {
            // uv follows XDG on macOS too, so no ~/Library/Caches probe.
            candidates.push(ctx.xdg_cache().join("uv"));
        }
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            Ownership::ToolCoordinated,
            None,
        )
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "UV_CACHE_DIR",
            subdir: "uv",
        }]
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale: "uv download/build cache; uv documents that modifying the cache directly is never safe and coordinates mutations with locks, so degu does not clean it until it can participate in that protocol -- reclaim with uv cache clean or uv cache prune. Installed environments unaffected.",
            },
        )
    }
}
