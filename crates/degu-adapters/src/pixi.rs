use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str = "pixi / rattler package cache -- downloaded conda packages, re-downloaded on the next pixi install";

pub struct Pixi;

impl Ecosystem for Pixi {
    fn id(&self) -> &'static str {
        "pixi"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        if let Some(dir) = ctx.env("PIXI_CACHE_DIR") {
            return crate::resolve_existing_roots(
                ctx,
                self.id(),
                [Root::redirect("PIXI_CACHE_DIR", PathBuf::from(dir))],
            );
        }
        if let Some(dir) = ctx.env("RATTLER_CACHE_DIR") {
            return crate::resolve_existing_roots(
                ctx,
                self.id(),
                [Root::redirect("RATTLER_CACHE_DIR", PathBuf::from(dir))],
            );
        }
        // A `[cache.root]` set in pixi's config.toml is out of scope.
        let rattler = || {
            crate::resolve_existing_roots(
                ctx,
                self.id(),
                [crate::platform_cache_root(ctx, "rattler/cache")],
            )
        };
        let legacy = crate::resolve_existing_roots(
            ctx,
            self.id(),
            [crate::xdg_cache_or_platform(ctx, "pixi")],
        );
        crate::first_present(legacy, rattler)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "PIXI_CACHE_DIR",
            subdir: "pixi",
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
