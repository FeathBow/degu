use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str =
    "ccache compiler cache; deleting costs full recompilation at PyTorch-from-source scale";

pub struct Ccache;

impl Ecosystem for Ccache {
    fn id(&self) -> &'static str {
        "ccache"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        primary_root(ctx)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "CCACHE_DIR",
            subdir: "ccache",
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
                kind: FindingKind::BuildArtifact,
                facts: self.stated_facts(root),
                rationale: RATIONALE,
            },
        )
    }
}

fn primary_root(ctx: &DetectCtx) -> RootOutcome {
    if let Some(dir) = ctx.env("CCACHE_DIR") {
        return crate::resolve_existing_roots(
            ctx,
            "ccache",
            vec![Root::redirect("CCACHE_DIR", PathBuf::from(dir))],
        );
    }
    let legacy = ctx.home.join(".ccache");
    let legacy = crate::resolve_existing_roots(ctx, "ccache", vec![Root::well_known(legacy)]);
    crate::first_present(legacy, || {
        let root = crate::xdg_cache_or_platform(ctx, "ccache");
        crate::resolve_existing_roots(ctx, "ccache", vec![root])
    })
}
