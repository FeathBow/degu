use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const RATIONALE: &str =
    "sccache compiler cache; deleting costs full recompilation at PyTorch-from-source scale";

pub struct Sccache;

impl Ecosystem for Sccache {
    fn id(&self) -> &'static str {
        "sccache"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidate = ctx
            .env("SCCACHE_DIR")
            .map(|dir| Root::redirect("SCCACHE_DIR", PathBuf::from(dir)))
            .unwrap_or_else(|| {
                // The `directories` crate names sccache's macOS dir Mozilla.sccache,
                // so this is asymmetric with the plain XDG "sccache" elsewhere.
                #[cfg(target_os = "macos")]
                {
                    Root::well_known(ctx.home.join("Library/Caches/Mozilla.sccache"))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    ctx.xdg_cache().join("sccache")
                }
            });
        crate::resolve_existing_roots(ctx, self.id(), [candidate])
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "SCCACHE_DIR",
            subdir: "sccache",
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
