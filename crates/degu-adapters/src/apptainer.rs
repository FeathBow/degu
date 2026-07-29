use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

pub struct Apptainer;

impl Ecosystem for Apptainer {
    fn id(&self) -> &'static str {
        "apptainer"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let root = ctx
            .env("APPTAINER_CACHEDIR")
            .map(|dir| Root::redirect("APPTAINER_CACHEDIR", PathBuf::from(dir)))
            .or_else(|| {
                ctx.env("SINGULARITY_CACHEDIR")
                    .map(|dir| Root::redirect("SINGULARITY_CACHEDIR", PathBuf::from(dir)))
            })
            .unwrap_or_else(|| Root::well_known(ctx.home.join(".apptainer/cache")));
        let candidates = vec![root];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "APPTAINER_CACHEDIR",
            subdir: "apptainer",
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
                kind: FindingKind::ContainerCache,
                facts: self.stated_facts(root),
                rationale: "apptainer OCI blob/build cache; rebuilt on the next pull or build, user's own .sif images live elsewhere and are untouched",
            },
        )
    }
}
