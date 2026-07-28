use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::ffi::OsStr;
use std::path::PathBuf;

const RATIONALE: &str = "JAX JIT compilation cache; deletion costs recompilation";

pub struct Jax;

impl Ecosystem for Jax {
    fn id(&self) -> &'static str {
        "jax"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        if ctx
            .env("JAX_COMPILATION_CACHE_DIR")
            .is_some_and(is_remote_cache)
        {
            return RootOutcome::default();
        }
        let candidates = ctx
            .env("JAX_COMPILATION_CACHE_DIR")
            .map(|dir| Root::redirect("JAX_COMPILATION_CACHE_DIR", PathBuf::from(dir)))
            .into_iter();
        crate::resolve_existing_roots(ctx, self.id(), candidates)
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

fn is_remote_cache(value: &OsStr) -> bool {
    value
        .to_str()
        .is_some_and(|value| value.starts_with("gs://"))
}
