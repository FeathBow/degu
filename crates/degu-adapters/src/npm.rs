use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

pub struct Npm;

impl Ecosystem for Npm {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let lowercase = ctx.env("npm_config_cache");
        let uppercase = ctx.env("NPM_CONFIG_CACHE");
        let candidate = match (lowercase, uppercase) {
            (Some(lower), Some(upper)) if lower != upper => {
                tracing::warn!("npm_config_cache and NPM_CONFIG_CACHE point to different roots");
                let candidates = vec![
                    Root::redirect("npm_config_cache", PathBuf::from(lower)),
                    Root::redirect("NPM_CONFIG_CACHE", PathBuf::from(upper)),
                ];
                let mut outcome = crate::resolve_existing_roots(ctx, self.id(), candidates);
                outcome.mark_incomplete();
                return outcome;
            }
            (Some(dir), _) => Root::redirect("npm_config_cache", PathBuf::from(dir)),
            (None, Some(dir)) => Root::redirect("NPM_CONFIG_CACHE", PathBuf::from(dir)),
            (None, None) => Root::well_known(ctx.home.join(".npm")),
        };
        crate::resolve_existing_roots(ctx, self.id(), vec![candidate])
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "npm_config_cache",
            subdir: "npm",
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
                rationale: "npm's content-addressable download cache; re-fetched on demand, installed node_modules unaffected",
            },
        )
    }
}
