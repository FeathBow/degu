use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Hazard, Ownership, Recovery, RegenCost};
use std::path::PathBuf;

const ROLE_OBJECTS: &str = "objects";
const ROLE_TEMPORARY: &str = "temporary";
const OBJECT_RATIONALE: &str = "W&B artifact object cache; W&B coordinates content-addressed objects and provides LRU cleanup, so degu reports it without cleaning it. Reclaim through `wandb artifact cache cleanup TARGET_SIZE`";
const TEMPORARY_RATIONALE: &str = "W&B artifact temporary files may be active writes; degu reports them without cleaning them. Only consider `wandb artifact cache cleanup --remove-temp TARGET_SIZE` after confirming no artifact operation is active";

pub struct Wandb;

impl Ecosystem for Wandb {
    fn id(&self) -> &'static str {
        "wandb"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let artifacts = ctx
            .env("WANDB_CACHE_DIR")
            .map(|dir| Root::redirect("WANDB_CACHE_DIR", PathBuf::from(dir)))
            .unwrap_or_else(|| crate::platform_cache_root(ctx, "wandb"))
            .join("artifacts");
        let candidates = vec![
            artifacts.clone().join("obj").with_role(ROLE_OBJECTS),
            artifacts.join("tmp").with_role(ROLE_TEMPORARY),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "WANDB_CACHE_DIR",
            subdir: "wandb",
            role: None,
        }]
    }

    fn stated_facts(&self, root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Costly,
            },
            Ownership::ToolCoordinated,
            (root.role == Some(ROLE_TEMPORARY)).then_some(Hazard::ActiveUse),
        )
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        let rationale = if root.role == Some(ROLE_TEMPORARY) {
            TEMPORARY_RATIONALE
        } else {
            OBJECT_RATIONALE
        };
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::Other,
                facts: self.stated_facts(root),
                rationale,
            },
        )
    }
}
