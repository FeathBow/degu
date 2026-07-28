use degu_core::ecosystem::{
    DetectCtx, Ecosystem, Relocation, RelocationRefusal, Root, RootOutcome, ScanOutcome,
};
use degu_core::finding::FindingFacts;
use std::path::PathBuf;

mod scan;

pub struct Huggingface;

const ROLE_HUB: &str = "hub";
const ROLE_DATASETS: &str = "datasets";
const ROLE_XET: &str = "xet";
const HUB_REPO_PREFIXES: [&str; 3] = ["models--", "datasets--", "spaces--"];
const HF_HOME_RELOCATION_REFUSAL_REASON: &str = "HF_HOME also decides where huggingface-cli login writes its token; degu does not move credentials";

impl Ecosystem for Huggingface {
    fn id(&self) -> &'static str {
        "huggingface"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let home = huggingface_home(ctx);
        let mut candidates = Vec::new();
        candidates.push(
            ctx.env("HF_HUB_CACHE")
                .map(|dir| Root::redirect("HF_HUB_CACHE", PathBuf::from(dir)))
                .or_else(|| {
                    ctx.env("HUGGINGFACE_HUB_CACHE")
                        .map(|dir| Root::redirect("HUGGINGFACE_HUB_CACHE", PathBuf::from(dir)))
                })
                .map(|root| root.with_role(ROLE_HUB))
                .unwrap_or_else(|| home.clone().join("hub").with_role(ROLE_HUB)),
        );
        candidates.push(
            ctx.env("HF_DATASETS_CACHE")
                .map(|dir| {
                    Root::redirect("HF_DATASETS_CACHE", PathBuf::from(dir)).with_role(ROLE_DATASETS)
                })
                .unwrap_or_else(|| home.clone().join("datasets").with_role(ROLE_DATASETS)),
        );
        candidates.push(
            ctx.env("HF_XET_CACHE")
                .map(|dir| Root::redirect("HF_XET_CACHE", PathBuf::from(dir)).with_role(ROLE_XET))
                .unwrap_or_else(|| home.join("xet").with_role(ROLE_XET)),
        );
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![
            Relocation {
                var: "HF_HUB_CACHE",
                subdir: "huggingface/hub",
            },
            Relocation {
                var: "HF_DATASETS_CACHE",
                subdir: "huggingface/datasets",
            },
            Relocation {
                var: "HF_XET_CACHE",
                subdir: "huggingface/xet",
            },
        ]
    }

    fn relocation_refusals(&self) -> Vec<RelocationRefusal> {
        vec![RelocationRefusal {
            var: "HF_HOME",
            reason: HF_HOME_RELOCATION_REFUSAL_REASON,
        }]
    }

    fn stated_facts(&self, root: &Root) -> FindingFacts {
        if root.role == Some(ROLE_HUB) {
            scan::costly_facts()
        } else {
            scan::coordinated_facts()
        }
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        if root.role == Some(ROLE_HUB) {
            return scan::hub(&root.path, ctx, self.id());
        }

        scan::whole_root(&root.path, ctx, self.id())
    }
}

fn huggingface_home(ctx: &DetectCtx) -> Root {
    ctx.env("HF_HOME")
        .map(|home| Root::redirect("HF_HOME", PathBuf::from(home)))
        .unwrap_or_else(|| ctx.xdg_cache().join("huggingface"))
}
