use super::super::EntryIdentity;
use anyhow::{Context, Result};
use degu_core::finding::Finding;
use degu_core::plan::Plan;
use degu_core::safety::paths_overlap;
use std::path::PathBuf;

pub(crate) struct CapturedCleanPlan {
    plan: Plan,
    // Preview-only plans may retain no child identity when source-parent
    // search requires the execution seal. Such plans never reach mutation;
    // every execution accessor fails loudly if that invariant is violated.
    identities: Box<[Option<EntryIdentity>]>,
    atomic_batch_preflight: bool,
}

impl CapturedCleanPlan {
    /// Captures a normal full-scope plan. Production retains per-item admission
    /// and execution semantics for these plans.
    pub(crate) fn capture(plan: Plan) -> Result<Self> {
        Self::capture_with_policy(plan, false)
    }

    /// Captures an explicit `--path`/`--review` selection whose entire batch
    /// must pass data-only production admission before any item may mutate.
    pub(crate) fn capture_atomic_selection(plan: Plan) -> Result<Self> {
        Self::capture_with_policy(plan, true)
    }

    fn capture_with_policy(plan: Plan, atomic_batch_preflight: bool) -> Result<Self> {
        validate_path_separation(&plan)?;
        let identities = capture_identities(&plan)?
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            plan,
            identities,
            atomic_batch_preflight,
        })
    }

    /// Captures a display-only dry-run plan without turning a source-parent
    /// search deferral into a child canonicalization failure. Preview facts are
    /// not retained here and cannot mint execution authority; non-dry-run
    /// callers must use `capture` variants.
    pub(crate) fn capture_preview(plan: Plan, atomic_batch_preflight: bool) -> Result<Self> {
        validate_preview_path_separation(&plan)?;
        // Never project preview facts into the executable plan. A preview plan
        // is display-only and deliberately lacks every identity required by
        // `items_with_identities`.
        let identities = vec![None; plan.items().len()].into_boxed_slice();
        Ok(Self {
            plan,
            identities,
            atomic_batch_preflight,
        })
    }

    pub(crate) fn requires_atomic_batch_preflight(&self) -> bool {
        self.atomic_batch_preflight
    }

    pub(crate) fn items(&self) -> &[Finding] {
        self.plan.items()
    }

    pub(crate) fn total_bytes_allocated(&self) -> u64 {
        self.plan.total_bytes_allocated()
    }

    pub(crate) fn items_with_identities(&self) -> impl Iterator<Item = (&Finding, &EntryIdentity)> {
        self.plan
            .items()
            .iter()
            .zip(&self.identities)
            .map(|(finding, identity)| {
                (
                    finding,
                    identity
                        .as_ref()
                        .expect("preview-only clean plan reached execution"),
                )
            })
    }

    pub(crate) fn validate_path_separation(&self) -> Result<()> {
        validate_path_separation(&self.plan)
    }
}

fn validate_path_separation(plan: &Plan) -> Result<()> {
    validate_separated(
        plan.items()
            .iter()
            .map(canonical_plan_path)
            .collect::<Result<Vec<_>>>()?,
    )
}

fn validate_preview_path_separation(plan: &Plan) -> Result<()> {
    validate_separated(
        plan.items()
            .iter()
            .map(|finding| {
                let original = finding.path().to_path_buf();
                let parent = original.parent().ok_or_else(|| {
                    anyhow::anyhow!("preview clean item has no parent: {}", original.display())
                })?;
                let basename = original.file_name().map(ToOwned::to_owned).ok_or_else(|| {
                    anyhow::anyhow!("preview clean item has no basename: {}", original.display())
                })?;
                let canonical_parent = std::fs::canonicalize(parent).with_context(|| {
                    format!(
                        "failed to canonicalize preview clean item parent {}",
                        parent.display()
                    )
                })?;
                Ok((original, canonical_parent.join(basename)))
            })
            .collect::<Result<Vec<_>>>()?,
    )
}

fn validate_separated(mut paths: Vec<(PathBuf, PathBuf)>) -> Result<()> {
    paths.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));
    for pair in paths.windows(2) {
        let (left, right) = (&pair[0], &pair[1]);
        if paths_overlap(&left.1, &right.1) {
            anyhow::bail!(
                "clean plan paths overlap after canonicalization: {} -> {}; {} -> {}",
                left.0.display(),
                left.1.display(),
                right.0.display(),
                right.1.display()
            );
        }
    }
    Ok(())
}

fn canonical_plan_path(finding: &Finding) -> Result<(PathBuf, PathBuf)> {
    let original = finding.path().to_path_buf();
    let canonical = std::fs::canonicalize(&original)
        .with_context(|| format!("failed to canonicalize clean item {}", original.display()))?;
    Ok((original, canonical))
}

fn capture_identities(plan: &Plan) -> Result<Vec<EntryIdentity>> {
    plan.items()
        .iter()
        .map(|finding| {
            EntryIdentity::capture(finding.path()).with_context(|| {
                format!("failed to snapshot clean item {}", finding.path().display())
            })
        })
        .collect()
}
