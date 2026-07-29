use super::super::EntryIdentity;
use anyhow::{Context, Result};
use degu_core::finding::Finding;
use degu_core::plan::Plan;
use degu_core::safety::paths_overlap;
use std::path::PathBuf;

pub(crate) struct CapturedCleanPlan {
    plan: Plan,
    identities: Box<[EntryIdentity]>,
}

impl CapturedCleanPlan {
    pub(crate) fn capture(plan: Plan) -> Result<Self> {
        validate_path_separation(&plan)?;
        let identities = capture_identities(&plan)?.into_boxed_slice();
        Ok(Self { plan, identities })
    }

    pub(crate) fn items(&self) -> &[Finding] {
        self.plan.items()
    }

    pub(crate) fn total_bytes_allocated(&self) -> u64 {
        self.plan.total_bytes_allocated()
    }

    pub(crate) fn items_with_identities(&self) -> impl Iterator<Item = (&Finding, &EntryIdentity)> {
        self.plan.items().iter().zip(&self.identities)
    }

    pub(crate) fn validate_path_separation(&self) -> Result<()> {
        validate_path_separation(&self.plan)
    }
}

fn validate_path_separation(plan: &Plan) -> Result<()> {
    let mut paths = plan
        .items()
        .iter()
        .map(canonical_plan_path)
        .collect::<Result<Vec<_>>>()?;
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
