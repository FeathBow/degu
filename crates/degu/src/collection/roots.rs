use super::ProjectRoots;
use anyhow::{Context, Result};
use degu_adapters::discovery::{ResolvedProjectRoot, ValidatedProjectRoot};
use degu_core::config::Config;
use degu_core::ecosystem::DetectCtx;
use degu_core::safety::{MIXED_STATE_AI_TOOL_REASON, ProtectionPolicy};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub(crate) fn artifact_roots(
    ctx: &DetectCtx,
    requested: ProjectRoots,
    config: &Config,
) -> Result<Vec<ValidatedProjectRoot>> {
    let roots = requested_roots(ctx, requested, config);
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let protection = ProtectionPolicy::for_mixed_state_ai(&ctx.home)?;
    let mut canonical_roots = Vec::new();
    let mut seen = HashSet::new();
    for requested in roots {
        let resolved = ResolvedProjectRoot::resolve(&requested)?;
        ensure_project_root_allowed(&requested, resolved.as_path(), &protection)?;
        let root = resolved.validate()?;
        if seen.insert(root.clone()) {
            canonical_roots.push(root);
        }
    }
    canonical_roots.sort_by_key(|root| root.as_path().components().count());
    let mut scoped_roots = Vec::<ValidatedProjectRoot>::new();
    for root in canonical_roots {
        if !scoped_roots
            .iter()
            .any(|scope| root.as_path().starts_with(scope.as_path()))
        {
            scoped_roots.push(root);
        }
    }
    Ok(scoped_roots)
}

fn ensure_project_root_allowed(
    root: &Path,
    resolved: &Path,
    protection: &ProtectionPolicy,
) -> Result<()> {
    let lexical = std::path::absolute(root)
        .with_context(|| format!("failed to resolve project root {}", root.display()))?;
    if let Some(protected) = protection.contains_resolved(&[&lexical, resolved]) {
        anyhow::bail!(
            "project root {} is excluded: {MIXED_STATE_AI_TOOL_REASON} ({})",
            root.display(),
            protected.display()
        );
    }
    Ok(())
}

fn requested_roots(ctx: &DetectCtx, requested: ProjectRoots, config: &Config) -> Vec<PathBuf> {
    match requested {
        ProjectRoots::ReadOnlyDiscovery(cli_roots) => {
            let mut roots = config
                .roots
                .iter()
                .map(|entry| config_root_path(ctx, entry))
                .collect::<Vec<_>>();
            roots.extend(cli_roots);
            roots
        }
        ProjectRoots::CleanupAuthorized(cli_roots) => cli_roots,
    }
}

fn config_root_path(ctx: &DetectCtx, entry: &str) -> PathBuf {
    if let Some(rest) = entry.strip_prefix("~/") {
        ctx.home.join(rest)
    } else {
        PathBuf::from(entry)
    }
}
