use anyhow::{Context, Result};
use degu_core::ecosystem::{DetectCtx, Root};
use degu_core::finding::FindingCandidate;
use degu_core::safety::paths_overlap;
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
pub(crate) struct ExclusionClaims {
    identities: Vec<PathBuf>,
    lexical_roots: Vec<PathBuf>,
    pub(crate) dependencies: Vec<PathBuf>,
}

impl ExclusionClaims {
    pub(crate) fn root_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.identities.iter().chain(&self.lexical_roots)
    }

    pub(super) fn extend(&mut self, other: Self) {
        self.identities.extend(other.identities);
        self.lexical_roots.extend(other.lexical_roots);
        self.dependencies.extend(other.dependencies);
    }

    pub(super) fn sort_and_dedup(&mut self) {
        for paths in [
            &mut self.identities,
            &mut self.lexical_roots,
            &mut self.dependencies,
        ] {
            paths.sort_unstable();
            paths.dedup();
        }
    }
}

pub(super) fn root_claims(
    ctx: &DetectCtx,
    adapter: &str,
    roots: &[Root],
) -> Result<Option<ExclusionClaims>> {
    let mut claims = ExclusionClaims::default();
    for root in roots {
        if ctx.deadline_elapsed() {
            return Ok(None);
        }
        let lexical = std::path::absolute(&root.path).with_context(|| {
            format!(
                "failed to resolve adapter {adapter:?} root {}",
                root.path.display()
            )
        })?;
        if ctx.deadline_elapsed() {
            return Ok(None);
        }
        let canonical = std::fs::canonicalize(&root.path).with_context(|| {
            format!(
                "failed to canonicalize adapter {adapter:?} root {}",
                root.path.display()
            )
        })?;
        let Some((namespace_root, dependencies)) =
            resolve_namespace(ctx, &lexical).with_context(|| {
                format!(
                    "failed to resolve adapter {adapter:?} namespace {}",
                    root.path.display()
                )
            })?
        else {
            return Ok(None);
        };
        claims.identities.push(canonical);
        claims.lexical_roots.push(lexical);
        claims.lexical_roots.extend(namespace_root);
        claims.dependencies.extend(dependencies);
    }
    Ok(Some(claims))
}

fn resolve_namespace(
    ctx: &DetectCtx,
    path: &Path,
) -> Result<Option<(Option<PathBuf>, Vec<PathBuf>)>> {
    if ctx.deadline_elapsed() {
        return Ok(None);
    }
    let namespace_root = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Some(std::fs::canonicalize(parent)?.join(name)),
        _ => None,
    };
    let mut prefix = PathBuf::new();
    let mut dependencies = Vec::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        let Component::Normal(name) = component else {
            continue;
        };
        let parent = prefix
            .parent()
            .context("absolute namespace component has no parent")?;
        if ctx.deadline_elapsed() {
            return Ok(None);
        }
        let canonical_parent = std::fs::canonicalize(parent).with_context(|| {
            format!(
                "failed to canonicalize namespace parent {}",
                parent.display()
            )
        })?;
        dependencies.push(canonical_parent.join(name));
        if ctx.deadline_elapsed() {
            return Ok(None);
        }
        dependencies.push(std::fs::canonicalize(&prefix).with_context(|| {
            format!(
                "failed to canonicalize namespace prefix {}",
                prefix.display()
            )
        })?);
    }
    Ok(Some((namespace_root, dependencies)))
}

/// Removes candidates overlapping an excluded adapter root and returns the
/// removed paths, so callers can account for the lost coverage as
/// incomplete-region provenance.
pub(crate) fn exclude_claimed_candidates(
    candidates: &mut Vec<FindingCandidate>,
    claims: &ExclusionClaims,
) -> Result<Vec<PathBuf>> {
    if claims.is_empty() {
        return Ok(Vec::new());
    }
    let mut kept = Vec::with_capacity(candidates.len());
    let mut excluded = Vec::new();
    for candidate in std::mem::take(candidates) {
        if path_overlaps_claim(&candidate.path, claims)? {
            tracing::warn!(
                path = %candidate.path.display(),
                ecosystem = candidate.ecosystem,
                "finding overlaps an excluded adapter root"
            );
            excluded.push(candidate.path);
        } else {
            kept.push(candidate);
        }
    }
    *candidates = kept;
    Ok(excluded)
}

impl ExclusionClaims {
    fn is_empty(&self) -> bool {
        self.identities.is_empty() && self.lexical_roots.is_empty() && self.dependencies.is_empty()
    }
}

fn path_overlaps_claim(path: &Path, claims: &ExclusionClaims) -> Result<bool> {
    let lexical = std::path::absolute(path).with_context(|| {
        format!(
            "failed to resolve finding {} against exclusion claims",
            path.display()
        )
    })?;
    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "failed to compare finding {} with exclusion claims",
            path.display()
        )
    })?;
    let views = [lexical.as_path(), canonical.as_path()];
    let overlaps_root = claims
        .root_paths()
        .any(|claim| views.iter().any(|view| paths_overlap(view, claim)));
    let breaks_dependency = claims
        .dependencies
        .iter()
        .any(|dependency| views.iter().any(|view| dependency.starts_with(view)));
    Ok(overlaps_root || breaks_dependency)
}
