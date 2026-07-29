mod claims;

use crate::source_selection::SourceSelection;
use anyhow::{Context, Result};
use degu_adapters::{AdapterScope, RegisteredAdapter};
use degu_core::ecosystem::{DetectCtx, Root, RootOutcome};
use std::collections::HashSet;
use std::path::PathBuf;

pub(crate) use claims::{
    ExclusionClaims, exclude_claimed_candidates, validate_clean_plan_disablement,
};

pub(crate) struct PreparedAdapters {
    pub(crate) enabled: Vec<PreparedAdapter>,
    pub(crate) claimed_roots: Vec<PathBuf>,
    pub(crate) exclusion_claims: ExclusionClaims,
    pub(crate) truncated: bool,
}

impl PreparedAdapters {
    fn truncated() -> Self {
        Self {
            enabled: Vec::new(),
            claimed_roots: Vec::new(),
            exclusion_claims: ExclusionClaims::default(),
            truncated: true,
        }
    }
}

pub(crate) struct PreparedAdapter {
    pub(crate) registration: RegisteredAdapter,
    pub(crate) roots: Vec<Root>,
    pub(crate) incomplete: bool,
}

pub(crate) struct RootResolutionPolicy<'a> {
    pub(crate) sources: &'a SourceSelection,
    pub(crate) project_claims: bool,
}

struct ResolvedAdapter {
    registration: RegisteredAdapter,
    outcome: RootOutcome,
    selected: bool,
}

pub(crate) fn prepare_adapters(
    ctx: &DetectCtx,
    disabled: &HashSet<&str>,
    policy: RootResolutionPolicy<'_>,
) -> Result<PreparedAdapters> {
    let project_claims = policy.project_claims;
    let Some(adapters) = resolve_adapters(ctx, disabled, policy)? else {
        return Ok(PreparedAdapters::truncated());
    };
    let claims = collect_claims(ctx, &adapters, project_claims)?;
    let Some((mut claimed_roots, mut exclusion_claims)) = claims else {
        return Ok(PreparedAdapters::truncated());
    };
    claimed_roots.sort_unstable();
    claimed_roots.dedup();
    exclusion_claims.sort_and_dedup();
    let enabled = adapters
        .into_iter()
        .filter(|adapter| adapter.selected)
        .map(|adapter| {
            let RootOutcome {
                roots, incomplete, ..
            } = adapter.outcome;
            PreparedAdapter {
                registration: adapter.registration,
                roots,
                incomplete,
            }
        })
        .collect();
    let truncated = ctx.deadline_elapsed();
    if truncated {
        tracing::debug!(target: "degu", "budget exhausted finalizing adapter preparation");
    }
    Ok(PreparedAdapters {
        enabled,
        claimed_roots,
        exclusion_claims,
        truncated,
    })
}

fn resolve_adapters(
    ctx: &DetectCtx,
    disabled: &HashSet<&str>,
    policy: RootResolutionPolicy<'_>,
) -> Result<Option<Vec<ResolvedAdapter>>> {
    let mut resolved = Vec::new();
    for registration in degu_adapters::all() {
        if ctx.deadline_elapsed() {
            tracing::debug!(target: "degu", adapter = registration.id(), "budget exhausted before adapter root resolution");
            return Ok(None);
        }
        if !should_resolve_roots(&registration, policy.sources, disabled) {
            continue;
        }
        let selected = is_selected(&registration, policy.sources, disabled);
        let outcome = registration.ecosystem().roots(ctx);
        let project_claim = registration.scope() == AdapterScope::Cache && policy.project_claims;
        if outcome.incomplete && (!selected || project_claim) {
            return Err(root_resolution_error(registration.id(), &outcome));
        }
        if outcome.truncated || ctx.deadline_elapsed() {
            tracing::debug!(target: "degu", adapter = registration.id(), "budget exhausted during adapter root resolution");
            return Ok(None);
        }
        resolved.push(ResolvedAdapter {
            registration,
            outcome,
            selected,
        });
    }
    Ok(Some(resolved))
}

fn collect_claims(
    ctx: &DetectCtx,
    adapters: &[ResolvedAdapter],
    project_claims: bool,
) -> Result<Option<(Vec<PathBuf>, ExclusionClaims)>> {
    let mut claimed_roots = Vec::new();
    let mut exclusion_claims = ExclusionClaims::default();
    for adapter in adapters {
        if ctx.deadline_elapsed() {
            tracing::debug!(target: "degu", adapter = adapter.registration.id(), "budget exhausted before adapter claim collection");
            return Ok(None);
        }
        if adapter.registration.scope() == AdapterScope::Runtime {
            continue;
        }
        if adapter.selected {
            if !project_claims {
                continue;
            }
            for root in &adapter.outcome.roots {
                if ctx.deadline_elapsed() {
                    tracing::debug!(target: "degu", adapter = adapter.registration.id(), "budget exhausted while claiming adapter roots");
                    return Ok(None);
                }
                claimed_roots.push(canonical_root_path(adapter.registration.id(), root)?);
            }
        } else {
            let Some(claims) =
                claims::root_claims(ctx, adapter.registration.id(), &adapter.outcome.roots)?
            else {
                tracing::debug!(target: "degu", adapter = adapter.registration.id(), "budget exhausted while collecting protective claims");
                return Ok(None);
            };
            claimed_roots.extend(claims.root_paths().cloned());
            exclusion_claims.extend(claims);
        }
    }
    Ok(Some((claimed_roots, exclusion_claims)))
}

fn should_resolve_roots(
    registration: &RegisteredAdapter,
    sources: &SourceSelection,
    disabled: &HashSet<&str>,
) -> bool {
    match registration.scope() {
        AdapterScope::Cache => sources.selects_findings(),
        AdapterScope::Runtime => {
            sources.selects_runtime()
                && sources.includes(registration.id())
                && !disabled.contains(registration.id())
        }
    }
}

fn is_selected(
    registration: &RegisteredAdapter,
    sources: &SourceSelection,
    disabled: &HashSet<&str>,
) -> bool {
    !disabled.contains(registration.id())
        && sources.includes(registration.id())
        && match registration.scope() {
            AdapterScope::Cache => sources.selects_findings(),
            AdapterScope::Runtime => sources.selects_runtime(),
        }
}

fn canonical_root_path(adapter: &str, root: &Root) -> Result<PathBuf> {
    std::fs::canonicalize(&root.path).with_context(|| {
        format!(
            "failed to canonicalize adapter {adapter:?} root {}",
            root.path.display()
        )
    })
}

/// A protective-root failure refuses the whole run, so the message must
/// carry everything needed to act: the failing path, the OS error, and a
/// first step. Without recorded provenance only the adapter id and the
/// diagnostic channel remain.
fn root_resolution_error(adapter: &str, outcome: &RootOutcome) -> anyhow::Error {
    let Some(failure) = outcome.failures.first() else {
        return anyhow::anyhow!(
            "failed to resolve protective roots for adapter {adapter:?}; rerun with -v to see the failing locations"
        );
    };
    anyhow::anyhow!(
        "failed to resolve protective roots for adapter {adapter:?}: failed to probe cache root {}: {}; {}, then rerun",
        failure.path.display(),
        failure.error,
        root_failure_remedy(failure)
    )
}

fn root_failure_remedy(failure: &degu_core::ecosystem::RootFailure) -> String {
    if failure.error.raw_os_error() == Some(libc::ELOOP) {
        format!("fix or remove the symlink at {}", failure.path.display())
    } else {
        format!("make {} accessible", failure.path.display())
    }
}
