//! degu-adapters — ecosystem adapters.
//!
//! Every adapter implements [`degu_core::ecosystem::Ecosystem`] and only reports findings.
//! Verified deletion remains private to the degu lifecycle.

mod apptainer;
mod artifacts;
mod cachedir_tag;
mod cargo;
mod ccache;
mod checkpoints;
mod computecache;
mod conda;
pub mod discovery;
mod docker;
mod gobuild;
mod helm;
mod huggingface;
mod inductor;
mod jax;
mod modelscope;
mod npm;
mod ollama;
mod orbstack;
mod pip;
mod pixi;
mod podman;
mod roots;
mod sccache;
mod shm;
mod spack;
mod tmp;
mod torch;
mod torchext;
mod triton;
mod uv;
mod vllm;
mod vscode;
mod wandb;

use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingCandidate, FindingFacts, FindingKind};
use std::path::Path;
use std::time::{Duration, SystemTime};

const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// The OS-native user cache dir for `name`, which ignores `XDG_CACHE_HOME` on
/// macOS: `~/Library/Caches/<name>` there, `$XDG_CACHE_HOME`/`~/.cache/<name>`
/// elsewhere. For tools whose macOS build uses the OS-native dir regardless of
/// XDG (go-build via `os.UserCacheDir`, sccache via the `directories` crate);
/// tools that honor XDG on macOS use [`xdg_cache_or_platform`] instead.
pub(crate) fn platform_cache_root(ctx: &DetectCtx, name: &str) -> Root {
    #[cfg(target_os = "macos")]
    {
        Root::well_known(ctx.home.join("Library/Caches").join(name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        ctx.xdg_cache().join(name)
    }
}

/// The cache dir for tools that honor `XDG_CACHE_HOME` on every platform (pip,
/// ccache, helm, pixi): `$XDG_CACHE_HOME/<name>` when it is set, otherwise the
/// OS-native cache dir (`~/Library/Caches/<name>` on macOS, `~/.cache/<name>`
/// elsewhere). A set `XDG_CACHE_HOME` stays WellKnown, preserving that contract.
pub(crate) fn xdg_cache_or_platform(ctx: &DetectCtx, name: &str) -> Root {
    let xdg = ctx.env("XDG_CACHE_HOME").is_some().then(|| ctx.xdg_cache());
    resolve_xdg_or_native(xdg, &ctx.home, name)
}

/// Pure resolution behind [`xdg_cache_or_platform`]: `xdg_cache` is `Some` iff
/// `XDG_CACHE_HOME` is set. No env or filesystem access, so it is unit-testable.
fn resolve_xdg_or_native(xdg_cache: Option<Root>, home: &Path, name: &str) -> Root {
    match xdg_cache {
        Some(root) => root.join(name),
        None => {
            #[cfg(target_os = "macos")]
            {
                Root::well_known(home.join("Library/Caches").join(name))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Root::well_known(home.join(".cache").join(name))
            }
        }
    }
}

/// First-present precedence, but `merge` carries `primary`'s incomplete/truncated
/// signal so a transient failure of the higher-precedence probe stays visible.
pub(crate) fn first_present(
    primary: RootOutcome,
    fallback: impl FnOnce() -> RootOutcome,
) -> RootOutcome {
    if !primary.roots.is_empty() {
        return primary;
    }
    let mut outcome = fallback();
    outcome.merge(primary);
    outcome
}

pub const ARTIFACT_SOURCE_ID: &str = artifacts::SOURCE_ID;
pub const CHECKPOINT_SOURCE_ID: &str = checkpoints::SOURCE_ID;
pub const PROJECT_SOURCE_IDS: [&str; 2] = [ARTIFACT_SOURCE_ID, CHECKPOINT_SOURCE_ID];
pub use cachedir_tag::{Probe as CachedirTagProbe, has_valid_cachedir_tag, probe_for_scheduling};

pub(crate) use roots::{resolve_existing_roots, validate_root_path};

pub(crate) struct FindingSpec<'a> {
    pub ecosystem: &'a str,
    pub kind: FindingKind,
    pub facts: FindingFacts,
    pub rationale: &'a str,
}

pub(crate) fn walk_options(ctx: &DetectCtx) -> degu_walk::WalkOptions {
    degu_walk::WalkOptions {
        max_concurrency: ctx.max_concurrency,
        required_uid: Some(rustix::process::geteuid().as_raw()),
        progress: ctx.progress.clone(),
        deadline: ctx.deadline,
        excluded_entry_names: &degu_core::safety::PROTECTED_DESCENDANT_DIR_NAMES,
        credential_entry_names: &degu_core::safety::CREDENTIAL_DIR_NAMES,
        ..Default::default()
    }
}

pub(crate) fn is_missing_path_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

pub(crate) fn age_days(newest_mtime: Option<SystemTime>) -> Option<u64> {
    newest_mtime.map(|mtime| {
        SystemTime::now()
            .duration_since(mtime)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            / SECS_PER_DAY
    })
}

pub(crate) fn measure_finding(path: &Path, ctx: &DetectCtx, spec: FindingSpec<'_>) -> ScanOutcome {
    if ctx.deadline_elapsed() {
        return ScanOutcome::truncated();
    }
    let opts = walk_options(ctx);
    let stats = match degu_walk::measure(path, &opts) {
        Ok(stats) => stats,
        Err(err) if is_missing_path_error(&err) => {
            tracing::debug!(path = %path.display(), ecosystem = spec.ecosystem, %err, "root vanished during scan");
            return ScanOutcome::default();
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), ecosystem = spec.ecosystem, %err, "cache scan failed");
            return ScanOutcome::failed();
        }
    };
    log_skipped_samples(spec.ecosystem, &stats);

    let (recovery, ownership, hazard) = spec.facts;
    ScanOutcome::from_candidates(vec![FindingCandidate {
        ecosystem: spec.ecosystem.to_string(),
        path: path.to_path_buf(),
        kind: spec.kind,
        bytes_apparent: stats.bytes_apparent,
        bytes_allocated: stats.bytes_allocated,
        age_days: age_days(stats.newest_mtime),
        bytes_hardlinked: stats.bytes_hardlinked,
        inodes: stats.inodes,
        skipped: stats.skipped_total,
        truncated: stats.truncated,
        unvisited_dirs: stats.unvisited_dirs,
        shared_writable_dirs: stats.shared_writable_dirs,
        parent_grants_foreign_mutation: false,
        protected_boundaries: stats.excluded_entries,
        protected_credential_boundaries: stats.excluded_credential_boundaries,
        recovery,
        ownership,
        hazard,
        rationale: spec.rationale.to_string(),
    }])
}

/// Findings carry only skip counts; surface degu-walk's bounded sample here --
/// one debug event per skipped path, plus a summary when events outran it.
pub(crate) fn log_skipped_samples(ecosystem: &str, stats: &degu_walk::WalkStats) {
    for skipped in &stats.skipped {
        tracing::debug!(
            target: "degu",
            ecosystem,
            path = %skipped.path.display(),
            reason = %skipped.reason,
            "scan skipped a path"
        );
    }
    let sampled = stats.skipped.len() as u64;
    if stats.skipped_total > sampled {
        tracing::debug!(
            target: "degu",
            ecosystem,
            skipped_total = stats.skipped_total,
            sampled,
            "scan skipped more paths than the recorded sample"
        );
    }
}

/// Where an adapter's findings are activated and accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterScope {
    Cache,
    Runtime,
}

/// An adapter instance and the scope governing its activation and output.
pub struct RegisteredAdapter {
    ecosystem: Box<dyn Ecosystem>,
    scope: AdapterScope,
}

impl RegisteredAdapter {
    fn new(ecosystem: impl Ecosystem + 'static, scope: AdapterScope) -> Self {
        Self {
            ecosystem: Box::new(ecosystem),
            scope,
        }
    }

    pub fn id(&self) -> &'static str {
        self.ecosystem.id()
    }

    pub fn scope(&self) -> AdapterScope {
        self.scope
    }

    pub fn ecosystem(&self) -> &dyn Ecosystem {
        self.ecosystem.as_ref()
    }
}

/// Full registry; config-driven activation filtering happens in the caller.
pub fn all() -> Vec<RegisteredAdapter> {
    use AdapterScope::{Cache, Runtime};

    vec![
        RegisteredAdapter::new(cargo::Cargo, Cache),
        RegisteredAdapter::new(conda::Conda, Cache),
        RegisteredAdapter::new(apptainer::Apptainer, Cache),
        RegisteredAdapter::new(npm::Npm, Cache),
        RegisteredAdapter::new(pip::Pip, Cache),
        RegisteredAdapter::new(uv::Uv, Cache),
        RegisteredAdapter::new(pixi::Pixi, Cache),
        RegisteredAdapter::new(vscode::Vscode, Cache),
        RegisteredAdapter::new(huggingface::Huggingface, Cache),
        RegisteredAdapter::new(modelscope::Modelscope, Cache),
        RegisteredAdapter::new(ollama::Ollama, Cache),
        RegisteredAdapter::new(podman::Podman, Cache),
        RegisteredAdapter::new(docker::Docker, Cache),
        RegisteredAdapter::new(orbstack::Orbstack, Cache),
        RegisteredAdapter::new(vllm::Vllm, Cache),
        RegisteredAdapter::new(triton::Triton, Cache),
        RegisteredAdapter::new(torch::Torch, Cache),
        RegisteredAdapter::new(torchext::Torchext, Cache),
        RegisteredAdapter::new(jax::Jax, Cache),
        RegisteredAdapter::new(helm::Helm, Cache),
        RegisteredAdapter::new(spack::Spack, Cache),
        RegisteredAdapter::new(computecache::Computecache, Cache),
        RegisteredAdapter::new(ccache::Ccache, Cache),
        RegisteredAdapter::new(gobuild::Gobuild, Cache),
        RegisteredAdapter::new(sccache::Sccache, Cache),
        RegisteredAdapter::new(inductor::Inductor, Cache),
        RegisteredAdapter::new(wandb::Wandb, Cache),
        RegisteredAdapter::new(shm::Shm, Runtime),
        RegisteredAdapter::new(tmp::Tmp, Runtime),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ctx(home: &Path) -> DetectCtx {
        let mut ctx = DetectCtx::from_process().unwrap();
        ctx.home = home.to_path_buf();
        ctx
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_cache_root_picks_library_caches_on_macos() {
        let dir = tempfile::tempdir().unwrap();
        let root = platform_cache_root(&fake_ctx(dir.path()), "pip");

        assert_eq!(root.path, dir.path().join("Library/Caches/pip"));
        assert_ne!(root.path, dir.path().join(".cache/pip"));
    }

    // XDG_CACHE_HOME may leak from CI's env, so anchor on ctx.xdg_cache() itself.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn platform_cache_root_picks_xdg_cache_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = fake_ctx(dir.path());
        let root = platform_cache_root(&ctx, "pip");

        assert_eq!(root.path, ctx.xdg_cache().join("pip").path);
        assert_ne!(root.path, dir.path().join("Library/Caches/pip"));
    }

    // XDG-honoring tools take $XDG_CACHE_HOME/<name> whenever it is set, on every
    // platform (macOS included) -- the case the old macOS-only helper dropped.
    #[test]
    fn resolve_xdg_or_native_uses_xdg_when_set() {
        let xdg = Root::well_known(std::path::PathBuf::from("/xdg"));
        let root = resolve_xdg_or_native(Some(xdg), Path::new("/home/user"), "pip");

        assert_eq!(root.path.as_path(), Path::new("/xdg/pip"));
    }

    #[test]
    fn resolve_xdg_or_native_falls_back_to_os_native_dir() {
        let root = resolve_xdg_or_native(None, Path::new("/home/user"), "pip");

        #[cfg(target_os = "macos")]
        assert_eq!(
            root.path.as_path(),
            Path::new("/home/user/Library/Caches/pip")
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(root.path.as_path(), Path::new("/home/user/.cache/pip"));
    }

    fn outcome(paths: &[&str], incomplete: bool) -> RootOutcome {
        RootOutcome {
            roots: paths
                .iter()
                .map(|p| Root::well_known(std::path::PathBuf::from(p)))
                .collect(),
            incomplete,
            truncated: false,
            failures: Vec::new(),
        }
    }

    #[test]
    fn first_present_keeps_primary_without_probing_fallback() {
        let result = first_present(outcome(&["/primary"], false), || {
            panic!("fallback must not be probed when primary has roots")
        });
        assert_eq!(result.roots.len(), 1);
        assert!(!result.incomplete);
    }

    #[test]
    fn first_present_probes_fallback_but_keeps_primary_incomplete_signal() {
        let result = first_present(outcome(&[], true), || outcome(&["/fallback"], false));
        assert!(
            result
                .roots
                .iter()
                .any(|r| r.path.as_path() == Path::new("/fallback"))
        );
        assert!(
            result.incomplete,
            "a transient failure of the higher-precedence probe must stay visible"
        );
    }

    #[test]
    fn first_present_uses_fallback_when_primary_absent() {
        let result = first_present(outcome(&[], false), || outcome(&["/fallback"], false));
        assert_eq!(result.roots.len(), 1);
        assert!(!result.incomplete);
    }

    #[test]
    fn vanished_roots_build_no_finding() {
        let ctx = DetectCtx::from_process().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("gone");

        let outcome = measure_finding(
            &root,
            &ctx,
            FindingSpec {
                ecosystem: "test",
                kind: FindingKind::Other,
                facts: (
                    degu_core::finding::Recovery::Regenerable {
                        cost: degu_core::finding::RegenCost::Cheap,
                    },
                    degu_core::finding::Ownership::Standalone,
                    None,
                ),
                rationale: "fixture",
            },
        );

        assert!(outcome.candidates.is_empty());
        assert!(!outcome.incomplete);
        assert!(!outcome.truncated);
    }

    #[test]
    fn registry_identity_and_scope_contract_is_consistent() {
        use AdapterScope::{Cache, Runtime};

        const EXPECTED: &[(&str, AdapterScope)] = &[
            ("cargo", Cache),
            ("conda", Cache),
            ("apptainer", Cache),
            ("npm", Cache),
            ("pip", Cache),
            ("uv", Cache),
            ("pixi", Cache),
            ("vscode", Cache),
            ("huggingface", Cache),
            ("modelscope", Cache),
            ("ollama", Cache),
            ("podman", Cache),
            ("docker", Cache),
            ("orbstack", Cache),
            ("vllm", Cache),
            ("triton", Cache),
            ("torch", Cache),
            ("torchext", Cache),
            ("jax", Cache),
            ("helm", Cache),
            ("spack", Cache),
            ("computecache", Cache),
            ("ccache", Cache),
            ("go-build", Cache),
            ("sccache", Cache),
            ("inductor", Cache),
            ("wandb", Cache),
            ("shm", Runtime),
            ("tmp", Runtime),
        ];

        let actual = all()
            .into_iter()
            .map(|registration| (registration.id(), registration.scope()))
            .collect::<Vec<_>>();
        let unique_ids = actual
            .iter()
            .map(|(id, _)| *id)
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(actual.as_slice(), EXPECTED);
        assert_eq!(unique_ids.len(), actual.len());
    }
}
