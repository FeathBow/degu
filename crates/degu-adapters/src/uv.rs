use crate::native::{
    NativeActionIdentity, NativeActionRequest, NativeCapabilityError, NativeCleanupCapability,
    NativeEnvironmentRequest, NativeExecutableSelection, NativeProcessContract,
};
use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const RUN_TIMEOUT: Duration = Duration::from_secs(250);
const CAPTURE_LIMIT: usize = 64 * 1024;

pub struct Uv;
pub(crate) struct NativePrune;

impl NativeCleanupCapability for NativePrune {
    fn declare(
        &self,
        _ctx: &DetectCtx,
        frozen_roots: &[Root],
        executable: &NativeExecutableSelection,
    ) -> Result<NativeActionRequest, NativeCapabilityError> {
        let [root] = frozen_roots else {
            return Err(NativeCapabilityError::InvalidFrozenRoots(
                "uv cache prune requires exactly one frozen cache root",
            ));
        };
        require_absolute_normalized_root(&root.path)?;
        NativeActionRequest::new(
            NativeActionIdentity::new("uv", "cache-prune")?,
            executable.clone(),
            [
                OsString::from("--no-config"),
                OsString::from("--color"),
                OsString::from("never"),
                OsString::from("--no-progress"),
                OsString::from("--offline"),
                OsString::from("--cache-dir"),
                root.path.as_os_str().to_os_string(),
                OsString::from("cache"),
                OsString::from("prune"),
            ],
            NativeEnvironmentRequest::clear()
                .with_fixed([(OsString::from("UV_LOCK_TIMEOUT"), OsString::from("240"))]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            RUN_TIMEOUT,
            CAPTURE_LIMIT,
            CAPTURE_LIMIT,
            [root.path.clone()],
        )
        .map_err(NativeCapabilityError::from)
    }
}

fn require_absolute_normalized_root(path: &Path) -> Result<(), NativeCapabilityError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || !matches!(components.next(), Some(Component::Normal(_)))
        || !components.all(|component| matches!(component, Component::Normal(_)))
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(NativeCapabilityError::InvalidFrozenRoots(
            "uv cache root must be absolute and lexically normalized",
        ));
    }
    Ok(())
}

impl Ecosystem for Uv {
    fn id(&self) -> &'static str {
        "uv"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let mut candidates = Vec::new();
        if let Some(dir) = ctx.env("UV_CACHE_DIR") {
            candidates.push(Root::redirect("UV_CACHE_DIR", PathBuf::from(dir)));
        } else {
            // uv follows XDG on macOS too, so no ~/Library/Caches probe.
            candidates.push(ctx.xdg_cache().join("uv"));
        }
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        (
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            Ownership::ToolCoordinated,
            None,
        )
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "UV_CACHE_DIR",
            subdir: "uv",
            role: None,
        }]
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        crate::measure_finding(
            &root.path,
            ctx,
            crate::FindingSpec {
                ecosystem: self.id(),
                kind: FindingKind::PackageCache,
                facts: self.stated_facts(root),
                rationale: "uv download/build cache; uv documents that modifying the cache directly is never safe and coordinates mutations with locks, so degu does not clean it until it can participate in that protocol -- reclaim with uv cache clean or uv cache prune. Installed environments unaffected.",
            },
        )
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::native::NativeInheritedEnvironment;

    fn ctx() -> DetectCtx {
        DetectCtx::for_test(
            PathBuf::from("/home/alice"),
            [] as [(OsString, OsString); 0],
        )
    }

    fn executable() -> NativeExecutableSelection {
        NativeExecutableSelection::explicit(PathBuf::from("/opt/uv/bin/uv")).unwrap()
    }

    #[test]
    fn native_prune_declaration_is_the_fixed_ordinary_envelope() {
        let root = Root::well_known(PathBuf::from("/scratch/alice/uv"));
        let request = NativePrune.declare(&ctx(), &[root], &executable()).unwrap();
        assert_eq!(request.identity().adapter_id(), "uv");
        assert_eq!(request.identity().action_id(), "cache-prune");
        assert_eq!(request.executable(), Path::new("/opt/uv/bin/uv"));
        assert_eq!(
            request.arguments(),
            &[
                "--no-config",
                "--color",
                "never",
                "--no-progress",
                "--offline",
                "--cache-dir",
                "/scratch/alice/uv",
                "cache",
                "prune",
            ]
            .map(OsString::from)
        );
        assert!(matches!(
            request.environment().inherited(),
            NativeInheritedEnvironment::Clear
        ));
        assert_eq!(
            request.environment().fixed(),
            [(OsString::from("UV_LOCK_TIMEOUT"), OsString::from("240"))]
        );
        assert_eq!(request.timeout(), RUN_TIMEOUT);
        assert_eq!(request.stdout_limit(), CAPTURE_LIMIT);
        assert_eq!(request.stderr_limit(), CAPTURE_LIMIT);
        assert_eq!(
            request.observation_requests(),
            [Path::new("/scratch/alice/uv")]
        );
    }

    #[test]
    fn native_prune_rejects_missing_multiple_and_relative_frozen_roots() {
        assert!(matches!(
            NativePrune.declare(&ctx(), &[], &executable()),
            Err(NativeCapabilityError::InvalidFrozenRoots(_))
        ));
        assert!(matches!(
            NativePrune.declare(
                &ctx(),
                &[
                    Root::well_known(PathBuf::from("/one")),
                    Root::well_known(PathBuf::from("/two")),
                ],
                &executable(),
            ),
            Err(NativeCapabilityError::InvalidFrozenRoots(_))
        ));
        assert!(matches!(
            NativePrune.declare(
                &ctx(),
                &[Root::well_known(PathBuf::from("relative"))],
                &executable(),
            ),
            Err(NativeCapabilityError::InvalidFrozenRoots(_))
        ));
    }
}
