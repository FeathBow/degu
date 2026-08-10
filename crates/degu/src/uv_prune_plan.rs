//! Combination boundary for one exact uv ordinary-prune preview.
//!
//! The type in this module simultaneously retains the probed executable, the
//! sealed cache namespace, and the immutable native request that an execution
//! capability must match. It deliberately exposes no consuming split or execute
//! operation: a preview may render and revalidate this plan, but cannot start
//! prune.

use crate::uv_cache_root::{
    SealedUvCacheRoot, UvCacheRootSealError, UvCacheRootSelection, seal_uv_cache_root,
};
use crate::uv_executable::{
    ProbedUvExecutable, UvExecutableProbeError, UvVersion, probe_uv_executable,
};
use degu_adapters::RegisteredAdapter;
use degu_adapters::native::{
    NativeActionIdentity, NativeActionRequest, NativeEnvironmentRequest, NativeExecutableSelection,
    NativeInheritedEnvironment, NativeProcessContract, NativeRequestError,
};
use degu_core::ecosystem::DetectCtx;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

pub(crate) const ADAPTER_ID: &str = "uv";
pub(crate) const ACTION_ID: &str = "cache-prune";
const RUN_TIMEOUT: Duration = Duration::from_secs(250);
const CAPTURE_LIMIT: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UvPrunePlanError {
    #[error("uv executable proof failed: {0}")]
    Executable(#[from] UvExecutableProbeError),
    #[error("uv cache-root proof failed: {0}")]
    CacheRoot(#[from] UvCacheRootSealError),
    #[error("fixed uv prune request is invalid: {0}")]
    Request(#[from] NativeRequestError),
}

/// Non-cloneable proof bundle for exactly one previewed uv prune action.
///
/// Keeping all three fields private prevents a preview caller from separating
/// the executable snapshot from its root proof or substituting a generic native
/// request. An execution transition must be added here rather than rebuilding
/// the operation from paths, discovery findings, or quota anchors.
pub(crate) struct PreparedUvPrunePlan {
    executable: ProbedUvExecutable,
    cache_root: SealedUvCacheRoot,
    request: NativeActionRequest,
}

pub(crate) fn prepare_uv_prune_plan(
    registration: &RegisteredAdapter,
    ctx: &DetectCtx,
    executable_selection: NativeExecutableSelection,
    cache_root_selection: UvCacheRootSelection,
) -> Result<PreparedUvPrunePlan, UvPrunePlanError> {
    let executable = probe_uv_executable(executable_selection)?;
    let cache_root = seal_uv_cache_root(registration, ctx, cache_root_selection, &executable)?;
    let request = fixed_request(executable.selection().clone(), cache_root.canonical_path())?;
    Ok(PreparedUvPrunePlan {
        executable,
        cache_root,
        request,
    })
}

impl PreparedUvPrunePlan {
    pub(crate) fn revalidate(&self) -> Result<(), UvPrunePlanError> {
        self.executable.revalidate_path()?;
        self.cache_root
            .revalidate_for_executable(&self.executable)?;
        Ok(())
    }

    pub(crate) fn selected_executable(&self) -> &Path {
        self.executable.selection().as_path()
    }

    pub(crate) fn version(&self) -> UvVersion {
        self.executable.version()
    }

    pub(crate) fn selected_cache_root(&self) -> &Path {
        self.cache_root.selection().as_path()
    }

    pub(crate) fn canonical_cache_root(&self) -> &Path {
        self.cache_root.canonical_path()
    }

    pub(crate) fn arguments(&self) -> &[OsString] {
        self.request.arguments()
    }

    pub(crate) fn inherited_environment(&self) -> &NativeInheritedEnvironment {
        self.request.environment().inherited()
    }

    pub(crate) fn fixed_environment(&self) -> &[(OsString, OsString)] {
        self.request.environment().fixed()
    }

    #[cfg(test)]
    fn request(&self) -> &NativeActionRequest {
        &self.request
    }
}

fn fixed_request(
    executable: NativeExecutableSelection,
    cache_root: &Path,
) -> Result<NativeActionRequest, NativeRequestError> {
    NativeActionRequest::new(
        NativeActionIdentity::new(ADAPTER_ID, ACTION_ID)?,
        executable,
        fixed_arguments(cache_root),
        NativeEnvironmentRequest::clear()
            .with_fixed([(OsString::from("UV_LOCK_TIMEOUT"), OsString::from("240"))]),
        NativeProcessContract::AuditedCooperativeProcessGroup,
        RUN_TIMEOUT,
        CAPTURE_LIMIT,
        CAPTURE_LIMIT,
        [cache_root.to_path_buf()],
    )
}

fn fixed_arguments(cache_root: &Path) -> [OsString; 9] {
    [
        OsString::from("--no-config"),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("--no-progress"),
        OsString::from("--offline"),
        OsString::from("--cache-dir"),
        cache_root.as_os_str().to_os_string(),
        OsString::from("cache"),
        OsString::from("prune"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn request_is_the_exact_audited_ordinary_prune_envelope() {
        let selection =
            NativeExecutableSelection::explicit(PathBuf::from("/opt/uv/bin/uv")).unwrap();
        let root = Path::new("/scratch/alice/uv");
        let request = fixed_request(selection, root).unwrap();

        assert_eq!(request.identity().adapter_id(), ADAPTER_ID);
        assert_eq!(request.identity().action_id(), ACTION_ID);
        assert_eq!(request.executable(), Path::new("/opt/uv/bin/uv"));
        assert_eq!(request.arguments(), fixed_arguments(root));
        assert!(matches!(
            request.environment().inherited(),
            NativeInheritedEnvironment::Clear
        ));
        assert_eq!(
            request.environment().fixed(),
            [(OsString::from("UV_LOCK_TIMEOUT"), OsString::from("240"))]
        );
        assert_eq!(
            request.process_contract(),
            NativeProcessContract::AuditedCooperativeProcessGroup
        );
        assert_eq!(request.timeout(), RUN_TIMEOUT);
        assert_eq!(request.stdout_limit(), CAPTURE_LIMIT);
        assert_eq!(request.stderr_limit(), CAPTURE_LIMIT);
        assert_eq!(request.observation_requests(), [root]);
    }

    #[test]
    fn request_getter_is_test_only_and_retains_the_private_contract() {
        // This compile-time shape check lives in the defining module. Production
        // callers receive only borrowed preview fields, never a request clone.
        fn inspect(plan: &PreparedUvPrunePlan) -> (&NativeActionRequest, UvVersion) {
            (plan.request(), plan.version())
        }
        let _ = inspect;
    }

    #[test]
    fn fixed_arguments_keep_the_root_as_one_literal_os_argument() {
        let root = Path::new("/cache/root with spaces");
        let arguments = fixed_arguments(root);
        assert_eq!(arguments[5], OsStr::new("--cache-dir"));
        assert_eq!(arguments[6], root.as_os_str());
        assert_eq!(arguments[7], OsStr::new("cache"));
        assert_eq!(arguments[8], OsStr::new("prune"));
    }
}
