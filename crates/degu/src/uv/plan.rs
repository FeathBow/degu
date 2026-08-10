//! Authority-bearing boundary for one exact uv 0.12.3 ordinary prune.
//!
//! Preview keeps the probed executable, sealed cache namespace, and immutable
//! request together. Production execution consumes that same bundle, requires
//! the registered capability to reproduce the request exactly, and retains the
//! root seal as a one-shot pre-spawn mutation binding through quota observation.

use crate::native::{
    CompletedNativeQuotaAction, NativeActionPlanError, NativePreparationError,
    PreparedNativeQuotaAction, attach_quota_observation,
};
use crate::quota;
use crate::uv::{
    ProbedUvExecutable, SealedUvCacheRoot, UvCacheRootSealError, UvCacheRootSelection,
    UvExecutableProbeError, UvVersion, probe_uv_executable, seal_uv_cache_root,
};
use degu_adapters::RegisteredAdapter;
use degu_adapters::native::{
    NativeActionIdentity, NativeActionRequest, NativeCapabilityError, NativeEnvironmentRequest,
    NativeExecutableSelection, NativeInheritedEnvironment, NativeProcessContract,
    NativeRequestError,
};
use degu_core::ecosystem::{DetectCtx, Root};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
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
    #[error("registered uv native capability declaration failed: {0}")]
    Capability(#[from] NativeCapabilityError),
    #[error("uv adapter has no registered native cache-prune capability")]
    CapabilityUnavailable,
    #[error("registered uv capability does not exactly match the sealed prune request")]
    CapabilityRequestMismatch,
    #[error("uv native runner preparation failed: {0}")]
    NativePreparation(#[from] NativePreparationError),
    #[error("uv quota-observation envelope preparation failed: {0}")]
    Observation(#[from] NativeActionPlanError),
}

/// Non-cloneable proof bundle for exactly one previewed uv prune action.
///
/// Keeping all three fields private prevents a preview caller from separating
/// the executable snapshot from its root proof or substituting a generic native
/// request. The consuming transition below never rebuilds the operation from
/// paths, discovery findings, or quota anchors.
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

    /// Consume the exact previewed proof bundle into the only production uv
    /// execution capability. Registry output is equality-checked rather than
    /// trusted to reconstruct mutation authority.
    pub(crate) fn into_execution(
        self,
        registration: &RegisteredAdapter,
        ctx: &DetectCtx,
    ) -> Result<PreparedUvPruneExecution, UvPrunePlanError> {
        self.revalidate()?;
        let Self {
            executable,
            cache_root,
            request,
        } = self;
        let canonical_cache_root = cache_root.canonical_path().to_path_buf();
        let frozen_roots = [Root::well_known(canonical_cache_root.clone())];
        let declared = registration
            .declare_native_cleanup(ctx, &frozen_roots, executable.selection())?
            .ok_or(UvPrunePlanError::CapabilityUnavailable)?;
        if declared != request {
            return Err(UvPrunePlanError::CapabilityRequestMismatch);
        }
        executable.revalidate_path()?;
        cache_root.revalidate_for_executable(&executable)?;
        let action = executable.into_native_action_with_binding(declared, move || {
            cache_root.revalidate().map_err(|error| error.to_string())
        })?;
        let action = attach_quota_observation(action)?;
        Ok(PreparedUvPruneExecution {
            action,
            canonical_cache_root,
        })
    }

    #[cfg(test)]
    fn request(&self) -> &NativeActionRequest {
        &self.request
    }
}

/// One-shot execution capability. It exposes neither the frozen request nor
/// either held proof, and execution always uses the quota pre/post observation envelope.
pub(crate) struct PreparedUvPruneExecution {
    action: PreparedNativeQuotaAction,
    canonical_cache_root: std::path::PathBuf,
}

impl PreparedUvPruneExecution {
    pub(crate) fn execute(self) -> CompletedNativeQuotaAction<UvPruneSummary, UvPruneOutputError> {
        let expected_root = self.canonical_cache_root;
        let mut probe = quota::probe;
        self.action
            .execute_output(&mut probe, move |stdout, stderr| {
                parse_uv_prune_output(stdout, stderr, &expected_root)
            })
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct UvPruneSummary {
    pub(crate) waited_for_lock: bool,
    pub(crate) removal_kind: &'static str,
    pub(crate) removal_count: u64,
    pub(crate) reported_size: Option<String>,
    pub(crate) reported_size_is_lower_bound: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UvPruneOutputError {
    #[error("uv cache prune unexpectedly wrote to stdout")]
    UnexpectedStdout,
    #[error("uv cache prune stderr is not UTF-8")]
    StderrNotUtf8,
    #[error("uv cache prune output does not match the audited 0.12.3 shape")]
    InvalidShape,
    #[error("uv cache prune reported a non-canonical or overflowing removal count")]
    InvalidCount,
    #[error("uv cache prune reported an invalid size token")]
    InvalidSize,
}

const LOCK_WAIT_LINE: &str = "Cache is currently in-use, waiting for other uv processes to finish (use `--force` to override)";

fn parse_uv_prune_output(
    stdout: &[u8],
    stderr: &[u8],
    expected_root: &Path,
) -> Result<UvPruneSummary, UvPruneOutputError> {
    if !stdout.is_empty() {
        return Err(UvPruneOutputError::UnexpectedStdout);
    }
    let lock_prefix = [LOCK_WAIT_LINE.as_bytes(), b"\n"].concat();
    let (waited_for_lock, stderr) = stderr
        .strip_prefix(lock_prefix.as_slice())
        .map_or((false, stderr), |remaining| (true, remaining));
    let stderr = stderr
        .strip_prefix(b"Pruning cache at: ")
        .and_then(|remaining| remaining.strip_prefix(expected_root.as_os_str().as_bytes()))
        .and_then(|remaining| remaining.strip_prefix(b"\n"))
        .ok_or(UvPruneOutputError::InvalidShape)?;
    // Match the root as exact bytes before interpreting line structure: valid
    // Unix paths may themselves contain LF, CR, or tab and uv prints them raw.
    let summary = std::str::from_utf8(stderr).map_err(|_| UvPruneOutputError::StderrNotUtf8)?;
    let summary = summary
        .strip_suffix('\n')
        .ok_or(UvPruneOutputError::InvalidShape)?;
    if summary.contains('\r') || summary.contains('\n') {
        return Err(UvPruneOutputError::InvalidShape);
    }
    let (summary, reported_size, reported_size_is_lower_bound) = parse_size_suffix(summary)?;
    let (removal_kind, removal_count) = if summary == "No unused entries found" {
        if reported_size.is_some() {
            return Err(UvPruneOutputError::InvalidShape);
        }
        ("none", 0)
    } else if summary == "Removed 1 file" {
        ("files", 1)
    } else if summary == "Removed 1 directory" {
        ("directories", 1)
    } else if let Some(count) = summary
        .strip_prefix("Removed ")
        .and_then(|value| value.strip_suffix(" files"))
    {
        ("files", parse_plural_count(count)?)
    } else if let Some(count) = summary
        .strip_prefix("Removed ")
        .and_then(|value| value.strip_suffix(" directories"))
    {
        ("directories", parse_plural_count(count)?)
    } else {
        return Err(UvPruneOutputError::InvalidShape);
    };
    Ok(UvPruneSummary {
        waited_for_lock,
        removal_kind,
        removal_count,
        reported_size,
        reported_size_is_lower_bound,
    })
}

fn parse_plural_count(value: &str) -> Result<u64, UvPruneOutputError> {
    let count = value
        .parse::<u64>()
        .map_err(|_| UvPruneOutputError::InvalidCount)?;
    if count < 2 || count.to_string() != value {
        return Err(UvPruneOutputError::InvalidCount);
    }
    Ok(count)
}

fn parse_size_suffix(summary: &str) -> Result<(&str, Option<String>, bool), UvPruneOutputError> {
    let Some(without_close) = summary.strip_suffix(')') else {
        return Ok((summary, None, false));
    };
    let (summary, size) = without_close
        .rsplit_once(" (")
        .ok_or(UvPruneOutputError::InvalidShape)?;
    let (lower_bound, size) = size
        .strip_prefix("at least ")
        .map_or((false, size), |size| (true, size));
    if !valid_size_token(size) {
        return Err(UvPruneOutputError::InvalidSize);
    }
    Ok((summary, Some(size.to_owned()), lower_bound))
}

fn valid_size_token(size: &str) -> bool {
    if let Some(bytes) = size.strip_suffix('B')
        && !bytes.contains('.')
    {
        return canonical_unsigned(bytes);
    }
    for unit in ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] {
        if let Some(number) = size.strip_suffix(unit) {
            let Some((whole, fraction)) = number.split_once('.') else {
                return false;
            };
            return canonical_unsigned(whole)
                && fraction.len() == 1
                && fraction.bytes().all(|byte| byte.is_ascii_digit());
        }
    }
    false
}

fn canonical_unsigned(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::attach_quota_observation;
    use crate::native::{NativeRunOutcome, prepare_native_action};
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
    fn production_registry_reproduces_the_frozen_request_exactly() {
        let ctx = DetectCtx::for_test(
            PathBuf::from("/home/alice"),
            [] as [(OsString, OsString); 0],
        );
        let registration = degu_adapters::all()
            .into_iter()
            .find(|registration| registration.id() == ADAPTER_ID)
            .unwrap();
        let selection =
            NativeExecutableSelection::explicit(PathBuf::from("/opt/uv/bin/uv")).unwrap();
        let root = PathBuf::from("/scratch/alice/uv");
        let declared = registration
            .declare_native_cleanup(&ctx, &[Root::well_known(root.clone())], &selection)
            .unwrap()
            .unwrap();
        assert_eq!(declared, fixed_request(selection, &root).unwrap());
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

    fn parse(stderr: &str) -> Result<UvPruneSummary, UvPruneOutputError> {
        parse_uv_prune_output(b"", stderr.as_bytes(), Path::new("/scratch/alice/uv"))
    }

    #[test]
    fn parser_accepts_every_audited_success_summary_class() {
        assert_eq!(
            parse("Pruning cache at: /scratch/alice/uv\nNo unused entries found\n").unwrap(),
            UvPruneSummary {
                waited_for_lock: false,
                removal_kind: "none",
                removal_count: 0,
                reported_size: None,
                reported_size_is_lower_bound: false,
            }
        );
        assert_eq!(
            parse("Pruning cache at: /scratch/alice/uv\nRemoved 1 file (1.0MiB)\n").unwrap(),
            UvPruneSummary {
                waited_for_lock: false,
                removal_kind: "files",
                removal_count: 1,
                reported_size: Some("1.0MiB".to_owned()),
                reported_size_is_lower_bound: false,
            }
        );
        assert_eq!(
            parse("Pruning cache at: /scratch/alice/uv\nRemoved 42 directories (at least 7B)\n")
                .unwrap(),
            UvPruneSummary {
                waited_for_lock: false,
                removal_kind: "directories",
                removal_count: 42,
                reported_size: Some("7B".to_owned()),
                reported_size_is_lower_bound: true,
            }
        );
    }

    #[test]
    fn parser_matches_control_characters_inside_the_exact_root_before_line_parsing() {
        for root in [
            "/scratch/alice/line\nbreak",
            "/scratch/alice/carriage\rreturn",
            "/scratch/alice/tab\troot",
        ] {
            let output = format!("Pruning cache at: {root}\nNo unused entries found\n");
            let parsed = parse_uv_prune_output(b"", output.as_bytes(), Path::new(root)).unwrap();
            assert_eq!(parsed.removal_kind, "none");
        }
    }

    #[test]
    fn parser_accepts_only_the_exact_optional_lock_wait_line() {
        let output =
            format!("{LOCK_WAIT_LINE}\nPruning cache at: /scratch/alice/uv\nRemoved 2 files\n");
        let parsed = parse(&output).unwrap();
        assert!(parsed.waited_for_lock);
        assert_eq!(parsed.removal_count, 2);
    }

    #[test]
    fn c2_execution_wrapper_parses_real_bounded_stderr_and_completes_observation() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let request = NativeActionRequest::new(
            NativeActionIdentity::new(ADAPTER_ID, ACTION_ID).unwrap(),
            NativeExecutableSelection::explicit(PathBuf::from("/bin/sh")).unwrap(),
            [
                OsString::from("-c"),
                OsString::from(
                    "printf 'Pruning cache at: %s\\nNo unused entries found\\n' \"$1\" >&2",
                ),
                OsString::from("degu-uv-parser-test"),
                canonical.as_os_str().to_os_string(),
            ],
            NativeEnvironmentRequest::clear(),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(2),
            1024,
            4096,
            [canonical.clone()],
        )
        .unwrap();
        let action = attach_quota_observation(prepare_native_action(request).unwrap()).unwrap();
        let completed = PreparedUvPruneExecution {
            action,
            canonical_cache_root: canonical,
        }
        .execute();
        let report = completed.execution().as_ref().unwrap();
        assert!(matches!(
            report.outcome(),
            NativeRunOutcome::Success(UvPruneSummary {
                removal_kind: "none",
                removal_count: 0,
                ..
            })
        ));
        assert_eq!(
            completed.observation().outcome(),
            crate::native::ActionOutcome::Success
        );
    }

    fn execute_test_shell(
        root: &Path,
        marker: &Path,
        script: &str,
        stderr_limit: usize,
    ) -> CompletedNativeQuotaAction<UvPruneSummary, UvPruneOutputError> {
        let request = NativeActionRequest::new(
            NativeActionIdentity::new(ADAPTER_ID, ACTION_ID).unwrap(),
            NativeExecutableSelection::explicit(PathBuf::from("/bin/sh")).unwrap(),
            [
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("degu-uv-terminal-test"),
                root.as_os_str().to_os_string(),
                marker.as_os_str().to_os_string(),
            ],
            NativeEnvironmentRequest::clear(),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(2),
            1024,
            stderr_limit,
            [root.to_path_buf()],
        )
        .unwrap();
        let action = attach_quota_observation(prepare_native_action(request).unwrap()).unwrap();
        PreparedUvPruneExecution {
            action,
            canonical_cache_root: root.to_path_buf(),
        }
        .execute()
    }

    #[test]
    fn successful_child_mutation_with_malformed_output_is_parse_failure_not_no_change() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let marker = canonical.join("parse-marker");
        let completed = execute_test_shell(
            &canonical,
            &marker,
            "printf marker > \"$2\"; printf 'malformed\\n' >&2",
            4096,
        );
        assert!(marker.is_file(), "the child mutation must have happened");
        assert!(matches!(
            completed.execution().as_ref().unwrap().outcome(),
            NativeRunOutcome::OutputParseFailure(UvPruneOutputError::InvalidShape)
        ));
        assert_eq!(
            completed.observation().outcome(),
            crate::native::ActionOutcome::OutputParseFailure
        );
    }

    #[test]
    fn successful_child_mutation_with_large_output_is_truncated_not_no_change() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let marker = canonical.join("truncated-marker");
        let completed = execute_test_shell(
            &canonical,
            &marker,
            "printf marker > \"$2\"; i=0; while [ $i -lt 100 ]; do printf x >&2; i=$((i + 1)); done",
            16,
        );
        assert!(marker.is_file(), "the child mutation must have happened");
        assert!(matches!(
            completed.execution().as_ref().unwrap().outcome(),
            NativeRunOutcome::OutputTruncated
        ));
        assert_eq!(
            completed.observation().outcome(),
            crate::native::ActionOutcome::OutputTruncated
        );
    }

    #[test]
    fn parser_rejects_other_streams_paths_lines_counts_and_sizes() {
        assert_eq!(
            parse_uv_prune_output(
                b"unexpected",
                b"Pruning cache at: /scratch/alice/uv\nNo unused entries found\n",
                Path::new("/scratch/alice/uv")
            ),
            Err(UvPruneOutputError::UnexpectedStdout)
        );
        let mut non_utf8_summary = b"Pruning cache at: /scratch/alice/uv\n".to_vec();
        non_utf8_summary.extend_from_slice(b"\xff\n");
        assert_eq!(
            parse_uv_prune_output(b"", &non_utf8_summary, Path::new("/scratch/alice/uv")),
            Err(UvPruneOutputError::StderrNotUtf8)
        );
        for output in [
            "Pruning cache at: /other\nNo unused entries found\n",
            "Pruning cache at: /scratch/alice/uv\nNo unused entries found\nextra\n",
            "Pruning cache at: /scratch/alice/uv\nRemoved 01 files\n",
            "Pruning cache at: /scratch/alice/uv\nRemoved 1 files\n",
            "Pruning cache at: /scratch/alice/uv\nRemoved 2 files (1MB)\n",
            "Pruning cache at: /scratch/alice/uv\nRemoved 2 files",
        ] {
            assert!(parse(output).is_err(), "unexpectedly accepted {output:?}");
        }
    }
}
