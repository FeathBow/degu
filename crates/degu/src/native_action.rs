//! Native action bridge into the existing action-result and quota-observation envelope.
//!
//! Declaration and runner preparation happen before this module creates a batch.
//! Observation requests are frozen, read-only data: they cannot authorize or alter
//! the invocation, and planning never dereferences them.

use crate::action_result::{
    ActionId, ActionKind, ActionObservationTargets, ActionResultOwner, ContractError,
    ObservationRequestPath, PlannedActionBatch, QuotaObservationTarget, StartedActionOutcome,
};
#[cfg(test)]
use crate::native_runner::prepare_native_action;
use crate::native_runner::{
    HeldNativeExecutable, NativePreparationError, NativeRunReport, NativeRunnerError,
    PreparedNativeAction, prepare_native_action_from_held,
};
use crate::quota::{ProbeError, QuotaSnapshot};
use crate::quota_observation::{self, CompletedQuotaAction};
use crate::uv_cache_root::{SealedUvCacheRoot, UvCacheRootSealError};
use crate::uv_executable::{ProbedUvExecutable, UvExecutableProbeError};
use degu_adapters::RegisteredAdapter;
use degu_adapters::native::{
    NativeActionRequest, NativeCapabilityError, NativeInheritedEnvironment,
};
use degu_core::ecosystem::{DetectCtx, Root};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeActionPlanError {
    #[error("native capability declaration failed: {0}")]
    Capability(#[from] NativeCapabilityError),
    #[error("native executable proof failed revalidation: {0}")]
    Executable(#[from] UvExecutableProbeError),
    #[error("uv cache-root proof failed revalidation: {0}")]
    CacheRoot(#[from] UvCacheRootSealError),
    #[error("uv executable/root proofs cannot prepare native adapter {0:?}")]
    NonUvAdapter(&'static str),
    #[error("native declaration is not bound to the exact sealed `--cache-dir`")]
    CacheRootArgumentMismatch,
    #[error("native action preparation failed: {0}")]
    Preparation(#[from] NativePreparationError),
    #[error("native action identity is invalid: {0:?}")]
    Contract(ContractError),
}

/// One exact preflighted invocation paired with its immutable action descriptor.
/// Neither field is cloneable; execution consumes both exactly once.
pub(crate) struct PreparedNativeQuotaAction {
    action: PreparedNativeAction,
    batch: PlannedActionBatch,
    /// Production uv work must retain and revalidate the non-cloneable root
    /// proof. Controlled generic runner tests deliberately carry no root.
    cache_root: Option<SealedUvCacheRoot>,
}

/// Runner diagnostics are retained even when observation also fails.
pub(crate) struct CompletedNativeQuotaAction<Parsed, ParseError> {
    execution: Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError>,
    observation: CompletedQuotaAction,
}

impl<Parsed, ParseError> CompletedNativeQuotaAction<Parsed, ParseError> {
    pub(crate) fn execution(
        &self,
    ) -> &Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
        &self.execution
    }

    pub(crate) fn observation(&self) -> &CompletedQuotaAction {
        &self.observation
    }
}

/// The only production entry: discovery-only adapters return `None`; a native
/// request must come through the separately registered capability, including
/// its adapter-identity check, before runner preflight and batch construction.
pub(crate) fn prepare_registered_native_action(
    registration: &RegisteredAdapter,
    ctx: &DetectCtx,
    executable: ProbedUvExecutable,
    cache_root: SealedUvCacheRoot,
) -> Result<Option<PreparedNativeQuotaAction>, NativeActionPlanError> {
    if registration.id() != "uv" {
        return Err(NativeActionPlanError::NonUvAdapter(registration.id()));
    }
    executable.revalidate_path()?;
    cache_root.revalidate_for_executable(&executable)?;
    // The adapter receives exactly one data-only root derived from the sealed
    // authority. A discovery Root or quota path can never construct the proof
    // consumed by this production seam.
    let frozen_roots = [Root::well_known(cache_root.canonical_path().to_path_buf())];
    let request =
        registration.declare_native_cleanup(ctx, &frozen_roots, executable.selection())?;
    let Some(request) = request else {
        return Ok(None);
    };
    require_exact_uv_prune_contract(&request, cache_root.canonical_path())?;
    let (_selection, held_executable) = executable.into_parts();
    prepare_request_from_held(request, held_executable, cache_root).map(Some)
}

fn require_exact_uv_prune_contract(
    request: &NativeActionRequest,
    cache_root: &Path,
) -> Result<(), NativeActionPlanError> {
    if request.identity().adapter_id() != "uv" || request.identity().action_id() != "cache-prune" {
        return Err(NativeActionPlanError::CacheRootArgumentMismatch);
    }
    if !matches!(
        request.environment().inherited(),
        NativeInheritedEnvironment::Clear
    ) || request.environment().fixed()
        != [(
            std::ffi::OsString::from("UV_LOCK_TIMEOUT"),
            std::ffi::OsString::from("240"),
        )]
    {
        return Err(NativeActionPlanError::CacheRootArgumentMismatch);
    }
    let expected = [
        std::ffi::OsStr::new("--no-config"),
        std::ffi::OsStr::new("--color"),
        std::ffi::OsStr::new("never"),
        std::ffi::OsStr::new("--no-progress"),
        std::ffi::OsStr::new("--offline"),
        std::ffi::OsStr::new("--cache-dir"),
        cache_root.as_os_str(),
        std::ffi::OsStr::new("cache"),
        std::ffi::OsStr::new("prune"),
    ];
    let arguments = request.arguments();
    if arguments.len() == expected.len()
        && arguments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_os_str() == expected)
    {
        Ok(())
    } else {
        Err(NativeActionPlanError::CacheRootArgumentMismatch)
    }
}

#[cfg(test)]
fn prepare_request(
    request: NativeActionRequest,
) -> Result<PreparedNativeQuotaAction, NativeActionPlanError> {
    // All declaration, inherited-environment, and other pre-start validation
    // finishes before a batch exists. A failure therefore performs no probe.
    prepare_preflighted(prepare_native_action(request)?, None)
}

fn prepare_request_from_held(
    request: NativeActionRequest,
    held_executable: HeldNativeExecutable,
    cache_root: SealedUvCacheRoot,
) -> Result<PreparedNativeQuotaAction, NativeActionPlanError> {
    prepare_preflighted(
        prepare_native_action_from_held(request, held_executable)?,
        Some(cache_root),
    )
}

fn prepare_preflighted(
    action: PreparedNativeAction,
    cache_root: Option<SealedUvCacheRoot>,
) -> Result<PreparedNativeQuotaAction, NativeActionPlanError> {
    let adapter_id =
        ActionId::new(action.adapter_id().to_owned()).map_err(NativeActionPlanError::Contract)?;
    let action_id =
        ActionId::new(action.action_id().to_owned()).map_err(NativeActionPlanError::Contract)?;
    let targets = ActionObservationTargets::new(
        action
            .observation_requests()
            .iter()
            .cloned()
            .map(ObservationRequestPath::new)
            .map(QuotaObservationTarget::new),
    );
    let batch = PlannedActionBatch::new(
        ActionResultOwner::NativeAdapter { adapter_id },
        ActionKind::Native,
        action_id,
        targets,
    );
    Ok(PreparedNativeQuotaAction {
        action,
        batch,
        cache_root,
    })
}

impl PreparedNativeQuotaAction {
    /// Coordinates the strict pre -> execute-once -> post sequence. Consuming the
    /// prepared executor is the start boundary. Every error returned after that
    /// point is a real started failure and still receives post observation.
    pub(crate) fn execute<Parsed, ParseError>(
        self,
        probe: &mut impl FnMut(&Path) -> Result<QuotaSnapshot, ProbeError>,
        parse: impl FnOnce(&[u8]) -> Result<Parsed, ParseError>,
    ) -> CompletedNativeQuotaAction<Parsed, ParseError> {
        let Self {
            action,
            batch,
            cache_root,
        } = self;
        let (execution, observation) = quota_observation::coordinate(batch, probe, move || {
            let execution = match cache_root {
                Some(cache_root) => cache_root
                    .revalidate()
                    .map_err(|error| NativeRunnerError::MutationBinding(error.to_string()))
                    .and_then(|()| action.execute(parse).result()),
                None => action.execute(parse).result(),
            };
            let outcome = execution
                .as_ref()
                .map(|report| report.outcome().action_outcome())
                .unwrap_or(StartedActionOutcome::Failure);
            (execution, outcome)
        });
        CompletedNativeQuotaAction {
            execution,
            observation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_result::{ActionOutcome, QuotaObservationState};
    use crate::quota::model::{
        ActiveQuota, QuotaDimension, QuotaLimits, QuotaScope, QuotaScopeIdentity,
    };
    use crate::quota_observation::{ProbePhase, UnavailableObservation};
    use degu_adapters::native::{
        NativeActionIdentity, NativeEnvironmentRequest, NativeExecutableSelection,
        NativeProcessContract,
    };
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    const HELPER_TEST: &str = "native_action::tests::controlled_helper_process";
    const HELPER_MODE: &str = "DEGU_NATIVE_ACTION_HELPER_MODE";

    fn selection(path: PathBuf) -> NativeExecutableSelection {
        NativeExecutableSelection::explicit(path).unwrap()
    }

    fn request(paths: impl IntoIterator<Item = PathBuf>, mode: &str) -> NativeActionRequest {
        NativeActionRequest::new(
            NativeActionIdentity::new("fake", "prune").unwrap(),
            selection(std::env::current_exe().unwrap()),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            NativeEnvironmentRequest::clear()
                .with_fixed([(OsString::from(HELPER_MODE), OsString::from(mode))]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_millis(250),
            4096,
            4096,
            paths,
        )
        .unwrap()
    }

    fn snapshot(path: &Path, used: u64) -> QuotaSnapshot {
        QuotaSnapshot::active(
            QuotaScope::new(
                path.to_path_buf(),
                path.to_path_buf(),
                "ext4".to_owned(),
                QuotaScopeIdentity::new(7, 8, 1, PathBuf::from("/dev/test")),
            ),
            1000,
            ActiveQuota {
                provider: "test",
                data_source: "fake",
                space: QuotaDimension::new(used, QuotaLimits::new(0, 0), None),
                inodes: QuotaDimension::new(1, QuotaLimits::new(0, 0), None),
            },
        )
    }

    #[test]
    fn production_registry_has_no_native_entry() {
        let home = tempfile::tempdir().unwrap();
        let ctx = DetectCtx::for_test(home.path().to_path_buf(), [] as [(OsString, OsString); 0]);
        for registration in degu_adapters::all() {
            assert!(
                registration
                    .declare_native_cleanup(
                        &ctx,
                        &[],
                        &selection(PathBuf::from("/usr/bin/unused")),
                    )
                    .unwrap()
                    .is_none(),
                "{} unexpectedly declared native work",
                registration.id()
            );
        }
    }

    #[test]
    fn sealed_cache_root_requires_the_complete_ordinary_prune_contract() {
        let root = Path::new("/sealed/cache");
        let exact_arguments = || {
            vec![
                OsString::from("--no-config"),
                OsString::from("--color"),
                OsString::from("never"),
                OsString::from("--no-progress"),
                OsString::from("--offline"),
                OsString::from("--cache-dir"),
                root.as_os_str().to_os_string(),
                OsString::from("cache"),
                OsString::from("prune"),
            ]
        };
        let exact_environment = || {
            NativeEnvironmentRequest::clear()
                .with_fixed([(OsString::from("UV_LOCK_TIMEOUT"), OsString::from("240"))])
        };
        let declared =
            |action: &str, arguments: Vec<OsString>, environment: NativeEnvironmentRequest| {
                NativeActionRequest::new(
                    NativeActionIdentity::new("uv", action).unwrap(),
                    selection(PathBuf::from("/usr/bin/uv")),
                    arguments,
                    environment,
                    NativeProcessContract::AuditedCooperativeProcessGroup,
                    Duration::from_secs(1),
                    16,
                    16,
                    [],
                )
                .unwrap()
            };

        assert!(
            require_exact_uv_prune_contract(
                &declared("cache-prune", exact_arguments(), exact_environment()),
                root,
            )
            .is_ok()
        );

        let mut clean = exact_arguments();
        *clean.last_mut().unwrap() = OsString::from("clean");
        let mut force = exact_arguments();
        force.push(OsString::from("--force"));
        let mut ci = exact_arguments();
        ci.push(OsString::from("--ci"));
        let mut other_root = exact_arguments();
        other_root[6] = OsString::from("/other");
        for (action, arguments) in [
            ("prune", exact_arguments()),
            ("cache-prune", clean),
            ("cache-prune", force),
            ("cache-prune", ci),
            ("cache-prune", other_root),
        ] {
            assert!(matches!(
                require_exact_uv_prune_contract(
                    &declared(action, arguments, exact_environment()),
                    root,
                ),
                Err(NativeActionPlanError::CacheRootArgumentMismatch)
            ));
        }

        for environment in [
            NativeEnvironmentRequest::clear(),
            NativeEnvironmentRequest::allowlist([OsString::from("HOME")]),
            NativeEnvironmentRequest::clear()
                .with_fixed([(OsString::from("UV_NO_CACHE"), OsString::from("1"))]),
        ] {
            assert!(matches!(
                require_exact_uv_prune_contract(
                    &declared("cache-prune", exact_arguments(), environment),
                    root,
                ),
                Err(NativeActionPlanError::CacheRootArgumentMismatch)
            ));
        }
    }

    #[test]
    fn exact_duplicate_requests_fold_but_lexical_aliases_stay_distinct() {
        let action = prepare_request(request(
            [
                PathBuf::from("/a"),
                PathBuf::from("/a"),
                PathBuf::from("/a/../a"),
            ],
            "success",
        ))
        .unwrap();
        let scopes = action.batch.observation_targets().quota_scopes();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].anchor().as_path(), Path::new("/a"));
        assert_eq!(scopes[1].anchor().as_path(), Path::new("/a/../a"));
    }

    #[test]
    fn relative_request_never_probes_and_does_not_block_execution() {
        let action = prepare_request(request([PathBuf::from("relative")], "success")).unwrap();
        let completed = action.execute(
            &mut |_| unreachable!("relative request must never probe"),
            |_| Ok::<_, ()>(()),
        );
        assert!(completed.execution().is_ok());
        assert_eq!(completed.observation().outcome(), ActionOutcome::Success);
        assert!(matches!(
            completed.observation().observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::Before,
                category: "invalid_request",
                ..
            })
        ));
    }

    #[test]
    fn empty_requests_execute_without_probes_or_synthetic_delta() {
        let action = prepare_request(request([], "success")).unwrap();
        let completed = action.execute(
            &mut |_| unreachable!("empty observation set must not probe"),
            |_| Ok::<_, ()>(()),
        );
        assert!(completed.execution().is_ok());
        assert_eq!(completed.observation().outcome(), ActionOutcome::Success);
        assert!(matches!(
            completed.observation().owner(),
            ActionResultOwner::NativeAdapter { adapter_id } if adapter_id.as_str() == "fake"
        ));
        assert_eq!(completed.observation().kind(), ActionKind::Native);
        assert_eq!(completed.observation().id().as_str(), "prune");
        assert!(
            completed
                .observation()
                .observations()
                .quota_scopes()
                .is_empty()
        );
    }

    #[test]
    fn started_spawn_failure_keeps_post_observation_and_diagnostic() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let mut bad = request([canonical.clone()], "success");
        // Rebuild with a valid absolute, normalized path that cannot spawn.
        bad = NativeActionRequest::new(
            bad.identity().clone(),
            selection(PathBuf::from("/definitely/missing/degu-native-test")),
            bad.arguments().iter().cloned(),
            bad.environment().clone(),
            bad.process_contract(),
            bad.timeout(),
            bad.stdout_limit(),
            bad.stderr_limit(),
            bad.observation_requests().iter().cloned(),
        )
        .unwrap();
        let action = prepare_request(bad).unwrap();
        let mut replies =
            VecDeque::from([Ok(snapshot(&canonical, 10)), Ok(snapshot(&canonical, 9))]);
        let mut probes = 0;
        let completed = action.execute(
            &mut |path| {
                probes += 1;
                assert_eq!(path, canonical);
                replies.pop_front().unwrap()
            },
            |_| Ok::<_, ()>(()),
        );
        assert!(matches!(
            completed.execution(),
            Err(NativeRunnerError::Spawn(_))
        ));
        assert_eq!(completed.observation().outcome(), ActionOutcome::Failure);
        assert_eq!(probes, 2);
        assert!(matches!(
            completed.observation().observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(_)
        ));
    }

    #[test]
    fn cache_root_revalidation_failure_is_started_and_keeps_post_observation() {
        use std::os::unix::fs::PermissionsExt;
        // CI runs under umask 002; pin the fixture to a private tree so the seal
        // sees a non-shared-writable root regardless of the ambient umask.
        let private = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        private(&canonical, 0o700);
        std::fs::write(
            canonical.join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        private(&canonical.join("CACHEDIR.TAG"), 0o600);
        std::fs::create_dir(canonical.join("sdists-v9")).unwrap();
        private(&canonical.join("sdists-v9"), 0o700);
        let cache_root = crate::uv_cache_root::seal_uv_cache_root_for_test(canonical.clone())
            .expect("private empty root seals");
        let action = prepare_preflighted(
            prepare_native_action(request([canonical.clone()], "success")).unwrap(),
            Some(cache_root),
        )
        .unwrap();

        // A current bucket was sealed missing; attaching it before the start
        // boundary must refuse spawn rather than execute against changed scope.
        std::fs::create_dir(canonical.join("archive-v0")).unwrap();
        let mut replies =
            VecDeque::from([Ok(snapshot(&canonical, 10)), Ok(snapshot(&canonical, 10))]);
        let completed = action.execute(&mut |_| replies.pop_front().unwrap(), |_| Ok::<_, ()>(()));

        assert!(matches!(
            completed.execution(),
            Err(NativeRunnerError::MutationBinding(_))
        ));
        assert_eq!(completed.observation().outcome(), ActionOutcome::Failure);
        assert!(
            replies.is_empty(),
            "failure still receives post observation"
        );
    }

    #[test]
    fn output_cannot_replace_frozen_targets() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let action = prepare_request(request([canonical.clone()], "print-other-path")).unwrap();
        let mut replies =
            VecDeque::from([Ok(snapshot(&canonical, 10)), Ok(snapshot(&canonical, 8))]);
        let mut seen = Vec::new();
        let completed = action.execute(
            &mut |path| {
                seen.push(path.to_path_buf());
                replies.pop_front().unwrap()
            },
            |stdout| {
                assert!(
                    stdout
                        .windows(b"/not/an/observation/target\n".len())
                        .any(|window| window == b"/not/an/observation/target\n")
                );
                Ok::<_, ()>(())
            },
        );
        assert!(completed.execution().is_ok());
        assert!(
            seen.iter().all(|path| path == &canonical),
            "the output path must never become an observation target: {seen:?}"
        );
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn every_native_terminal_class_keeps_post_observation() {
        for (mode, expected) in [
            ("failure", ActionOutcome::Failure),
            ("success", ActionOutcome::OutputParseFailure),
            (
                "signal",
                ActionOutcome::Signal {
                    signal: Some(libc::SIGTERM),
                },
            ),
            ("timeout", ActionOutcome::Timeout),
            ("large-output", ActionOutcome::OutputTruncated),
        ] {
            let root = tempfile::tempdir().unwrap();
            let canonical = std::fs::canonicalize(root.path()).unwrap();
            let action = prepare_request(request([canonical.clone()], mode)).unwrap();
            let mut replies =
                VecDeque::from([Ok(snapshot(&canonical, 10)), Ok(snapshot(&canonical, 9))]);
            let completed = action.execute(&mut |_| replies.pop_front().unwrap(), |_: &[u8]| {
                if mode == "success" {
                    Err("invalid")
                } else {
                    Ok(())
                }
            });
            assert_eq!(completed.observation().outcome(), expected);
            assert!(replies.is_empty());
        }
    }

    #[test]
    fn controlled_helper_process() {
        let Ok(mode) = std::env::var(HELPER_MODE) else {
            return;
        };
        match mode.as_str() {
            "success" => {}
            "failure" => std::process::exit(17),
            "signal" => {
                // SAFETY: this dedicated child intentionally terminates itself.
                unsafe { libc::raise(libc::SIGTERM) };
            }
            "timeout" => std::thread::sleep(Duration::from_secs(30)),
            "large-output" => {
                use std::io::Write;
                std::io::stdout().write_all(&vec![b'x'; 8192]).unwrap();
            }
            "print-other-path" => println!("/not/an/observation/target"),
            other => panic!("unknown helper mode: {other:?}"),
        }
    }
}
