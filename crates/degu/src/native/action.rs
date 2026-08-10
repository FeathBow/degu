//! Native action bridge into the existing action-result and quota-observation envelope.
//!
//! Declaration and runner preparation happen before this module creates a batch.
//! Observation requests are frozen, read-only data: they cannot authorize or alter
//! the invocation, and planning never dereferences them.

#[cfg(test)]
use crate::native::prepare_native_action;
use crate::native::{
    ActionId, ActionKind, ActionObservationTargets, ActionResultOwner, CompletedQuotaAction,
    ContractError, NativePreparationError, NativeRunReport, NativeRunnerError,
    ObservationRequestPath, PlannedActionBatch, PostObservationPolicy, PreparedNativeAction,
    QuotaObservationTarget, StartedActionOutcome, coordinate_with_post_policy,
};
use crate::quota::{ProbeError, QuotaSnapshot};
#[cfg(test)]
use degu_adapters::native::NativeActionRequest;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeActionPlanError {
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
}

/// Runner diagnostics are retained even when observation also fails.
pub(crate) struct CompletedNativeQuotaAction<Parsed, ParseError> {
    execution: Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError>,
    observation: CompletedQuotaAction,
}

impl<Parsed, ParseError> CompletedNativeQuotaAction<Parsed, ParseError> {
    #[cfg(test)]
    pub(crate) fn execution(
        &self,
    ) -> &Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
        &self.execution
    }

    #[cfg(test)]
    pub(crate) fn observation(&self) -> &CompletedQuotaAction {
        &self.observation
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError>,
        CompletedQuotaAction,
    ) {
        (self.execution, self.observation)
    }
}

/// Attach the immutable quota-observation batch to an already preflighted native
/// action. The caller must first consume adapter-specific authority and compare
/// the production registry declaration against its frozen request; quota code
/// receives only the resulting runner capability and reporting targets.
pub(crate) fn attach_quota_observation(
    action: PreparedNativeAction,
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
    Ok(PreparedNativeQuotaAction { action, batch })
}

impl PreparedNativeQuotaAction {
    /// Coordinates the strict pre -> execute-once -> post sequence. Consuming the
    /// prepared executor is the start boundary. Every error returned after that
    /// point is a real started failure and still receives post observation.
    #[cfg(test)]
    pub(crate) fn execute<Parsed, ParseError>(
        self,
        probe: &mut impl FnMut(&Path) -> Result<QuotaSnapshot, ProbeError>,
        parse: impl FnOnce(&[u8]) -> Result<Parsed, ParseError>,
    ) -> CompletedNativeQuotaAction<Parsed, ParseError> {
        self.execute_output(probe, move |stdout, _stderr| parse(stdout))
    }

    pub(crate) fn execute_output<Parsed, ParseError>(
        self,
        probe: &mut impl FnMut(&Path) -> Result<QuotaSnapshot, ProbeError>,
        parse: impl FnOnce(&[u8], &[u8]) -> Result<Parsed, ParseError>,
    ) -> CompletedNativeQuotaAction<Parsed, ParseError> {
        let Self { action, batch } = self;
        let (execution, observation) = coordinate_with_post_policy(batch, probe, move || {
            let execution = action.execute_output(parse).result();
            let outcome = execution
                .as_ref()
                .map(|report| report.outcome().action_outcome())
                .unwrap_or(StartedActionOutcome::Failure);
            let post_policy = native_post_policy(&execution);
            (execution, outcome, post_policy)
        });
        CompletedNativeQuotaAction {
            execution,
            observation,
        }
    }
}

fn native_post_policy<Parsed, ParseError>(
    execution: &Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError>,
) -> PostObservationPolicy {
    if execution
        .as_ref()
        .is_err_and(NativeRunnerError::termination_unconfirmed)
    {
        PostObservationPolicy::Unavailable {
            category: "action_not_terminal",
            message: "native action termination is unconfirmed; post-action quota observation was not attempted"
                .to_owned(),
        }
    } else {
        PostObservationPolicy::Probe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{ActionOutcome, QuotaObservationState};
    use crate::native::{ProbePhase, UnavailableObservation};
    use crate::quota::model::{
        ActiveQuota, QuotaDimension, QuotaLimits, QuotaScope, QuotaScopeIdentity,
    };
    use degu_adapters::native::{
        NativeActionIdentity, NativeEnvironmentRequest, NativeExecutableSelection,
        NativeProcessContract,
    };
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    const HELPER_TEST: &str = "native::action::tests::controlled_helper_process";
    const HELPER_MODE: &str = "DEGU_NATIVE_ACTION_HELPER_MODE";

    fn request(paths: impl IntoIterator<Item = PathBuf>, mode: &str) -> NativeActionRequest {
        NativeActionRequest::new(
            NativeActionIdentity::new("fake", "prune").unwrap(),
            NativeExecutableSelection::explicit(std::env::current_exe().unwrap()).unwrap(),
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

    fn prepare_request(
        request: NativeActionRequest,
    ) -> Result<PreparedNativeQuotaAction, NativeActionPlanError> {
        // Test-only path-based preparation exercises the generic observation envelope.
        // Production uv preparation enters with a held executable and root binding.
        attach_quota_observation(prepare_native_action(request)?)
    }

    #[test]
    fn unconfirmed_child_termination_disables_post_observation() {
        let execution: Result<NativeRunReport<(), ()>, _> =
            Err(NativeRunnerError::TerminationUnconfirmed {
                stage: "controlled test",
            });
        assert!(matches!(
            native_post_policy(&execution),
            PostObservationPolicy::Unavailable {
                category: "action_not_terminal",
                ..
            }
        ));
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
            NativeExecutableSelection::explicit(PathBuf::from(
                "/definitely/missing/degu-native-test",
            ))
            .unwrap(),
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
