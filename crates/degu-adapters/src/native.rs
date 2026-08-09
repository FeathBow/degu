//! Data-only declaration boundary for optional native cleanup capabilities.
//!
//! This module grants no filesystem or lifecycle authority. A capability can
//! only describe one bounded invocation from one frozen detection context and
//! the exact roots resolved from that context. The CLI independently validates
//! and executes the request.

use degu_core::ecosystem::{DetectCtx, Root};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_ID_BYTES: usize = 128;
pub const MAX_EXECUTABLE_BYTES: usize = 4096;
pub const MAX_ARGUMENTS: usize = 128;
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_ENVIRONMENT_ENTRIES: usize = 64;
pub const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const MAX_OBSERVATION_REQUESTS: usize = 64;
pub const MAX_OBSERVATION_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeActionIdentity {
    adapter_id: String,
    action_id: String,
}

impl NativeActionIdentity {
    pub fn new(
        adapter_id: impl Into<String>,
        action_id: impl Into<String>,
    ) -> Result<Self, NativeRequestError> {
        let adapter_id = adapter_id.into();
        let action_id = action_id.into();
        if !valid_id(&adapter_id) || adapter_id.len() > MAX_ID_BYTES {
            return Err(NativeRequestError::InvalidAdapterId);
        }
        if !valid_id(&action_id) || action_id.len() > MAX_ID_BYTES {
            return Err(NativeRequestError::InvalidActionId);
        }
        Ok(Self {
            adapter_id,
            action_id,
        })
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeInheritedEnvironment {
    Clear,
    Allowlist(Vec<OsString>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEnvironmentRequest {
    inherited: NativeInheritedEnvironment,
    fixed: Vec<(OsString, OsString)>,
}

impl NativeEnvironmentRequest {
    pub fn clear() -> Self {
        Self {
            inherited: NativeInheritedEnvironment::Clear,
            fixed: Vec::new(),
        }
    }

    pub fn allowlist(names: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            inherited: NativeInheritedEnvironment::Allowlist(names.into_iter().collect()),
            fixed: Vec::new(),
        }
    }

    pub fn with_fixed(mut self, values: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        self.fixed.extend(values);
        self
    }

    pub fn inherited(&self) -> &NativeInheritedEnvironment {
        &self.inherited
    }
    pub fn fixed(&self) -> &[(OsString, OsString)] {
        &self.fixed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessContract {
    AuditedCooperativeProcessGroup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeActionRequest {
    identity: NativeActionIdentity,
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: NativeEnvironmentRequest,
    process_contract: NativeProcessContract,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    observation_requests: Vec<PathBuf>,
}

impl NativeActionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: NativeActionIdentity,
        executable: PathBuf,
        arguments: impl IntoIterator<Item = OsString>,
        environment: NativeEnvironmentRequest,
        process_contract: NativeProcessContract,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
        observation_requests: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, NativeRequestError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        let observation_requests = observation_requests.into_iter().collect::<Vec<_>>();
        if executable.as_os_str().as_bytes().len() > MAX_EXECUTABLE_BYTES {
            return Err(NativeRequestError::ExecutableTooLarge);
        }
        validate_arguments(&arguments)?;
        validate_environment(&environment)?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(NativeRequestError::InvalidTimeout);
        }
        if stdout_limit > MAX_CAPTURE_BYTES || stderr_limit > MAX_CAPTURE_BYTES {
            return Err(NativeRequestError::CaptureLimitTooLarge);
        }
        if observation_requests.len() > MAX_OBSERVATION_REQUESTS {
            return Err(NativeRequestError::TooManyObservationRequests);
        }
        let observation_bytes = observation_requests.iter().fold(0usize, |n, path| {
            n.saturating_add(path.as_os_str().as_bytes().len())
        });
        if observation_bytes > MAX_OBSERVATION_REQUEST_BYTES {
            return Err(NativeRequestError::ObservationRequestsTooLarge);
        }
        Ok(Self {
            identity,
            executable,
            arguments,
            environment,
            process_contract,
            timeout,
            stdout_limit,
            stderr_limit,
            observation_requests,
        })
    }

    pub fn identity(&self) -> &NativeActionIdentity {
        &self.identity
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
    pub fn environment(&self) -> &NativeEnvironmentRequest {
        &self.environment
    }
    pub fn process_contract(&self) -> NativeProcessContract {
        self.process_contract
    }
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    pub fn stdout_limit(&self) -> usize {
        self.stdout_limit
    }
    pub fn stderr_limit(&self) -> usize {
        self.stderr_limit
    }
    pub fn observation_requests(&self) -> &[PathBuf] {
        &self.observation_requests
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeRequestError {
    #[error("invalid native adapter id")]
    InvalidAdapterId,
    #[error("invalid native action id")]
    InvalidActionId,
    #[error("native executable path exceeds the byte limit")]
    ExecutableTooLarge,
    #[error("native argument contains an invalid byte")]
    InvalidArgument,
    #[error("native declaration has too many arguments")]
    TooManyArguments,
    #[error("native declaration arguments exceed the byte limit")]
    ArgumentsTooLarge,
    #[error("native environment name is invalid")]
    InvalidEnvironmentName,
    #[error("native environment value is invalid")]
    InvalidEnvironmentValue,
    #[error("native environment name is duplicated")]
    DuplicateEnvironmentName,
    #[error("native environment exceeds its resource limit")]
    EnvironmentTooLarge,
    #[error("native timeout is zero or exceeds the hard limit")]
    InvalidTimeout,
    #[error("native output capture limit exceeds the hard limit")]
    CaptureLimitTooLarge,
    #[error("native declaration has too many observation requests")]
    TooManyObservationRequests,
    #[error("native observation requests exceed the byte limit")]
    ObservationRequestsTooLarge,
}

#[derive(Debug, thiserror::Error)]
pub enum NativeCapabilityError {
    #[error("native declaration failed: {0}")]
    Declaration(#[from] NativeRequestError),
    #[error("native capability returned adapter id {actual:?}, expected {expected:?}")]
    AdapterIdentityMismatch {
        expected: &'static str,
        actual: String,
    },
}

/// Separate optional mutation declaration capability. Discovery remains on
/// `Ecosystem` and implementing it cannot satisfy this interface.
pub trait NativeCleanupCapability: Send + Sync {
    fn declare(
        &self,
        ctx: &DetectCtx,
        frozen_roots: &[Root],
    ) -> Result<NativeActionRequest, NativeCapabilityError>;
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn validate_arguments(arguments: &[OsString]) -> Result<(), NativeRequestError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(NativeRequestError::TooManyArguments);
    }
    let mut bytes = 0usize;
    for argument in arguments {
        if argument.as_bytes().contains(&0) {
            return Err(NativeRequestError::InvalidArgument);
        }
        bytes = bytes.saturating_add(argument.as_bytes().len());
    }
    if bytes > MAX_ARGUMENT_BYTES {
        Err(NativeRequestError::ArgumentsTooLarge)
    } else {
        Ok(())
    }
}

fn validate_environment(environment: &NativeEnvironmentRequest) -> Result<(), NativeRequestError> {
    let inherited = match environment.inherited() {
        NativeInheritedEnvironment::Clear => &[][..],
        NativeInheritedEnvironment::Allowlist(names) => names.as_slice(),
    };
    if inherited.len().saturating_add(environment.fixed().len()) > MAX_ENVIRONMENT_ENTRIES {
        return Err(NativeRequestError::EnvironmentTooLarge);
    }
    let mut names = HashSet::new();
    let mut bytes = 0usize;
    for name in inherited {
        validate_environment_name(name)?;
        if !names.insert(name.clone()) {
            return Err(NativeRequestError::DuplicateEnvironmentName);
        }
        bytes = bytes.saturating_add(name.as_bytes().len());
    }
    for (name, value) in environment.fixed() {
        validate_environment_name(name)?;
        if value.as_bytes().contains(&0) {
            return Err(NativeRequestError::InvalidEnvironmentValue);
        }
        if !names.insert(name.clone()) {
            return Err(NativeRequestError::DuplicateEnvironmentName);
        }
        bytes = bytes
            .saturating_add(name.as_bytes().len())
            .saturating_add(value.as_bytes().len());
    }
    if bytes > MAX_ENVIRONMENT_BYTES {
        Err(NativeRequestError::EnvironmentTooLarge)
    } else {
        Ok(())
    }
}

fn validate_environment_name(name: &OsStr) -> Result<(), NativeRequestError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'=') {
        Err(NativeRequestError::InvalidEnvironmentName)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn request(
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<NativeActionRequest, NativeRequestError> {
        NativeActionRequest::new(
            NativeActionIdentity::new("fake", "prune").unwrap(),
            PathBuf::from("/usr/bin/fake"),
            [OsString::from("prune")],
            NativeEnvironmentRequest::clear(),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(10),
            1024,
            2048,
            paths,
        )
    }

    #[test]
    fn observation_paths_are_stored_verbatim_without_dedup_or_normalization() {
        let missing = PathBuf::from("/does/not/exist/../still-data");
        let relative = PathBuf::from("relative");
        let declared = request([missing.clone(), relative.clone(), missing.clone()]).unwrap();
        assert_eq!(
            declared.observation_requests(),
            &[missing.clone(), relative, missing]
        );
    }

    #[test]
    fn identity_arguments_environment_and_observation_limits_are_bounded() {
        assert_eq!(
            NativeActionIdentity::new("bad id", "ok"),
            Err(NativeRequestError::InvalidAdapterId)
        );
        assert_eq!(
            NativeActionIdentity::new("x".repeat(MAX_ID_BYTES + 1), "ok"),
            Err(NativeRequestError::InvalidAdapterId)
        );
        assert!(matches!(
            NativeActionRequest::new(
                NativeActionIdentity::new("fake", "prune").unwrap(),
                PathBuf::from(format!("/{}", "x".repeat(MAX_EXECUTABLE_BYTES))),
                [],
                NativeEnvironmentRequest::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                0,
                0,
                []
            ),
            Err(NativeRequestError::ExecutableTooLarge)
        ));
        assert!(matches!(
            NativeActionRequest::new(
                NativeActionIdentity::new("fake", "prune").unwrap(),
                PathBuf::from("/x"),
                [OsString::from_vec(b"bad\0arg".to_vec())],
                NativeEnvironmentRequest::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                0,
                0,
                []
            ),
            Err(NativeRequestError::InvalidArgument)
        ));
        assert!(matches!(
            request((0..=MAX_OBSERVATION_REQUESTS).map(|n| PathBuf::from(format!("/{n}")))),
            Err(NativeRequestError::TooManyObservationRequests)
        ));
        assert!(matches!(
            request([PathBuf::from(format!(
                "/{}",
                "x".repeat(MAX_OBSERVATION_REQUEST_BYTES)
            ))]),
            Err(NativeRequestError::ObservationRequestsTooLarge)
        ));
        let duplicate = NativeEnvironmentRequest::allowlist([OsString::from("HOME")])
            .with_fixed([(OsString::from("HOME"), OsString::from("/tmp"))]);
        assert!(matches!(
            NativeActionRequest::new(
                NativeActionIdentity::new("fake", "prune").unwrap(),
                PathBuf::from("/x"),
                [],
                duplicate,
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                0,
                0,
                []
            ),
            Err(NativeRequestError::DuplicateEnvironmentName)
        ));
    }

    #[test]
    fn request_owns_a_frozen_copy_of_every_input() {
        let mut argument = OsString::from("before");
        let mut path = PathBuf::from("/before");
        let declared = NativeActionRequest::new(
            NativeActionIdentity::new("fake", "prune").unwrap(),
            PathBuf::from("/usr/bin/fake"),
            [argument.clone()],
            NativeEnvironmentRequest::clear(),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(1),
            0,
            0,
            [path.clone()],
        )
        .unwrap();
        argument.push("-after");
        path.push("after");
        assert_eq!(declared.arguments(), &[OsString::from("before")]);
        assert_eq!(declared.observation_requests(), &[PathBuf::from("/before")]);
    }
}
