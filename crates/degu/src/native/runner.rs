//! Bounded execution primitive for validated native adapter actions.
//!
//! This module is crate-private and deliberately carries no lifecycle handle,
//! cleanup path, or mutation capability. A declaration fixes the executable,
//! arguments, environment policy, cooperative process contract, resource limits,
//! and timeout before spawn. Process-group cleanup bounds the caller and
//! cooperative descendants; it is not a cross-platform containment sandbox.

use crate::native::StartedActionOutcome;
use degu_adapters::native::{
    NativeActionRequest, NativeInheritedEnvironment,
    NativeProcessContract as RequestedProcessContract,
};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_DRAIN_BYTES_PER_TICK: usize = 64 * 1024;
const POST_EXIT_DRAIN_GRACE: Duration = Duration::from_millis(250);
const KILL_REAP_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InheritedEnvironment {
    Clear,
    Allowlist(Vec<OsString>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeEnvironment {
    inherited: InheritedEnvironment,
    fixed: Vec<(OsString, OsString)>,
}

impl NativeEnvironment {
    pub(crate) fn clear() -> Self {
        Self {
            inherited: InheritedEnvironment::Clear,
            fixed: Vec::new(),
        }
    }

    pub(crate) fn allowlist(names: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            inherited: InheritedEnvironment::Allowlist(names.into_iter().collect()),
            fixed: Vec::new(),
        }
    }

    pub(crate) fn with_fixed(
        mut self,
        values: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Self {
        self.fixed.extend(values);
        self
    }
}

/// Fully fixed declaration for one future native adapter invocation.
/// Explicit process-topology policy required from every future adapter.
///
/// This is an audit assertion, not a kernel containment capability. It may be
/// selected only for a tool whose invoked action and descendants are known not
/// to daemonize, call `setsid`, unshare into another PID namespace, or otherwise
/// escape the runner's process group. Adapter wiring must review that behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeProcessContract {
    AuditedCooperativeProcessGroup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeActionDeclaration {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: NativeEnvironment,
    process_contract: NativeProcessContract,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
}

impl NativeActionDeclaration {
    pub(crate) fn from_request(
        request: &NativeActionRequest,
    ) -> Result<Self, NativeDeclarationError> {
        let environment = match request.environment().inherited() {
            NativeInheritedEnvironment::Clear => NativeEnvironment::clear(),
            NativeInheritedEnvironment::Allowlist(names) => {
                NativeEnvironment::allowlist(names.iter().cloned())
            }
        }
        .with_fixed(request.environment().fixed().iter().cloned());
        let process_contract = match request.process_contract() {
            RequestedProcessContract::AuditedCooperativeProcessGroup => {
                NativeProcessContract::AuditedCooperativeProcessGroup
            }
        };
        Self::new(
            request.executable().to_path_buf(),
            request.arguments().iter().cloned(),
            environment,
            process_contract,
            request.timeout(),
            request.stdout_limit(),
            request.stderr_limit(),
        )
    }

    pub(crate) fn new(
        executable: PathBuf,
        arguments: impl IntoIterator<Item = OsString>,
        environment: NativeEnvironment,
        process_contract: NativeProcessContract,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Result<Self, NativeDeclarationError> {
        validate_executable(&executable)?;
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        validate_arguments(&arguments)?;
        validate_environment(&environment)?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(NativeDeclarationError::InvalidTimeout);
        }
        if stdout_limit > MAX_CAPTURE_BYTES || stderr_limit > MAX_CAPTURE_BYTES {
            return Err(NativeDeclarationError::CaptureLimitTooLarge);
        }
        Ok(Self {
            executable,
            arguments,
            environment,
            process_contract,
            timeout,
            stdout_limit,
            stderr_limit,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeDeclarationError {
    #[error("native executable path is not absolute")]
    ExecutableNotAbsolute,
    #[error("native executable path is not lexically normalized")]
    ExecutableNotLexicallyNormalized,
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
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativePreparationError {
    #[error("native declaration validation failed: {0}")]
    Declaration(#[from] NativeDeclarationError),
    #[error("native preflight failed before spawn: {0}")]
    Preflight(#[source] NativeRunnerError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeRunnerError {
    #[error("inherited native environment exceeds its bound at {0:?}")]
    InheritedEnvironmentTooLarge(OsString),
    #[error("private native executable snapshot failed attachment revalidation: {0}")]
    ExecutableBinding(#[source] io::Error),
    #[error("native mutation scope failed attachment revalidation: {0}")]
    MutationBinding(String),
    #[error("failed to establish the native child descriptor policy: {0}")]
    DescriptorPolicy(#[source] io::Error),
    #[error("failed to spawn native action: {0}")]
    Spawn(#[source] io::Error),
    #[error("failed to configure nonblocking native output: {0}")]
    OutputSetup(#[source] io::Error),
    #[error("failed while waiting for native action: {0}")]
    Wait(#[source] io::Error),
    #[error("failed to drain native action output: {0}")]
    Drain(#[source] io::Error),
    #[error("native action termination is unconfirmed after {stage}")]
    TerminationUnconfirmed { stage: &'static str },
}

impl NativeRunnerError {
    pub(crate) fn termination_unconfirmed(&self) -> bool {
        matches!(self, Self::TerminationUnconfirmed { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
    limit: usize,
}

impl CapturedOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    #[cfg(test)]
    pub(crate) fn for_test(bytes: Vec<u8>, truncated: bool, limit: usize) -> Self {
        Self {
            bytes,
            truncated,
            limit,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NativeRunOutcome<Parsed, ParseError> {
    Success(Parsed),
    ExitFailure { code: Option<i32> },
    Signal { signal: Option<i32> },
    Timeout,
    OutputTruncated,
    OutputParseFailure(ParseError),
}

impl<Parsed, ParseError> NativeRunOutcome<Parsed, ParseError> {
    /// Normalization precedence is timeout, signal, non-zero/unknown exit,
    /// truncation, parse failure, then success.
    pub(crate) fn action_outcome(&self) -> StartedActionOutcome {
        match self {
            Self::Success(_) => StartedActionOutcome::Success,
            Self::ExitFailure { .. } => StartedActionOutcome::Failure,
            Self::Signal { signal } => StartedActionOutcome::Signal { signal: *signal },
            Self::Timeout => StartedActionOutcome::Timeout,
            Self::OutputTruncated => StartedActionOutcome::OutputTruncated,
            Self::OutputParseFailure(_) => StartedActionOutcome::OutputParseFailure,
        }
    }
}

/// One-use, fully preflighted native invocation. It deliberately is neither
/// `Clone` nor reusable. Calling `execute` is the exact spawn-attempt boundary.
pub(crate) struct PreparedNativeAction {
    declaration: NativeActionDeclaration,
    adapter_id: String,
    action_id: String,
    observation_requests: Vec<PathBuf>,
    resolved_environment: Vec<(OsString, OsString)>,
    /// Keeps the private executable snapshot and its cleanup lease alive through
    /// execution. Its descriptor is CLOEXEC and never enters the tool.
    held_executable: Option<HeldNativeExecutable>,
    /// Adapter-specific mutation authority retained through quota pre-observation
    /// and consumed for one final fail-closed attachment check immediately before
    /// spawn. Reporting paths cannot construct this closure.
    mutation_binding: Option<MutationBinding>,
}

type MutationBinding = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// One private executable snapshot. Its stable path works with `exec` on both
/// Linux and macOS, while the open descriptor pins identity. The shared cleanup
/// lease removes the snapshot only after all prepared uses finish.
pub(crate) struct HeldNativeExecutable {
    executable: OwnedFd,
    execution_path: PathBuf,
    identity: rustix::fs::Stat,
    cleanup: Arc<ExecutableSnapshotCleanup>,
}

struct ExecutableSnapshotCleanup {
    parent: OwnedFd,
    directory: OwnedFd,
    directory_name: OsString,
}

impl HeldNativeExecutable {
    pub(crate) fn new(
        executable: OwnedFd,
        execution_path: PathBuf,
        parent: OwnedFd,
        directory: OwnedFd,
        directory_name: OsString,
    ) -> io::Result<Self> {
        let identity = rustix::fs::fstat(&executable).map_err(io::Error::from)?;
        Ok(Self {
            executable,
            execution_path,
            identity,
            cleanup: Arc::new(ExecutableSnapshotCleanup {
                parent,
                directory,
                directory_name,
            }),
        })
    }

    pub(crate) fn duplicate(&self) -> io::Result<Self> {
        Ok(Self {
            executable: rustix::io::dup(&self.executable).map_err(io::Error::from)?,
            execution_path: self.execution_path.clone(),
            identity: self.identity,
            cleanup: Arc::clone(&self.cleanup),
        })
    }

    fn revalidate(&self) -> io::Result<()> {
        let held = rustix::fs::fstat(&self.executable).map_err(io::Error::from)?;
        let attached = rustix::fs::statat(
            &self.cleanup.directory,
            "uv",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let path = rustix::fs::statat(
            rustix::fs::CWD,
            &self.execution_path,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let execution_parent = self
            .execution_path
            .parent()
            .ok_or_else(|| io::Error::other("native snapshot path has no parent"))?;
        let parent = rustix::fs::openat(
            rustix::fs::CWD,
            execution_parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let parent = rustix::fs::fstat(&parent).map_err(io::Error::from)?;
        let held_parent = rustix::fs::fstat(&self.cleanup.directory).map_err(io::Error::from)?;
        if !same_snapshot_identity(&self.identity, &held)
            || !same_snapshot_identity(&self.identity, &attached)
            || !same_snapshot_identity(&self.identity, &path)
            || parent.st_dev != held_parent.st_dev
            || parent.st_ino != held_parent.st_ino
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private native executable snapshot changed identity or path attachment",
            ));
        }
        Ok(())
    }

    fn execution_path(&self) -> &Path {
        &self.execution_path
    }

    #[cfg(test)]
    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.execution_path
    }
}

fn same_snapshot_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

impl Drop for ExecutableSnapshotCleanup {
    fn drop(&mut self) {
        cleanup_executable_snapshot(&self.parent, &self.directory, &self.directory_name);
    }
}

/// Best-effort cleanup of the exact private snapshot namespace held by FDs.
/// This intentionally does not use path-based removal or the general lifecycle.
pub(crate) fn cleanup_executable_snapshot(
    parent: &OwnedFd,
    directory: &OwnedFd,
    directory_name: &OsStr,
) {
    raw_unlinkat(directory, OsStr::new("uv"), 0);
    raw_unlinkat(parent, directory_name, libc::AT_REMOVEDIR);
}

#[allow(
    clippy::disallowed_methods,
    reason = "removes only fixed names created in a random private snapshot directory, through held exact parent FDs"
)]
fn raw_unlinkat(parent: &OwnedFd, name: &OsStr, flags: libc::c_int) {
    let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
        return;
    };
    // SAFETY: `parent` stays live; `name` is a NUL-terminated single relative
    // component created by this module; flags are either zero or AT_REMOVEDIR.
    unsafe {
        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags);
    }
}

impl PreparedNativeAction {
    pub(crate) fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    pub(crate) fn observation_requests(&self) -> &[PathBuf] {
        &self.observation_requests
    }

    /// Consuming this value crosses the start boundary. The descriptor-table
    /// bound is deliberately refreshed here, not at preparation, so an FD
    /// opened between preparation and execution is still covered by fallback.
    /// Refresh or spawn failure is therefore a started execution error.
    pub(crate) fn execute<Parsed, ParseError>(
        self,
        parse: impl FnOnce(&[u8]) -> Result<Parsed, ParseError>,
    ) -> StartedNativeExecution<Parsed, ParseError> {
        self.execute_output(move |stdout, _stderr| parse(stdout))
    }

    /// Variant for audited tools, including uv, whose stable machine-disabled
    /// summary is written to stderr. Both streams remain independently bounded.
    pub(crate) fn execute_output<Parsed, ParseError>(
        self,
        parse: impl FnOnce(&[u8], &[u8]) -> Result<Parsed, ParseError>,
    ) -> StartedNativeExecution<Parsed, ParseError> {
        self.execute_output_with_descriptor_limit(parse, descriptor_scan_limit)
    }

    fn execute_output_with_descriptor_limit<Parsed, ParseError>(
        self,
        parse: impl FnOnce(&[u8], &[u8]) -> Result<Parsed, ParseError>,
        refresh_descriptor_limit: impl FnOnce() -> io::Result<i32>,
    ) -> StartedNativeExecution<Parsed, ParseError> {
        StartedNativeExecution {
            result: run_preflighted_output(
                self.declaration,
                self.resolved_environment,
                self.held_executable,
                self.mutation_binding,
                refresh_descriptor_limit,
                parse,
            ),
        }
    }
}

pub(crate) struct StartedNativeExecution<Parsed, ParseError> {
    result: Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError>,
}

impl<Parsed, ParseError> StartedNativeExecution<Parsed, ParseError> {
    pub(crate) fn result(self) -> Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
        self.result
    }
}

#[cfg(test)]
pub(crate) fn prepare_native_action(
    request: NativeActionRequest,
) -> Result<PreparedNativeAction, NativePreparationError> {
    prepare_native_action_with(request, None, None, resolve_environment)
}

/// Prepare a request to execute the exact private snapshot paired with a held
/// descriptor and cleanup lease, rather than resolving the caller-selected
/// pathname again at spawn. The request retains that reviewed lexical selection
/// for identity and adapter-substitution checks.
pub(crate) fn prepare_native_action_from_held(
    request: NativeActionRequest,
    held_executable: HeldNativeExecutable,
) -> Result<PreparedNativeAction, NativePreparationError> {
    prepare_native_action_with(request, Some(held_executable), None, resolve_environment)
}

/// The only production preparation seam that retains adapter-specific mutation
/// authority through the quota pre-observation and into the runner's final pre-spawn
/// check. The binding is one-shot and cannot be cloned or recovered as a path.
pub(crate) fn prepare_native_action_from_held_with_binding(
    request: NativeActionRequest,
    held_executable: HeldNativeExecutable,
    mutation_binding: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<PreparedNativeAction, NativePreparationError> {
    prepare_native_action_with(
        request,
        Some(held_executable),
        Some(Box::new(mutation_binding)),
        resolve_environment,
    )
}

fn prepare_native_action_with(
    request: NativeActionRequest,
    held_executable: Option<HeldNativeExecutable>,
    mutation_binding: Option<MutationBinding>,
    resolve: impl FnOnce(&NativeEnvironment) -> Result<Vec<(OsString, OsString)>, NativeRunnerError>,
) -> Result<PreparedNativeAction, NativePreparationError> {
    let mut declaration = NativeActionDeclaration::from_request(&request)?;
    if let Some(executable) = &held_executable {
        declaration.executable = executable.execution_path().to_path_buf();
    }
    let resolved_environment =
        resolve(&declaration.environment).map_err(NativePreparationError::Preflight)?;
    Ok(PreparedNativeAction {
        declaration,
        adapter_id: request.identity().adapter_id().to_owned(),
        action_id: request.identity().action_id().to_owned(),
        observation_requests: request.observation_requests().to_vec(),
        resolved_environment,
        held_executable,
        mutation_binding,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeRunReport<Parsed, ParseError> {
    outcome: NativeRunOutcome<Parsed, ParseError>,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
}

impl<Parsed, ParseError> NativeRunReport<Parsed, ParseError> {
    pub(crate) fn outcome(&self) -> &NativeRunOutcome<Parsed, ParseError> {
        &self.outcome
    }

    pub(crate) fn stdout(&self) -> &CapturedOutput {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &CapturedOutput {
        &self.stderr
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        outcome: NativeRunOutcome<Parsed, ParseError>,
        stdout: CapturedOutput,
        stderr: CapturedOutput,
    ) -> Self {
        Self {
            outcome,
            stdout,
            stderr,
        }
    }
}

/// Test-only entry point that resolves the environment inline; production paths
/// go through `PreparedNativeAction`.
#[cfg(test)]
fn run_native_action<Parsed, ParseError>(
    declaration: &NativeActionDeclaration,
    parse: impl FnOnce(&[u8]) -> Result<Parsed, ParseError>,
) -> Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
    let resolved_environment = resolve_environment(&declaration.environment)?;
    run_preflighted(
        declaration.clone(),
        resolved_environment,
        None,
        descriptor_scan_limit,
        parse,
    )
}

#[cfg(test)]
fn run_preflighted<Parsed, ParseError>(
    declaration: NativeActionDeclaration,
    resolved_environment: Vec<(OsString, OsString)>,
    held_executable: Option<HeldNativeExecutable>,
    refresh_descriptor_limit: impl FnOnce() -> io::Result<i32>,
    parse: impl FnOnce(&[u8]) -> Result<Parsed, ParseError>,
) -> Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
    run_preflighted_output(
        declaration,
        resolved_environment,
        held_executable,
        None,
        refresh_descriptor_limit,
        move |stdout, _stderr| parse(stdout),
    )
}

fn run_preflighted_output<Parsed, ParseError>(
    declaration: NativeActionDeclaration,
    resolved_environment: Vec<(OsString, OsString)>,
    held_executable: Option<HeldNativeExecutable>,
    mutation_binding: Option<MutationBinding>,
    refresh_descriptor_limit: impl FnOnce() -> io::Result<i32>,
    parse: impl FnOnce(&[u8], &[u8]) -> Result<Parsed, ParseError>,
) -> Result<NativeRunReport<Parsed, ParseError>, NativeRunnerError> {
    let mut command = Command::new(&declaration.executable);
    command
        .args(&declaration.arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A private process group provides cleanup for the explicitly audited
        // cooperative topology; it does not contain setsid/namespace escape.
        .process_group(0);
    apply_resolved_environment(&mut command, &resolved_environment);
    // Refresh after command construction and immediately before installing the
    // pre-exec policy/spawning. This is intentionally inside the consuming
    // started boundary, not frozen with declaration preparation.
    let scan_limit = refresh_descriptor_limit().map_err(NativeRunnerError::DescriptorPolicy)?;
    install_descriptor_policy(&mut command, scan_limit);

    // These are the final fallible attachment checks before `spawn`. They live
    // inside the consuming started boundary and after the quota pre-observation.
    if let Some(executable) = &held_executable {
        executable
            .revalidate()
            .map_err(NativeRunnerError::ExecutableBinding)?;
    }
    if let Some(binding) = mutation_binding {
        binding().map_err(NativeRunnerError::MutationBinding)?;
    }

    let mut child = command.spawn().map_err(NativeRunnerError::Spawn)?;
    let process_group = child.id();
    let mut stdout_pipe = child.stdout.take().expect("piped stdout is present");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr is present");
    if let Err(error) = set_nonblocking(&stdout_pipe).and_then(|()| set_nonblocking(&stderr_pipe)) {
        return Err(terminate_reap_or_defer(
            child,
            process_group,
            "output setup failure",
            NativeRunnerError::OutputSetup(error),
        ));
    }

    let mut stdout = CapturedOutput::empty(declaration.stdout_limit);
    let mut stderr = CapturedOutput::empty(declaration.stderr_limit);
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let execution_deadline = Instant::now() + declaration.timeout;
    let mut kill_deadline = None;
    let mut drain_deadline = None;
    let mut status = None;
    let mut timed_out = false;

    loop {
        if !stdout_eof {
            match drain_available(&mut stdout_pipe, &mut stdout) {
                Ok(eof) => stdout_eof = eof,
                Err(error) => {
                    return Err(terminate_reap_or_defer(
                        child,
                        process_group,
                        "stdout drain failure",
                        NativeRunnerError::Drain(error),
                    ));
                }
            }
        }
        if !stderr_eof {
            match drain_available(&mut stderr_pipe, &mut stderr) {
                Ok(eof) => stderr_eof = eof,
                Err(error) => {
                    return Err(terminate_reap_or_defer(
                        child,
                        process_group,
                        "stderr drain failure",
                        NativeRunnerError::Drain(error),
                    ));
                }
            }
        }

        let now = Instant::now();
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(observed)) => {
                    status = Some(observed);
                    // A declaration is bounded work, not a daemon launcher.
                    terminate_process_group(process_group);
                    let candidate = now + POST_EXIT_DRAIN_GRACE;
                    drain_deadline =
                        Some(kill_deadline.map_or(candidate, |kill| candidate.min(kill)));
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(terminate_reap_or_defer(
                        child,
                        process_group,
                        "wait failure",
                        NativeRunnerError::Wait(error),
                    ));
                }
            }
        }

        if status.is_none() && !timed_out && now >= execution_deadline {
            timed_out = true;
            terminate_process_group(process_group);
            // Fallback covers a platform/process-group failure.
            let _ = child.kill();
            kill_deadline = Some(now + KILL_REAP_GRACE);
        }

        if status.is_none() && kill_deadline.is_some_and(|deadline| now >= deadline) {
            defer_reap(child);
            return Err(NativeRunnerError::TerminationUnconfirmed {
                stage: "timeout kill grace",
            });
        }

        if let Some(observed) = status {
            if stdout_eof && stderr_eof {
                let outcome = normalize_outcome(observed, timed_out, &stdout, &stderr, parse);
                return Ok(NativeRunReport {
                    outcome,
                    stdout,
                    stderr,
                });
            }
            if drain_deadline.is_some_and(|deadline| now >= deadline) {
                // A descendant escaped the process group while retaining a pipe,
                // or a pipe otherwise failed to reach EOF. Close our read ends
                // and make incomplete output dominate parse/success.
                stdout.truncated |= !stdout_eof;
                stderr.truncated |= !stderr_eof;
                let outcome = normalize_outcome(observed, timed_out, &stdout, &stderr, parse);
                return Ok(NativeRunReport {
                    outcome,
                    stdout,
                    stderr,
                });
            }
        }

        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
}

fn normalize_outcome<Parsed, ParseError>(
    status: ExitStatus,
    timed_out: bool,
    stdout: &CapturedOutput,
    stderr: &CapturedOutput,
    parse: impl FnOnce(&[u8], &[u8]) -> Result<Parsed, ParseError>,
) -> NativeRunOutcome<Parsed, ParseError> {
    if timed_out {
        return NativeRunOutcome::Timeout;
    }
    if let Some(signal) = status.signal() {
        return NativeRunOutcome::Signal {
            signal: Some(signal),
        };
    }
    if !status.success() {
        return NativeRunOutcome::ExitFailure {
            code: status.code(),
        };
    }
    if stdout.truncated || stderr.truncated {
        return NativeRunOutcome::OutputTruncated;
    }
    match parse(&stdout.bytes, &stderr.bytes) {
        Ok(parsed) => NativeRunOutcome::Success(parsed),
        Err(error) => NativeRunOutcome::OutputParseFailure(error),
    }
}

impl CapturedOutput {
    fn empty(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            truncated: false,
            limit,
        }
    }
}

fn set_nonblocking(output: &impl AsRawFd) -> io::Result<()> {
    let fd = output.as_raw_fd();
    // SAFETY: fd is a live owned pipe. F_GETFL does not modify memory and
    // F_SETFL changes only this open file description's status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same live fd; the existing flags are preserved while adding
    // O_NONBLOCK so neither stream can stall the other or the deadline loop.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain_available(input: &mut impl Read, captured: &mut CapturedOutput) -> io::Result<bool> {
    let mut buffer = [0_u8; 8 * 1024];
    let mut drained = 0_usize;
    while drained < MAX_DRAIN_BYTES_PER_TICK {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                retain_bytes(captured, &buffer[..count]);
                drained = drained.saturating_add(count);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    // Yield to the sibling stream, child-state check, and deadline even when a
    // producer can keep this pipe perpetually readable.
    Ok(false)
}

fn retain_bytes(captured: &mut CapturedOutput, bytes: &[u8]) {
    let remaining = captured.limit.saturating_sub(captured.bytes.len());
    let retained = bytes.len().min(remaining);
    captured.bytes.extend_from_slice(&bytes[..retained]);
    captured.truncated |= retained != bytes.len();
}

fn terminate_reap_or_defer(
    mut child: std::process::Child,
    process_group: u32,
    stage: &'static str,
    confirmed_error: NativeRunnerError,
) -> NativeRunnerError {
    terminate_process_group(process_group);
    let _ = child.kill();
    if reap_within_grace(&mut child) {
        confirmed_error
    } else {
        defer_reap(child);
        NativeRunnerError::TerminationUnconfirmed { stage }
    }
}

fn reap_within_grace(child: &mut std::process::Child) -> bool {
    let deadline = Instant::now() + KILL_REAP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(WAIT_POLL_INTERVAL),
            Ok(None) | Err(_) => return false,
        }
    }
}

/// A SIGKILLed task may remain uninterruptible and unreapable. Move the child
/// into a detached best-effort waiter rather than violating the caller's bound.
fn defer_reap(mut child: std::process::Child) {
    let _ = std::thread::Builder::new()
        .name("degu-native-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn terminate_process_group(process_group: u32) {
    let Ok(process_group) = i32::try_from(process_group) else {
        return;
    };
    // SAFETY: a negative PID addresses the process group created for the child;
    // SIGKILL has no borrowed-memory or signal-handler safety requirements.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

fn install_descriptor_policy(command: &mut Command, scan_limit: i32) {
    // SAFETY: the closure performs only async-signal-safe syscalls after fork.
    // It marks every non-stdio descriptor CLOEXEC in the child only. Rust's
    // exec-error pipe remains usable if exec fails because CLOEXEC takes effect
    // only after a successful exec.
    unsafe {
        command.pre_exec(move || mark_nonstdio_cloexec(scan_limit));
    }
}

fn descriptor_scan_limit() -> io::Result<i32> {
    #[cfg(target_os = "linux")]
    const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    const DESCRIPTOR_DIRECTORY: &str = "/dev/fd";

    // A soft RLIMIT can be lowered below descriptors which are already open.
    // Enumerate the actual descriptor table instead, and fail closed if the
    // platform view is unavailable. The directory's own temporary FD may be
    // included; scanning one closed slot after this function returns is safe.
    let mut highest = 2_i32;
    for entry in std::fs::read_dir(DESCRIPTOR_DIRECTORY)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<i32>() else {
            continue;
        };
        highest = highest.max(fd);
    }
    highest
        .checked_add(1)
        .ok_or_else(|| io::Error::other("native descriptor table exceeds the supported range"))
}

fn mark_nonstdio_cloexec(scan_limit: i32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        // SAFETY: close_range with CLOEXEC mutates only the child descriptor
        // table and accepts the full unsigned range without user pointers.
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL)
        ) {
            return Err(error);
        }
    }

    mark_nonstdio_cloexec_fallback(scan_limit)
}

fn mark_nonstdio_cloexec_fallback(scan_limit: i32) -> io::Result<()> {
    for fd in 3..scan_limit {
        loop {
            // SAFETY: fcntl operates on the numeric descriptor in the forked
            // child. EBADF means the slot is already closed and is harmless.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::EBADF) {
                    break;
                }
                return Err(error);
            }
            // SAFETY: the live descriptor's existing flags are preserved.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            break;
        }
    }
    Ok(())
}

fn resolve_environment(
    environment: &NativeEnvironment,
) -> Result<Vec<(OsString, OsString)>, NativeRunnerError> {
    let mut bytes = environment
        .fixed
        .iter()
        .fold(0_usize, |total, (name, value)| {
            total
                .saturating_add(os_len(name))
                .saturating_add(os_len(value))
        });
    let mut resolved = Vec::new();
    if let InheritedEnvironment::Allowlist(names) = &environment.inherited {
        for name in names {
            if let Some(value) = std::env::var_os(name) {
                bytes = bytes
                    .saturating_add(os_len(name))
                    .saturating_add(os_len(&value));
                if bytes > MAX_ENVIRONMENT_BYTES {
                    return Err(NativeRunnerError::InheritedEnvironmentTooLarge(
                        name.clone(),
                    ));
                }
                resolved.push((name.clone(), value));
            }
        }
    }
    resolved.extend(environment.fixed.iter().cloned());
    Ok(resolved)
}

fn apply_resolved_environment(command: &mut Command, environment: &[(OsString, OsString)]) {
    for (name, value) in environment {
        command.env(name, value);
    }
}

fn validate_executable(path: &Path) -> Result<(), NativeDeclarationError> {
    if !path.is_absolute() {
        return Err(NativeDeclarationError::ExecutableNotAbsolute);
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(NativeDeclarationError::ExecutableNotLexicallyNormalized);
    }
    let Some(Component::Normal(_)) = components.next() else {
        return Err(NativeDeclarationError::ExecutableNotLexicallyNormalized);
    };
    if !components.all(|component| matches!(component, Component::Normal(_))) {
        return Err(NativeDeclarationError::ExecutableNotLexicallyNormalized);
    }
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(NativeDeclarationError::ExecutableNotLexicallyNormalized);
    }
    Ok(())
}

fn validate_arguments(arguments: &[OsString]) -> Result<(), NativeDeclarationError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(NativeDeclarationError::TooManyArguments);
    }
    let mut bytes = 0_usize;
    for argument in arguments {
        if argument.as_bytes().contains(&0) {
            return Err(NativeDeclarationError::InvalidArgument);
        }
        bytes = bytes.saturating_add(os_len(argument));
    }
    if bytes > MAX_ARGUMENT_BYTES {
        return Err(NativeDeclarationError::ArgumentsTooLarge);
    }
    Ok(())
}

fn validate_environment(environment: &NativeEnvironment) -> Result<(), NativeDeclarationError> {
    let inherited = match &environment.inherited {
        InheritedEnvironment::Clear => &[][..],
        InheritedEnvironment::Allowlist(names) => names.as_slice(),
    };
    if inherited.len().saturating_add(environment.fixed.len()) > MAX_ENVIRONMENT_ENTRIES {
        return Err(NativeDeclarationError::EnvironmentTooLarge);
    }
    let mut names = HashSet::new();
    let mut bytes = 0_usize;
    for name in inherited {
        validate_environment_name(name)?;
        if !names.insert(name.clone()) {
            return Err(NativeDeclarationError::DuplicateEnvironmentName);
        }
        bytes = bytes.saturating_add(os_len(name));
    }
    for (name, value) in &environment.fixed {
        validate_environment_name(name)?;
        if value.as_bytes().contains(&0) {
            return Err(NativeDeclarationError::InvalidEnvironmentValue);
        }
        if !names.insert(name.clone()) {
            return Err(NativeDeclarationError::DuplicateEnvironmentName);
        }
        bytes = bytes
            .saturating_add(os_len(name))
            .saturating_add(os_len(value));
    }
    if bytes > MAX_ENVIRONMENT_BYTES {
        return Err(NativeDeclarationError::EnvironmentTooLarge);
    }
    Ok(())
}

fn validate_environment_name(name: &OsStr) -> Result<(), NativeDeclarationError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'=') {
        Err(NativeDeclarationError::InvalidEnvironmentName)
    } else {
        Ok(())
    }
}

fn os_len(value: &OsStr) -> usize {
    value.as_bytes().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;

    const HELPER_TEST: &str = "native::runner::tests::controlled_helper_process";
    const HELPER_MODE: &str = "DEGU_NATIVE_RUNNER_HELPER_MODE";
    const HELPER_FD: &str = "DEGU_NATIVE_RUNNER_HELPER_FD";

    fn native_request(executable: PathBuf, paths: Vec<PathBuf>) -> NativeActionRequest {
        NativeActionRequest::new(
            degu_adapters::native::NativeActionIdentity::new("fake", "prune").unwrap(),
            degu_adapters::native::NativeExecutableSelection::explicit(executable).unwrap(),
            [OsString::from("prune")],
            degu_adapters::native::NativeEnvironmentRequest::clear(),
            RequestedProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(1),
            64,
            64,
            paths,
        )
        .unwrap()
    }

    fn declaration(
        mode: &str,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> NativeActionDeclaration {
        NativeActionDeclaration::new(
            std::env::current_exe().unwrap(),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            NativeEnvironment::clear()
                .with_fixed([(OsString::from(HELPER_MODE), OsString::from(mode))]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            timeout,
            stdout_limit,
            stderr_limit,
        )
        .unwrap()
    }

    #[test]
    fn prepared_action_freezes_identity_paths_and_is_consumed_at_spawn_boundary() {
        let paths = vec![PathBuf::from("/persistent"), PathBuf::from("relative-data")];
        let prepared = prepare_native_action(native_request(
            PathBuf::from("/definitely/missing/degu-native-tool"),
            paths.clone(),
        ))
        .unwrap();
        assert_eq!(prepared.adapter_id(), "fake");
        assert_eq!(prepared.action_id(), "prune");
        assert_eq!(prepared.observation_requests(), paths);

        // `execute(self, ..)` consumes the only prepared capability. A missing
        // executable is a spawn-attempt failure, not a preflight failure.
        let started = prepared.execute(|_| Ok::<(), ()>(()));
        assert!(matches!(started.result(), Err(NativeRunnerError::Spawn(_))));
    }

    #[test]
    fn from_request_carries_every_declared_field_and_substitutes_nothing() {
        let request = NativeActionRequest::new(
            degu_adapters::native::NativeActionIdentity::new("fake", "prune").unwrap(),
            degu_adapters::native::NativeExecutableSelection::explicit(PathBuf::from(
                "/usr/bin/prune-tool",
            ))
            .unwrap(),
            [OsString::from("cache"), OsString::from("--prune")],
            degu_adapters::native::NativeEnvironmentRequest::allowlist([OsString::from("HOME")])
                .with_fixed([(OsString::from("TOOL_MODE"), OsString::from("prune"))]),
            RequestedProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(42),
            111,
            222,
            [PathBuf::from("/observed/root")],
        )
        .unwrap();

        let declaration = NativeActionDeclaration::from_request(&request).unwrap();

        assert_eq!(declaration.executable, PathBuf::from("/usr/bin/prune-tool"));
        assert_eq!(
            declaration.arguments,
            vec![OsString::from("cache"), OsString::from("--prune")]
        );
        assert_eq!(
            declaration.environment.inherited,
            InheritedEnvironment::Allowlist(vec![OsString::from("HOME")])
        );
        assert_eq!(
            declaration.environment.fixed,
            vec![(OsString::from("TOOL_MODE"), OsString::from("prune"))]
        );
        assert_eq!(declaration.timeout, Duration::from_secs(42));
        assert_eq!(declaration.stdout_limit, 111);
        assert_eq!(declaration.stderr_limit, 222);
    }

    #[test]
    fn preflight_failure_never_produces_a_started_capability() {
        let error = prepare_native_action_with(
            native_request(PathBuf::from("/usr/bin/fake"), Vec::new()),
            None,
            None,
            |_| {
                Err(NativeRunnerError::InheritedEnvironmentTooLarge(
                    OsString::from("HUGE"),
                ))
            },
        )
        .err()
        .expect("preflight must fail");
        assert!(matches!(
            error,
            NativePreparationError::Preflight(NativeRunnerError::InheritedEnvironmentTooLarge(_))
        ));
    }

    #[test]
    fn descriptor_refresh_failure_is_a_started_execution_error() {
        let prepared = prepare_native_action(native_request(
            PathBuf::from("/definitely/missing/degu-native-tool"),
            Vec::new(),
        ))
        .unwrap();
        let started = prepared.execute_output_with_descriptor_limit(
            |_, _| Ok::<(), ()>(()),
            || Err(io::Error::other("controlled descriptor refresh failure")),
        );
        assert!(matches!(
            started.result(),
            Err(NativeRunnerError::DescriptorPolicy(_))
        ));
    }

    #[test]
    fn post_spawn_error_returns_only_after_killed_child_is_reaped() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", HELPER_TEST, "--nocapture"])
            .env_clear()
            .env(HELPER_MODE, "timeout")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().unwrap();
        let process_group = child.id();
        let error = terminate_reap_or_defer(
            child,
            process_group,
            "controlled drain failure",
            NativeRunnerError::Drain(io::Error::other("controlled")),
        );
        assert!(matches!(error, NativeRunnerError::Drain(_)));
    }

    #[test]
    fn mutation_binding_is_consumed_inside_started_boundary_before_spawn() {
        let prepared = prepare_native_action_with(
            native_request(
                PathBuf::from("/definitely/missing/degu-native-tool"),
                Vec::new(),
            ),
            None,
            Some(Box::new(|| Err("sealed uv root changed".to_owned()))),
            resolve_environment,
        )
        .unwrap();
        let result = prepared.execute(|_| Ok::<(), ()>(())).result();
        assert!(matches!(
            result,
            Err(NativeRunnerError::MutationBinding(message))
                if message == "sealed uv root changed"
        ));
    }

    #[test]
    fn declaration_rejects_path_argument_environment_and_limit_ambiguity() {
        let valid = std::env::current_exe().unwrap();
        assert_eq!(
            NativeActionDeclaration::new(
                PathBuf::from("tool"),
                [],
                NativeEnvironment::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                1,
                1,
            ),
            Err(NativeDeclarationError::ExecutableNotAbsolute)
        );
        assert_eq!(
            NativeActionDeclaration::new(
                PathBuf::from("/bin/../bin/tool"),
                [],
                NativeEnvironment::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                1,
                1,
            ),
            Err(NativeDeclarationError::ExecutableNotLexicallyNormalized)
        );
        assert!(matches!(
            NativeActionDeclaration::new(
                valid.clone(),
                [OsString::from_vec(b"bad\0arg".to_vec())],
                NativeEnvironment::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                1,
                1,
            ),
            Err(NativeDeclarationError::InvalidArgument)
        ));
        assert!(matches!(
            NativeActionDeclaration::new(
                valid.clone(),
                [],
                NativeEnvironment::allowlist([OsString::from("PATH")])
                    .with_fixed([(OsString::from("PATH"), OsString::from("/evil"))]),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                1,
                1,
            ),
            Err(NativeDeclarationError::DuplicateEnvironmentName)
        ));
        assert!(matches!(
            NativeActionDeclaration::new(
                valid.clone(),
                [],
                NativeEnvironment::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::ZERO,
                1,
                1,
            ),
            Err(NativeDeclarationError::InvalidTimeout)
        ));
        assert!(matches!(
            NativeActionDeclaration::new(
                valid,
                [],
                NativeEnvironment::clear(),
                NativeProcessContract::AuditedCooperativeProcessGroup,
                Duration::from_secs(1),
                MAX_CAPTURE_BYTES + 1,
                1,
            ),
            Err(NativeDeclarationError::CaptureLimitTooLarge)
        ));
    }

    #[test]
    fn concurrent_drains_finish_and_cap_both_streams() {
        let report = run_native_action(
            &declaration("both-large", Duration::from_secs(5), 1024, 2048),
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::OutputTruncated);
        assert_eq!(report.stdout().bytes().len(), 1024);
        assert_eq!(report.stderr().bytes().len(), 2048);
        assert!(report.stdout().truncated());
        assert!(report.stderr().truncated());
    }

    #[test]
    fn timeout_kills_and_reaps_the_process_group() {
        let started = Instant::now();
        let report = run_native_action(
            &declaration("timeout-tree", Duration::from_millis(50), 4096, 4096),
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Timeout);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            report.outcome().action_outcome(),
            StartedActionOutcome::Timeout
        );
    }

    #[test]
    fn escaped_descendant_cannot_hold_capture_pipes_unbounded() {
        let started = Instant::now();
        let report = run_native_action(
            &declaration("escaped-pipe", Duration::from_secs(5), 4096, 4096),
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::OutputTruncated);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn continuous_stdout_flood_cannot_starve_timeout_or_stderr() {
        let started = Instant::now();
        let report = run_native_action(
            &declaration("stdout-flood", Duration::from_millis(50), 1024, 1024),
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Timeout);
        assert!(report.stdout().truncated());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn signal_precedes_truncation_and_parse() {
        let report =
            run_native_action(&declaration("signal", Duration::from_secs(5), 0, 0), |_| {
                Err::<(), _>("must not parse")
            })
            .unwrap();
        assert!(matches!(
            report.outcome(),
            NativeRunOutcome::Signal {
                signal: Some(libc::SIGTERM)
            }
        ));
    }

    #[test]
    fn failed_exit_precedes_truncation_and_parse() {
        let report = run_native_action(
            &declaration("exit-failure", Duration::from_secs(5), 1, 1),
            |_| Err::<(), _>("must not parse"),
        )
        .unwrap();
        assert_eq!(
            report.outcome(),
            &NativeRunOutcome::ExitFailure { code: Some(7) }
        );
        assert!(report.stdout().truncated());
    }

    #[test]
    fn parse_failure_and_success_are_distinct_after_complete_successful_output() {
        let declaration = declaration("success", Duration::from_secs(5), 4096, 4096);
        let failed =
            run_native_action(&declaration, |_| Err::<usize, _>("invalid output")).unwrap();
        assert_eq!(
            failed.outcome(),
            &NativeRunOutcome::OutputParseFailure("invalid output")
        );
        let succeeded = run_native_action(&declaration, |bytes| {
            std::str::from_utf8(bytes)
                .map(|text| text.contains("HELPER_OK"))
                .map_err(|_| ())
        })
        .unwrap();
        assert_eq!(succeeded.outcome(), &NativeRunOutcome::Success(true));
    }

    #[test]
    fn absolute_execution_does_not_consult_path_or_interpret_shell_arguments() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("injected");
        let declaration = NativeActionDeclaration::new(
            std::env::current_exe().unwrap(),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
                OsString::from(format!(";touch {}", marker.display())),
            ],
            NativeEnvironment::clear().with_fixed([
                (OsString::from(HELPER_MODE), OsString::from("success")),
                (
                    OsString::from("PATH"),
                    OsString::from("/definitely/not/used"),
                ),
            ]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(5),
            4096,
            4096,
        )
        .unwrap();
        // The absolute test executable starts even though PATH is unusable. The
        // injected-looking argument is passed literally to the test harness.
        let _report = run_native_action(&declaration, |_| Ok::<_, ()>(())).unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn prepared_execution_refreshes_descriptor_bound_after_prepare() {
        use std::os::fd::{FromRawFd, OwnedFd};

        let target_fd = descriptor_scan_limit().unwrap().checked_add(100).unwrap();
        let request = NativeActionRequest::new(
            degu_adapters::native::NativeActionIdentity::new("fake", "descriptor-check").unwrap(),
            degu_adapters::native::NativeExecutableSelection::explicit(
                std::env::current_exe().unwrap(),
            )
            .unwrap(),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            degu_adapters::native::NativeEnvironmentRequest::clear().with_fixed([
                (
                    OsString::from(HELPER_MODE),
                    OsString::from("descriptor-policy"),
                ),
                (
                    OsString::from(HELPER_FD),
                    OsString::from(target_fd.to_string()),
                ),
            ]),
            RequestedProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(5),
            4096,
            4096,
            [],
        )
        .unwrap();
        let prepared = prepare_native_action(request).unwrap();

        let temp = tempfile::tempfile().unwrap();
        // Open the non-CLOEXEC descriptor only after preparation. Since the
        // requested slot is above the then-current table, F_DUPFD returns it.
        // SAFETY: temp is live and the successful result is immediately owned.
        let raw = unsafe { libc::fcntl(temp.as_raw_fd(), libc::F_DUPFD, target_fd) };
        assert_eq!(
            raw, target_fd,
            "failed to create controlled high descriptor"
        );
        // SAFETY: raw is a fresh successful F_DUPFD result.
        let high_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: high_fd remains live through child execution.
        assert_eq!(
            unsafe { libc::fcntl(high_fd.as_raw_fd(), libc::F_GETFD) },
            0
        );

        let report = prepared
            .execute(|bytes| {
                Ok::<_, ()>(String::from_utf8_lossy(bytes).contains("DESCRIPTORS_CLOSED"))
            })
            .result()
            .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Success(true));
    }

    #[test]
    fn fallback_refresh_covers_a_descriptor_opened_after_a_stale_bound() {
        use std::os::fd::{FromRawFd, OwnedFd};

        let stale_limit = descriptor_scan_limit().unwrap();
        let target_fd = stale_limit.checked_add(50).unwrap();
        let temp = tempfile::tempfile().unwrap();
        // SAFETY: temp is live and the successful result is immediately owned.
        let raw = unsafe { libc::fcntl(temp.as_raw_fd(), libc::F_DUPFD, target_fd) };
        assert_eq!(raw, target_fd);
        // SAFETY: raw is a fresh successful F_DUPFD result.
        let high_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(
            raw >= stale_limit,
            "the stale bound must miss this descriptor"
        );

        let refreshed_limit = descriptor_scan_limit().unwrap();
        assert!(refreshed_limit > raw);
        mark_nonstdio_cloexec_fallback(refreshed_limit).unwrap();
        // SAFETY: high_fd remains live for the query.
        let flags = unsafe { libc::fcntl(high_fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn child_closes_nonstdio_parent_descriptors() {
        use std::os::fd::{FromRawFd, OwnedFd};

        let temp = tempfile::tempfile().unwrap();
        // F_DUPFD deliberately creates a non-CLOEXEC descriptor at a high slot.
        // SAFETY: temp owns a live descriptor and the returned duplicate is
        // immediately adopted by OwnedFd.
        let raw = unsafe { libc::fcntl(temp.as_raw_fd(), libc::F_DUPFD, 900) };
        assert!(
            raw >= 900,
            "failed to duplicate test descriptor: {}",
            io::Error::last_os_error()
        );
        // SAFETY: raw is a fresh successful F_DUPFD result owned by this test.
        let leaked = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: leaked is live for the call.
        assert_eq!(unsafe { libc::fcntl(leaked.as_raw_fd(), libc::F_GETFD) }, 0);

        let declaration = NativeActionDeclaration::new(
            std::env::current_exe().unwrap(),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            NativeEnvironment::clear().with_fixed([
                (
                    OsString::from(HELPER_MODE),
                    OsString::from("descriptor-policy"),
                ),
                (OsString::from(HELPER_FD), OsString::from(raw.to_string())),
            ]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(5),
            4096,
            4096,
        )
        .unwrap();
        let report = run_native_action(&declaration, |bytes| {
            Ok::<_, ()>(String::from_utf8_lossy(bytes).contains("DESCRIPTORS_CLOSED"))
        })
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Success(true));
    }

    #[test]
    fn environment_is_cleared_except_for_explicit_fixed_values() {
        let report = run_native_action(
            &declaration("environment", Duration::from_secs(5), 4096, 4096),
            |bytes| {
                let text = String::from_utf8_lossy(bytes);
                Ok::<_, ()>(text.contains("ENVIRONMENT_OK"))
            },
        )
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Success(true));
    }

    #[test]
    fn environment_allowlist_inherits_only_named_values() {
        assert!(std::env::var_os("PATH").is_some());
        let declaration = NativeActionDeclaration::new(
            std::env::current_exe().unwrap(),
            [
                OsString::from("--exact"),
                OsString::from(HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            NativeEnvironment::allowlist([OsString::from("PATH")])
                .with_fixed([(OsString::from(HELPER_MODE), OsString::from("allowlist"))]),
            NativeProcessContract::AuditedCooperativeProcessGroup,
            Duration::from_secs(5),
            4096,
            4096,
        )
        .unwrap();
        let report = run_native_action(&declaration, |bytes| {
            Ok::<_, ()>(String::from_utf8_lossy(bytes).contains("ALLOWLIST_OK"))
        })
        .unwrap();
        assert_eq!(report.outcome(), &NativeRunOutcome::Success(true));
    }

    #[test]
    #[allow(
        clippy::zombie_processes,
        reason = "the controlled helper must exit while descendants retain pipes so the runner's group cleanup and drain deadline are exercised"
    )]
    fn controlled_helper_process() {
        let Ok(mode) = std::env::var(HELPER_MODE) else {
            return;
        };
        match mode.as_str() {
            "both-large" => {
                let bytes = vec![b'x'; 256 * 1024];
                std::io::stdout().write_all(&bytes).unwrap();
                std::io::stdout().flush().unwrap();
                std::io::stderr().write_all(&bytes).unwrap();
                std::io::stderr().flush().unwrap();
            }
            "timeout-tree" => {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", HELPER_TEST, "--nocapture"])
                    .env(HELPER_MODE, "descendant")
                    .spawn()
                    .unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "descendant" => std::thread::sleep(Duration::from_secs(30)),
            "escaped-pipe" => {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", HELPER_TEST, "--nocapture"])
                    .env(HELPER_MODE, "escaped-descendant")
                    .spawn()
                    .unwrap();
                // Give the controlled child time to leave our process group.
                std::thread::sleep(Duration::from_millis(200));
            }
            "escaped-descendant" => {
                // SAFETY: this dedicated helper intentionally escapes the runner's
                // process group while retaining inherited capture pipes.
                assert_ne!(unsafe { libc::setsid() }, -1);
                std::thread::sleep(Duration::from_secs(2));
            }
            "stdout-flood" => {
                let bytes = [b'f'; 8 * 1024];
                loop {
                    if std::io::stdout().write_all(&bytes).is_err() {
                        break;
                    }
                }
            }
            "signal" => {
                std::io::stdout().write_all(b"truncated").unwrap();
                // SAFETY: raising SIGTERM in the dedicated child process is the fixture.
                unsafe { libc::raise(libc::SIGTERM) };
            }
            "exit-failure" => {
                std::io::stdout().write_all(b"long output").unwrap();
                std::io::stdout().flush().unwrap();
                std::process::exit(7);
            }
            "success" => println!("HELPER_OK"),
            "descriptor-policy" => {
                let fd = std::env::var(HELPER_FD).unwrap().parse::<i32>().unwrap();
                // SAFETY: probing a numeric descriptor with F_GETFD does not
                // dereference memory. The child policy must have closed it.
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                println!("DESCRIPTORS_CLOSED");
            }
            "environment" => {
                assert!(std::env::var_os("PATH").is_none());
                assert_eq!(std::env::var(HELPER_MODE).unwrap(), "environment");
                assert_eq!(std::env::current_dir().unwrap(), Path::new("/"));
                let mut stdin = Vec::new();
                std::io::stdin().read_to_end(&mut stdin).unwrap();
                assert!(stdin.is_empty());
                println!("ENVIRONMENT_OK");
            }
            "allowlist" => {
                assert!(std::env::var_os("PATH").is_some());
                assert!(std::env::var_os("HOME").is_none());
                println!("ALLOWLIST_OK");
            }
            other => panic!("unknown helper mode: {other}"),
        }
    }
}
