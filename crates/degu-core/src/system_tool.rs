//! Bounded invocation of a trusted, host-installed tool.
//!
//! degu answers nearly every question with a syscall. A few facts belong to a
//! host service whose protocol is deliberately late-bound, so no syscall can
//! return them: the account database behind the name service switch is the case
//! that forces this module. A statically linked build cannot load the host's
//! resolver plugins into its own address space, and reimplementing each backend
//! would mean owning the plugins we deliberately do not own. Asking a
//! dynamically linked tool the host already trusts, in a separate process, is
//! the supported way to read such a fact.
//!
//! Everything here is tool-agnostic: an absolute binary, a fixed argument list,
//! and hard bounds on time and output. `degu`'s Lustre quota probe runs the same
//! shape against `lfs` and is the intended next caller.
//! Each invocation owns a process group: ordinary descendants are stopped when
//! its wrapper exits or exceeds the time limit. This is not a sandbox for tools
//! that deliberately escape the group with setsid or setpgid.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const READ_CHUNK_BYTES: usize = 4096;
/// Reaping starts eagerly and backs off. A cached account answer costs single
/// digit milliseconds, and a fixed interval would dominate it; a tool that runs
/// long is then waited on cheaply.
const FIRST_POLL_INTERVAL: Duration = Duration::from_micros(500);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Grace for the reader thread once the child has already been reaped.
const OUTPUT_COLLECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a tool produced no usable answer. None of these are the tool answering
/// "no"; that is a successful run whose output the caller parses.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// No executable exists at this path.
    #[error("no executable at {0}")]
    NotInstalled(String),
    /// The executable exists but could not be started.
    #[error("could not start {path}")]
    Spawn {
        path: String,
        #[source]
        source: io::Error,
    },
    /// The tool outlived its bound and was killed.
    #[error("{path} exceeded its {timeout:?} bound")]
    Timeout { path: String, timeout: Duration },
    /// The tool wrote more than the caller admits.
    #[error("{0} wrote more than the accepted output bound")]
    OutputOverflow(String),
    /// The tool ran but its output could not be collected.
    #[error("could not collect output from {0}")]
    OutputUnreadable(String),
    /// The invocation's private process group could not be stopped.
    #[error("could not stop the process group for {path}")]
    Terminate {
        path: String,
        #[source]
        source: io::Error,
    },
    /// Waiting on the child failed.
    #[error("could not wait for {path}")]
    Wait {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// A completed run within its bounds. `success` is the tool's own verdict; a
/// tool that ran and reported "not found" is a successful invocation with an
/// unsuccessful status, not an error.
#[derive(Debug)]
pub struct CapturedRun {
    pub success: bool,
    pub stdout: Vec<u8>,
}

enum Capture {
    Complete(Vec<u8>),
    Overflowed,
    Failed,
}

/// One host-tool invocation and its resource bounds.
pub struct Invocation<'a> {
    pub binary: &'a Path,
    pub arguments: &'a [&'a OsStr],
    pub timeout: Duration,
    pub stdout_cap: usize,
}

impl Invocation<'_> {
    /// Run with an optional payload on stdin. The child receives only a pinned
    /// C locale, a neutral working directory, and its own process group.
    /// A payload goes through a pipe rather than argv or a temporary file.
    pub fn run(self, input: Option<&[u8]>) -> Result<CapturedRun, ToolError> {
        let path = self.binary.display().to_string();
        let mut child = spawn_tool(self.binary, self.arguments, input.is_some())?;
        let output = capture_output(&mut child, self.stdout_cap);
        write_input(&mut child, input);
        let status = wait_for_tool(&mut child, &path, self.timeout)?;
        // Ending the wrapper also ends its invocation, including ordinary
        // descendants still holding the pipes.
        terminate_group(&child, &path)?;
        collect_output(output, status, path)
    }
}

fn spawn_tool(binary: &Path, arguments: &[&OsStr], has_input: bool) -> Result<Child, ToolError> {
    Command::new(binary)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(if has_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|source| match source.kind() {
            io::ErrorKind::NotFound => ToolError::NotInstalled(binary.display().to_string()),
            _ => ToolError::Spawn {
                path: binary.display().to_string(),
                source,
            },
        })
}

fn capture_output(child: &mut Child, cap: usize) -> mpsc::Receiver<Capture> {
    let stdout = child.stdout.take().expect("stdout is piped");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(read_capped(stdout, cap));
    });
    receiver
}

fn write_input(child: &mut Child, input: Option<&[u8]>) {
    if let Some(payload) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        let payload = payload.to_vec();
        // Keep writes off the wait path: a tool need not read its input.
        // EPIPE means the tool declined more input; its status remains final.
        std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
        });
    }
}

fn wait_for_tool(
    child: &mut Child,
    path: &str,
    timeout: Duration,
) -> Result<ExitStatus, ToolError> {
    let deadline = Instant::now() + timeout;
    let mut interval = FIRST_POLL_INTERVAL;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                terminate_group(child, path)?;
                reap(child, path)?;
                return Err(ToolError::Timeout {
                    path: path.to_owned(),
                    timeout,
                });
            }
            Ok(None) => {
                std::thread::sleep(interval);
                interval = (interval * 2).min(MAX_POLL_INTERVAL);
            }
            Err(source) => {
                terminate_group(child, path)?;
                reap(child, path)?;
                return Err(ToolError::Wait {
                    path: path.to_owned(),
                    source,
                });
            }
        }
    }
}

fn terminate_group(child: &Child, path: &str) -> Result<(), ToolError> {
    use rustix::process::{Pid, Signal, kill_process_group};

    match kill_process_group(Pid::from_child(child), Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(source) => Err(ToolError::Terminate {
            path: path.to_owned(),
            source: source.into(),
        }),
    }
}

fn reap(child: &mut Child, path: &str) -> Result<(), ToolError> {
    child.wait().map(|_| ()).map_err(|source| ToolError::Wait {
        path: path.to_owned(),
        source,
    })
}

fn collect_output(
    output: mpsc::Receiver<Capture>,
    status: ExitStatus,
    path: String,
) -> Result<CapturedRun, ToolError> {
    match output.recv_timeout(OUTPUT_COLLECT_TIMEOUT) {
        Ok(Capture::Complete(stdout)) => Ok(CapturedRun {
            success: status.success(),
            stdout,
        }),
        Ok(Capture::Overflowed) => Err(ToolError::OutputOverflow(path)),
        Ok(Capture::Failed) | Err(_) => Err(ToolError::OutputUnreadable(path)),
    }
}

/// Read to EOF, accumulating at most `cap` bytes.
///
/// Draining continues past the bound rather than stopping there: a child that
/// fills the pipe would otherwise block on its next write and live until the
/// timeout kills it, turning a tool that merely says too much into a stall.
fn read_capped(mut stream: impl Read, cap: usize) -> Capture {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    let mut overflowed = false;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                return if overflowed {
                    Capture::Overflowed
                } else {
                    Capture::Complete(buffer)
                };
            }
            Ok(read) => {
                if overflowed || buffer.len() + read > cap {
                    overflowed = true;
                    buffer = Vec::new();
                    continue;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Capture::Failed,
        }
    }
}

#[cfg(test)]
mod tests;
