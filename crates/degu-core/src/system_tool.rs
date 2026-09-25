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

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
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

/// Run `binary` with exactly `arguments` and capture at most `stdout_cap` bytes.
///
/// The child gets an emptied environment with a pinned C locale, so neither
/// loader variables nor locale can change what it does or how it prints; a
/// neutral working directory; a closed stdin; and a discarded stderr. Nothing
/// is resolved through `PATH` and no shell is involved.
pub fn run_capped(
    binary: &Path,
    arguments: &[&OsStr],
    timeout: Duration,
    stdout_cap: usize,
) -> Result<CapturedRun, ToolError> {
    run_capped_input(binary, arguments, None, timeout, stdout_cap)
}

/// [`run_capped`] that also hands the tool `input` on its standard input.
///
/// Standard input is the only channel that shows the tool a payload without
/// putting it in `argv`, where every account on a shared node can read it, or on
/// disk, where it outlives the run. Output is already drained by a separate
/// thread, so writing here cannot deadlock against a tool that answers while it
/// is still being written to; a tool that stops reading early closes the pipe,
/// and that is its answer, not an error.
pub fn run_capped_with_input(
    binary: &Path,
    arguments: &[&OsStr],
    input: &[u8],
    timeout: Duration,
    stdout_cap: usize,
) -> Result<CapturedRun, ToolError> {
    run_capped_input(binary, arguments, Some(input), timeout, stdout_cap)
}

fn run_capped_input(
    binary: &Path,
    arguments: &[&OsStr],
    input: Option<&[u8]>,
    timeout: Duration,
    stdout_cap: usize,
) -> Result<CapturedRun, ToolError> {
    let path = binary.display().to_string();
    let mut child = Command::new(binary)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| match source.kind() {
            io::ErrorKind::NotFound => ToolError::NotInstalled(path.clone()),
            _ => ToolError::Spawn {
                path: path.clone(),
                source,
            },
        })?;

    // Taking the pipe moves the parent's only handle into the reader, so the
    // read sees EOF as soon as the child exits.
    let stdout = child.stdout.take().expect("stdout is piped");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(read_capped(stdout, stdout_cap));
    });

    // On its own thread, because this caller's bound is enforced by the wait
    // loop below and a tool that never reads its input would otherwise block the
    // write before the loop is ever entered — a payload larger than the pipe
    // buffer would hang past any timeout. Dropping the handle when the write
    // finishes closes the pipe, so a tool reading to EOF sees one. A tool that
    // stopped reading gives this thread EPIPE, which its own exit status and
    // output already account for.
    if let Some(payload) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        let payload = payload.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
        });
    }

    let deadline = Instant::now() + timeout;
    let mut interval = FIRST_POLL_INTERVAL;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ToolError::Timeout { path, timeout });
                }
                std::thread::sleep(interval);
                interval = (interval * 2).min(MAX_POLL_INTERVAL);
            }
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ToolError::Wait { path, source });
            }
        }
    };

    match receiver.recv_timeout(OUTPUT_COLLECT_TIMEOUT) {
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
mod tests {
    use super::*;

    fn os(value: &str) -> &OsStr {
        OsStr::new(value)
    }

    /// The payload reaches the tool's standard input and nowhere else: not in
    /// `argv`, where every account on a shared node could read it, and not on
    /// disk, where it would outlive the run.
    #[test]
    fn a_payload_reaches_the_tool_on_standard_input() {
        let cat = ["/bin/cat", "/usr/bin/cat"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.exists())
            .expect("a host with no cat cannot run this suite");
        let run = run_capped_with_input(
            cat,
            &[],
            b"degu advisory payload",
            Duration::from_secs(5),
            4096,
        )
        .expect("cat runs");
        assert!(run.success);
        assert_eq!(run.stdout, b"degu advisory payload");
    }

    /// A tool that never reads its input still gets to answer. Nothing here may
    /// turn "this program ignored the payload" into a failed run.
    #[test]
    fn a_tool_that_ignores_its_input_still_answers() {
        let echo = ["/bin/echo", "/usr/bin/echo"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.exists())
            .expect("a host with no echo cannot run this suite");
        let run = run_capped_with_input(
            echo,
            &[os("answered anyway")],
            &vec![b'x'; 256 * 1024],
            Duration::from_secs(5),
            4096,
        )
        .expect("echo runs");
        assert!(run.success);
        assert_eq!(run.stdout, b"answered anyway\n");
    }

    /// A tool that never reads its input and never exits must still be killed at
    /// the bound. Writing the payload inline would block here instead, before
    /// the bound is ever enforced.
    #[test]
    fn a_tool_that_never_reads_a_large_payload_still_hits_its_bound() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.exists())
            .expect("a host with no sleep cannot run this suite");
        let started = Instant::now();
        let error = run_capped_with_input(
            sleep,
            &[os("30")],
            // Comfortably past any pipe buffer, so the write cannot complete
            // before the tool would have to read it.
            &vec![b'x'; 4 * 1024 * 1024],
            Duration::from_millis(500),
            4096,
        )
        .expect_err("a sleeping tool cannot answer");
        assert!(matches!(error, ToolError::Timeout { .. }), "{error:?}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the bound did not stop the write: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn missing_binary_is_reported_as_not_installed() {
        let error = run_capped(
            Path::new("/nonexistent/degu-system-tool-probe"),
            &[],
            Duration::from_secs(5),
            1024,
        )
        .expect_err("a missing binary cannot run");
        assert!(matches!(error, ToolError::NotInstalled(_)), "{error:?}");
    }

    #[test]
    fn stdout_is_captured_and_status_reported() {
        let run = run_capped(
            Path::new("/bin/echo"),
            &[os("degu")],
            Duration::from_secs(5),
            1024,
        )
        .expect("echo runs");
        assert!(run.success);
        assert_eq!(run.stdout, b"degu\n");
    }

    #[test]
    fn a_failing_tool_is_a_successful_invocation() {
        let run = run_capped(
            Path::new("/bin/sh"),
            &[os("-c"), os("exit 2")],
            Duration::from_secs(5),
            1024,
        )
        .expect("sh runs");
        assert!(!run.success);
        assert!(run.stdout.is_empty());
    }

    #[test]
    fn output_beyond_the_bound_is_refused() {
        let error = run_capped(
            Path::new("/bin/sh"),
            &[os("-c"), os("printf '%0.sx' $(seq 1 4096)")],
            Duration::from_secs(10),
            64,
        )
        .expect_err("output past the bound is not an answer");
        assert!(matches!(error, ToolError::OutputOverflow(_)), "{error:?}");
    }

    #[test]
    fn a_flood_past_the_pipe_buffer_is_refused_without_waiting_for_the_bound() {
        let started = Instant::now();
        let error = run_capped(
            Path::new("/bin/sh"),
            &[os("-c"), os("head -c 1000000 /dev/zero | tr '\\0' 'x'")],
            Duration::from_secs(30),
            1024,
        )
        .expect_err("output past the bound is not an answer");
        assert!(matches!(error, ToolError::OutputOverflow(_)), "{error:?}");
        // A reader that stopped at the bound would leave the child blocked on
        // its next write, and this would take the full 30 seconds.
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_tool_that_outlives_its_bound_is_killed() {
        let started = Instant::now();
        let error = run_capped(
            Path::new("/bin/sh"),
            &[os("-c"), os("sleep 30")],
            Duration::from_millis(200),
            1024,
        )
        .expect_err("a tool past its bound is not an answer");
        assert!(matches!(error, ToolError::Timeout { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn the_child_environment_is_emptied_apart_from_the_pinned_locale() {
        // SAFETY: single-threaded test setup, before any child is spawned.
        unsafe { std::env::set_var("DEGU_SYSTEM_TOOL_LEAK_PROBE", "leaked") };
        let run = run_capped(
            Path::new("/bin/sh"),
            &[os("-c"), os("env")],
            Duration::from_secs(5),
            64 * 1024,
        )
        .expect("sh runs");
        // SAFETY: single-threaded test teardown.
        unsafe { std::env::remove_var("DEGU_SYSTEM_TOOL_LEAK_PROBE") };
        let environment = String::from_utf8(run.stdout).expect("env prints UTF-8 here");
        assert!(!environment.contains("DEGU_SYSTEM_TOOL_LEAK_PROBE"));
        assert!(environment.contains("LC_ALL=C"));
    }
}
