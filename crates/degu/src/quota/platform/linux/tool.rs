//! Bounded run of a host quota tool, and the column grammar the tools share.
//!
//! The exec hardening: an absolute binary path, a cleared environment, a pinned C
//! locale, a neutral working directory, closed stdin, bounded concurrent capture
//! of both streams, and a bounded timeout. `degu_core::system_tool` has the same
//! shape but discards stderr, which is where these tools say why they failed.
//!
//! A tool also dies with degu. `Child` does not kill on drop, and the timeout below
//! is enforced by the thread running it, so `degu quota` passing its own deadline,
//! a Ctrl-C or a kill would otherwise leave a tool running with nobody watching it.
//! That is what the parent-death signal is for. It fires when the *thread* that
//! spawned the child ends, which is safe here: `capture` is what spawns, and it
//! holds that thread until the child has exited or been given up on. The kernel
//! clears the signal on executing a set-user-ID binary, and it reaches only the tool
//! itself and not anything the tool started.

use super::{MountInfo, ProbeError};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Linux `f_type` has arch-dependent signedness and width; every known magic
/// value is 32-bit, so comparisons mask to the low 32 bits first. This is the
/// same trick as degu-walk's fstype module, reimplemented locally because
/// that module is private to degu-walk.
const LINUX_F_TYPE_MASK: u64 = u32::MAX as u64;
/// Per-stream capture bound; output beyond it makes the probe Incomplete.
const OUTPUT_CAP_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 4096;
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_COLLECT_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const KIB: u64 = 1024;
/// Reasons surface on stderr; keep hostile or verbose tool output bounded.
/// The display layer escapes terminal controls, so truncation is the only
/// concern here.
const STDERR_REASON_CHAR_CAP: usize = 200;

#[derive(Debug)]
pub(super) struct Execution {
    pub(super) status: ExitStatus,
    pub(super) stdout: CappedStream,
    pub(super) stderr: CappedStream,
}

#[derive(Debug)]
pub(super) struct CappedStream {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

/// One tool invocation. `tool` is its name in error messages.
pub(super) struct ToolRun<'a> {
    pub(super) binary: &'a Path,
    pub(super) tool: &'static str,
    pub(super) arguments: &'a [&'a OsStr],
    pub(super) timeout: Duration,
}

pub(super) fn capture(run: ToolRun<'_>, mount: &MountInfo) -> Result<Execution, ProbeError> {
    let tool = run.tool;
    let mut child = spawn_tool(&run, mount)?;
    // Read both pipes concurrently on dedicated threads: a child that fills
    // stderr while the parent drains only stdout (or vice versa) would
    // deadlock against a full pipe buffer. The threads are never joined; on
    // the failure paths below they stay parked on a read until this
    // short-lived process exits.
    let stdout_stream = child.stdout.take().expect("stdout is piped at spawn");
    let stderr_stream = child.stderr.take().expect("stderr is piped at spawn");
    let stdout_receiver = spawn_capped_reader(stdout_stream);
    let stderr_receiver = spawn_capped_reader(stderr_stream);
    let status = await_exit(&mut child, mount, tool, run.timeout)?;
    // The pipes normally close when the child exits, but the tool could have
    // leaked its descriptors to a grandchild that keeps them open; bound the
    // wait and abandon the reader instead of hanging.
    let stdout = collect_stream(&stdout_receiver).ok_or_else(|| {
        unavailable(
            mount,
            format!("{tool} exited but its stdout pipe stayed open"),
        )
    })?;
    let stderr = collect_stream(&stderr_receiver).ok_or_else(|| {
        unavailable(
            mount,
            format!("{tool} exited but its stderr pipe stayed open"),
        )
    })?;
    Ok(Execution {
        status,
        stdout,
        stderr,
    })
}

fn spawn_tool(run: &ToolRun<'_>, mount: &MountInfo) -> Result<Child, ProbeError> {
    // Shares the gate the native runner's exec takes, so a fork here cannot
    // land inside another thread's write-then-exec window.
    #[cfg(test)]
    let _shared = crate::fork_gate::forking();
    let parent = rustix::process::getpid();
    let mut command = Command::new(run.binary);
    command
        .args(run.arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: this runs in the child between fork and exec, where only
    // async-signal-safe work is allowed. Both calls are single raw syscalls that
    // allocate nothing and take no lock.
    unsafe {
        command.pre_exec(move || {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
            // The parent may have gone before the signal was armed, and then it
            // would never fire.
            if rustix::process::getppid() != Some(parent) {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|error| spawn_error(run, mount, &error))
}

fn spawn_error(run: &ToolRun<'_>, mount: &MountInfo, error: &std::io::Error) -> ProbeError {
    let binary = run.binary.display();
    let reason = if error.kind() == std::io::ErrorKind::NotFound {
        format!("the {} tool is not present at {binary}", run.tool)
    } else {
        format!("failed to launch {binary}: {error}")
    };
    unavailable(mount, reason)
}

fn spawn_capped_reader(stream: impl Read + Send + 'static) -> mpsc::Receiver<CappedStream> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        // A dropped receiver on the timeout path makes this send fail; the
        // capture is discarded on purpose there.
        let _ = sender.send(read_capped(stream));
    });
    receiver
}

fn read_capped(mut stream: impl Read) -> CappedStream {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let capacity_left = OUTPUT_CAP_BYTES - bytes.len();
                if count > capacity_left {
                    truncated = true;
                }
                bytes.extend_from_slice(&chunk[..count.min(capacity_left)]);
                // Keep draining past the bound so the child never blocks on a
                // full pipe; the excess is discarded and the probe fails
                // closed on `truncated`.
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            // A read error means the capture cannot be trusted to be
            // complete; fail closed the same way as an over-bound stream.
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    CappedStream { bytes, truncated }
}

fn collect_stream(receiver: &mpsc::Receiver<CappedStream>) -> Option<CappedStream> {
    receiver.recv_timeout(OUTPUT_COLLECT_TIMEOUT).ok()
}

fn await_exit(
    child: &mut Child,
    mount: &MountInfo,
    tool: &str,
    timeout: Duration,
) -> Result<ExitStatus, ProbeError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                abandon(child);
                return Err(unavailable(
                    mount,
                    format!("failed to monitor the {tool} process: {error}"),
                ));
            }
        }
        if Instant::now() >= deadline {
            abandon(child);
            return Err(unavailable(mount, format!("{tool} timed out")));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill, then reap within a bounded window. A Lustre client stuck in
/// uninterruptible I/O (D state) can outlive SIGKILL indefinitely; a blocking
/// `wait()` here could hang degu forever, so after the window the child is
/// abandoned unreaped. degu exits shortly afterwards and init adopts and
/// reaps the orphan; a lingering D-state process is the accepted residual.
fn abandon(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + REAP_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

pub(super) fn reason_snippet(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return "no stderr output".to_owned();
    }
    let mut snippet: String = trimmed.chars().take(STDERR_REASON_CHAR_CAP).collect();
    if snippet.len() < trimmed.len() {
        snippet.push_str("...");
    }
    snippet
}

pub(super) fn unavailable(mount: &MountInfo, reason: String) -> ProbeError {
    ProbeError::Unavailable {
        filesystem: mount.filesystem.clone(),
        mount_point: mount.mount_point.display().to_string(),
        reason,
    }
}

/// The mount point is handed to the tool as a positional argument; require an
/// absolute path so a mangled mountinfo entry can never smuggle an
/// option-like or relative argument into the child process.
pub(super) fn require_rooted_mount_point(mount: &MountInfo) -> Result<(), ProbeError> {
    if mount.mount_point.as_os_str().as_bytes().starts_with(b"/") {
        return Ok(());
    }
    Err(super::incomplete(
        mount,
        "mount point is not an absolute path",
    ))
}

/// Requires the kernel's statfs magic to agree with what mountinfo said, before
/// a tool runs against this mount point.
pub(super) fn verify_statfs(mount: &MountInfo, expected: u64) -> Result<(), ProbeError> {
    let stat = rustix::fs::statfs(&mount.mount_point).map_err(|error| {
        super::incomplete(mount, format!("statfs failed for the mount point: {error}"))
    })?;
    let magic = stat.f_type as u64 & LINUX_F_TYPE_MASK;
    if magic != expected {
        return Err(super::incomplete(
            mount,
            format!(
                "mountinfo reports {} but the statfs magic is {magic:#x}",
                mount.filesystem
            ),
        ));
    }
    Ok(())
}

/// Numeric columns are plain unsigned integers, optionally carrying one
/// trailing `*`. With exit status zero as a precondition the marker is a
/// genuine over-limit flag, so it is stripped without further semantics.
/// Everything else -- bracketed `[N]` placeholders, signs, empty tokens --
/// fails closed.
/// A trailing `*` is lfs's over-limit marker on the usage columns only; a
/// starred limit is not lfs grammar and fails closed.
pub(super) fn numeric_usage(token: &str, column: &str) -> Result<u64, String> {
    numeric_plain(token.strip_suffix('*').unwrap_or(token), column)
}

pub(super) fn numeric_plain(token: &str, column: &str) -> Result<u64, String> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{column} column is not an unsigned integer"));
    }
    token
        .parse()
        .map_err(|_| format!("{column} column does not fit in 64 bits"))
}

pub(super) fn kib_to_bytes(value: u64, column: &str) -> Result<u64, String> {
    value
        .checked_mul(KIB)
        .ok_or_else(|| format!("{column} column overflows when converted to bytes"))
}
