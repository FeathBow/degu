use anyhow::Result;
use std::fmt;
use std::io::{self, Write};

pub(crate) fn write_stdout(output: Vec<u8>) -> Result<()> {
    map_stdout_result(io::stdout().lock().write_all(&output))
}

pub(crate) fn write_stdout_line(arguments: fmt::Arguments<'_>) -> Result<()> {
    map_stdout_result(writeln!(io::stdout().lock(), "{arguments}"))
}

pub(crate) fn is_stdout_closed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<StdoutClosed>())
}

pub(crate) fn stdout_closed_error() -> anyhow::Error {
    StdoutClosed.into()
}

/// Whether stdout's consumer has hung up its end. `poll` reports the pipe/socket
/// state directly, so unlike a write that a full kernel send buffer can accept
/// before surfacing EPIPE (racy under load), this deterministically detects a
/// closed consumer -- letting a caller stop before an irreversible mutation.
#[cfg(unix)]
pub(crate) fn stdout_consumer_gone() -> bool {
    let mut poll_fd = libc::pollfd {
        fd: libc::STDOUT_FILENO,
        events: libc::POLLOUT,
        revents: 0,
    };
    // Zero timeout: read the current readiness and return at once.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    ready > 0 && poll_fd.revents & (libc::POLLHUP | libc::POLLERR) != 0
}

#[cfg(not(unix))]
pub(crate) fn stdout_consumer_gone() -> bool {
    false
}

fn map_stdout_result(result: io::Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Err(StdoutClosed.into()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug)]
struct StdoutClosed;

impl fmt::Display for StdoutClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stdout consumer closed the pipe")
    }
}

impl std::error::Error for StdoutClosed {}

macro_rules! stdoutln {
    ($($argument:tt)*) => {
        crate::output::write_stdout_line(format_args!($($argument)*))
    };
}

pub(crate) use stdoutln;
