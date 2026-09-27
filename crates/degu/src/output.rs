use anyhow::Result;
use std::fmt;
use std::io::{self, Write};

pub(crate) fn write_stdout(output: Vec<u8>) -> Result<()> {
    map_stdout_result(io::stdout().lock().write_all(&output))
}

pub(crate) fn write_stdout_line(arguments: fmt::Arguments<'_>) -> Result<()> {
    map_stdout_result(writeln!(io::stdout().lock(), "{arguments}"))
}

pub(crate) fn flush_stdout() -> Result<()> {
    map_stdout_result(io::stdout().lock().flush())
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
    consumer_gone(libc::STDOUT_FILENO)
}

/// Whether the consumer on one descriptor has hung up.
///
/// Taking the descriptor rather than reading `STDOUT_FILENO` directly is what lets
/// this be tested: a test can hand it a socket whose peer closed, a pipe whose
/// reader closed, a descriptor that is not open, and a healthy one, without
/// disturbing the descriptor the test harness is writing its own output to.
#[cfg(unix)]
fn consumer_gone(fd: libc::c_int) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // Zero timeout: read the current readiness and return at once.
    // SAFETY: one initialized pollfd naming a descriptor this process owns.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if ready <= 0 {
        return false;
    }
    if poll_fd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
        return true;
    }
    // `POLLNVAL` answers two questions at once: a descriptor that is not open,
    // which is a consumer that is gone, and a descriptor `poll` will not report on,
    // which is what macOS returns for an ordinary `/dev/null`. Only the first is a
    // hangup, so the descriptor is asked directly rather than inferred. The standard
    // descriptors cannot reach the first case — the runtime substitutes `/dev/null`
    // for any that is closed before `main` — so that arm is completeness for a
    // descriptor closed later, and the reachable case is the second.
    if poll_fd.revents & libc::POLLNVAL != 0 {
        // SAFETY: querying flags on a numeric descriptor mutates nothing.
        return unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1;
    }
    // A guard that waves a mutation through leaves no trace of why, which is what
    // made one CI failure unexplainable.
    tracing::debug!(
        target: "degu",
        revents = poll_fd.revents,
        "stdout consumer polled live before a mutation boundary"
    );
    false
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

#[cfg(all(test, unix))]
mod tests {
    use super::consumer_gone;
    use std::os::fd::AsRawFd;

    #[test]
    fn a_hung_up_consumer_is_recognized_on_every_shape_stdout_takes() {
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(reader);
        assert!(
            consumer_gone(writer.as_raw_fd()),
            "a socket whose peer closed is a consumer that hung up"
        );

        let mut ends = [0; 2];
        // SAFETY: libc::pipe fills two descriptors this test then owns.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: closing the read end leaves the write end this test polls.
        unsafe { libc::close(ends[0]) };
        assert!(
            consumer_gone(ends[1]),
            "a pipe whose reader closed is a consumer that hung up"
        );
        // SAFETY: the write end is still owned here and closed exactly once.
        unsafe { libc::close(ends[1]) };

        // SAFETY: a duplicate of this process's own stderr, closed exactly once,
        // leaving a descriptor number that is no longer open.
        let vacant = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(vacant >= 0);
        // SAFETY: the duplicate is owned here.
        unsafe { libc::close(vacant) };
        assert!(
            consumer_gone(vacant),
            "a descriptor that is not open cannot have a consumer"
        );

        // `/dev/null` is the case the descriptor has to be asked about rather than
        // inferred: macOS reports it as `POLLNVAL` even though it is open and
        // writable, and refusing there would refuse an ordinary redirect.
        let sink = std::fs::File::create("/dev/null").unwrap();
        assert!(
            !consumer_gone(sink.as_raw_fd()),
            "a writable sink is not a hangup"
        );
    }
}
