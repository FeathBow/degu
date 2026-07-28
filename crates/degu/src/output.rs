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
