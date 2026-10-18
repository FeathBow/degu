//! The wrapper shape both bounded-invocation tests build.
//!
//! The two tests that use this live in separate test binaries on purpose. A
//! pipe's CLOEXEC is not set by the syscall that creates it on a platform
//! without `pipe2`, so a spawn on one thread can inherit a write end another
//! thread created microseconds earlier and keep it past its own exec. In one
//! process that makes each of these tests the other's noise, and the one
//! waiting for EOF reads a held write end as output it cannot collect. In two
//! processes it cannot happen: fork copies only the descriptor table of the
//! process that calls it.

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use degu_core::system_tool::{Invocation, ToolError};

const TOOL_TIMEOUT: Duration = Duration::from_millis(500);
/// Longer than the descendant's own sleep, so a descendant that outlived the
/// wrapper has had time to write before the assertion looks.
pub const DESCENDANT_DELAY: Duration = Duration::from_millis(2500);
const OUTPUT_CAP: usize = 4096;

/// A wrapper that starts an ordinary descendant, waits until it is running, and
/// then ends the way `ending` says.
pub fn run_wrapper(
    directory: &Path,
    ending: &str,
) -> Result<degu_core::system_tool::CapturedRun, ToolError> {
    let program = format!(
        r#"/bin/sh -c 'printf ready > "$1/ready"; /bin/sleep 2; printf survived > "$1/survived"' child "$1" &
while [ ! -f "$1/ready" ]; do /bin/sleep 0.01; done
{ending}"#
    );
    Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[
            OsStr::new("-c"),
            OsStr::new(&program),
            OsStr::new("advisor"),
            directory.as_os_str(),
        ],
        timeout: TOOL_TIMEOUT,
        stdout_cap: OUTPUT_CAP,
    }
    .run(Some(b"{}"))
}
