//! A bounded invocation must include ordinary descendants of its wrapper.

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use degu_core::system_tool::{Invocation, ToolError};

const TOOL_TIMEOUT: Duration = Duration::from_millis(500);
const DESCENDANT_DELAY: Duration = Duration::from_millis(2500);
const OUTPUT_CAP: usize = 4096;

fn run_wrapper(
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

#[test]
fn timeout_stops_the_wrappers_descendant_before_it_can_write() {
    let directory = tempfile::tempdir().unwrap();
    let result = run_wrapper(directory.path(), "wait");
    assert!(
        directory.path().join("ready").exists(),
        "descendant never started"
    );
    assert!(
        matches!(result, Err(ToolError::Timeout { .. })),
        "{result:?}"
    );
    std::thread::sleep(DESCENDANT_DELAY);
    assert!(
        !directory.path().join("survived").exists(),
        "descendant survived the timeout"
    );
}

#[test]
fn a_completed_wrapper_does_not_leave_its_descendant_running() {
    let directory = tempfile::tempdir().unwrap();
    let result = run_wrapper(directory.path(), "printf answer; exit 0");
    assert!(
        directory.path().join("ready").exists(),
        "descendant never started"
    );
    std::thread::sleep(DESCENDANT_DELAY);
    assert!(
        !directory.path().join("survived").exists(),
        "descendant survived the wrapper"
    );
    let run = result.expect("wrapper output is collected after descendants are stopped");
    assert!(run.success);
    assert_eq!(run.stdout, b"answer");
}
