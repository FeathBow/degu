//! A bounded invocation that runs out of time must end its wrapper's ordinary
//! descendants too.

mod system_tool_support;

use degu_core::system_tool::ToolError;
use system_tool_support::{DESCENDANT_DELAY, run_wrapper};

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
