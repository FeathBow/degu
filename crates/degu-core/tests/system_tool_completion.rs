//! A bounded invocation whose wrapper exits on its own must still end that
//! wrapper's ordinary descendants, and must still collect its output.

mod system_tool_support;

use system_tool_support::{DESCENDANT_DELAY, run_wrapper};

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
