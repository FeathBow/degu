use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Mutex;

// Parallel expect sessions contend for CPU and overrun the 10s budget on
// loaded machines; serialize PTY runs while every other test stays parallel.
static PTY_GATE: Mutex<()> = Mutex::new(());

const EXPECT_TIMEOUT_SECONDS: u8 = 10;
const EXPECT_TIMEOUT_EXIT_CODE: u8 = 124;
const EXPECT_HARNESS_FAILURE_EXIT_CODE: u8 = 125;
const EXPECT_WAIT_FIELD_COUNT: usize = 4;
const EXPECT_WAIT_OS_ERROR_INDEX: usize = 2;
const EXPECT_WAIT_EXIT_STATUS_INDEX: usize = 3;
const EXPECT_NO_OS_ERROR: u8 = 0;

pub(crate) struct PtyRun<'a> {
    pub body: &'a str,
    pub home: &'a Path,
    pub config_home: &'a Path,
    pub state_home: &'a Path,
    pub extra_env: &'a [(&'static str, &'a OsStr)],
}

fn script(body: &str) -> String {
    format!(
        r#"set timeout {EXPECT_TIMEOUT_SECONDS}
expect_before -i any_spawn_id timeout {{
    set timed_out_spawn_id $spawn_id
    puts stderr "PTY integration test timed out waiting for degu"
    catch {{close -i $timed_out_spawn_id}}
    catch {{wait -nowait -i $timed_out_spawn_id}}
    exit {EXPECT_TIMEOUT_EXIT_CODE}
}}
{body}
expect eof
if {{[catch {{wait}} result]}} {{
    puts stderr "PTY integration test could not wait for degu: $result"
    exit {EXPECT_HARNESS_FAILURE_EXIT_CODE}
}}
if {{[llength $result] != {EXPECT_WAIT_FIELD_COUNT} || [lindex $result {EXPECT_WAIT_OS_ERROR_INDEX}] != {EXPECT_NO_OS_ERROR}}} {{
    puts stderr "PTY integration test observed an abnormal degu termination: $result"
    exit {EXPECT_HARNESS_FAILURE_EXIT_CODE}
}}
exit [lindex $result {EXPECT_WAIT_EXIT_STATUS_INDEX}]
"#
    )
}

pub(crate) fn run(request: PtyRun<'_>) -> Output {
    let _serialized = PTY_GATE.lock().expect("PTY test gate poisoned");
    let path = std::env::var_os("PATH").expect("PATH is required for PTY integration tests");
    let mut command = Command::new("expect");
    command
        .arg("-c")
        .arg(script(request.body))
        .env_clear()
        .env("PATH", path)
        .env("DEGU_BIN", env!("CARGO_BIN_EXE_degu"))
        .env("HOME", request.home)
        .env("LOGNAME", request.home)
        .env("XDG_CONFIG_HOME", request.config_home)
        .env("XDG_STATE_HOME", request.state_home);
    for &(name, value) in request.extra_env {
        command.env(name, value);
    }
    match command.output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "`expect` is required for PTY integration tests; install it and ensure it is on PATH"
            )
        }
        Err(error) => panic!("failed to run `expect`: {error}"),
    }
}
