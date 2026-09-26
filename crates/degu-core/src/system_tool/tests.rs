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
    let run = Invocation {
        binary: cat,
        arguments: &[],
        timeout: Duration::from_secs(5),
        stdout_cap: 4096,
    }
    .run(Some(b"degu advisory payload"))
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
    let run = Invocation {
        binary: echo,
        arguments: &[os("answered anyway")],
        timeout: Duration::from_secs(5),
        stdout_cap: 4096,
    }
    .run(Some(&vec![b'x'; 256 * 1024]))
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
    let error = Invocation {
        binary: sleep,
        arguments: &[os("30")],
        timeout: Duration::from_millis(500),
        stdout_cap: 4096,
    }
    // Comfortably past any pipe buffer, so the write cannot complete before
    // the tool would have to read it.
    .run(Some(&vec![b'x'; 4 * 1024 * 1024]))
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
    let error = Invocation {
        binary: Path::new("/nonexistent/degu-system-tool-probe"),
        arguments: &[],
        timeout: Duration::from_secs(5),
        stdout_cap: 1024,
    }
    .run(None)
    .expect_err("a missing binary cannot run");
    assert!(matches!(error, ToolError::NotInstalled(_)), "{error:?}");
}

#[test]
fn stdout_is_captured_and_status_reported() {
    let run = Invocation {
        binary: Path::new("/bin/echo"),
        arguments: &[os("degu")],
        timeout: Duration::from_secs(5),
        stdout_cap: 1024,
    }
    .run(None)
    .expect("echo runs");
    assert!(run.success);
    assert_eq!(run.stdout, b"degu\n");
}

#[test]
fn a_failing_tool_is_a_successful_invocation() {
    let run = Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[os("-c"), os("exit 2")],
        timeout: Duration::from_secs(5),
        stdout_cap: 1024,
    }
    .run(None)
    .expect("sh runs");
    assert!(!run.success);
    assert!(run.stdout.is_empty());
}

#[test]
fn output_beyond_the_bound_is_refused() {
    let error = Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[os("-c"), os("printf '%0.sx' $(seq 1 4096)")],
        timeout: Duration::from_secs(10),
        stdout_cap: 64,
    }
    .run(None)
    .expect_err("output past the bound is not an answer");
    assert!(matches!(error, ToolError::OutputOverflow(_)), "{error:?}");
}

#[test]
fn a_flood_past_the_pipe_buffer_is_refused_without_waiting_for_the_bound() {
    let started = Instant::now();
    let error = Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[os("-c"), os("head -c 1000000 /dev/zero | tr '\\0' 'x'")],
        timeout: Duration::from_secs(30),
        stdout_cap: 1024,
    }
    .run(None)
    .expect_err("output past the bound is not an answer");
    assert!(matches!(error, ToolError::OutputOverflow(_)), "{error:?}");
    // A reader that stopped at the bound would leave the child blocked on
    // its next write, and this would take the full 30 seconds.
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_tool_that_outlives_its_bound_is_killed() {
    let started = Instant::now();
    let error = Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[os("-c"), os("sleep 30")],
        timeout: Duration::from_millis(200),
        stdout_cap: 1024,
    }
    .run(None)
    .expect_err("a tool past its bound is not an answer");
    assert!(matches!(error, ToolError::Timeout { .. }), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_child_environment_is_emptied_apart_from_the_pinned_locale() {
    // SAFETY: single-threaded test setup, before any child is spawned.
    unsafe { std::env::set_var("DEGU_SYSTEM_TOOL_LEAK_PROBE", "leaked") };
    let run = Invocation {
        binary: Path::new("/bin/sh"),
        arguments: &[os("-c"), os("env")],
        timeout: Duration::from_secs(5),
        stdout_cap: 64 * 1024,
    }
    .run(None)
    .expect("sh runs");
    // SAFETY: single-threaded test teardown.
    unsafe { std::env::remove_var("DEGU_SYSTEM_TOOL_LEAK_PROBE") };
    let environment = String::from_utf8(run.stdout).expect("env prints UTF-8 here");
    assert!(!environment.contains("DEGU_SYSTEM_TOOL_LEAK_PROBE"));
    assert!(environment.contains("LC_ALL=C"));
}
