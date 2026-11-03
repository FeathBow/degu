mod output;

use crate::cli::QuotaArgs;
use crate::commands::guidance::{self, OutputMode, Request, Workflow};
use crate::presentation::escape_terminal_text;
use crate::quota::{ProbeError, QuotaSnapshot};
use crate::runtime::Ui;
use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

/// Four tool runs at their own ten-second limit, and room for the calls around them.
const SURVEY_DEADLINE: Duration = Duration::from_secs(45);
/// Lets a test reach the deadline without waiting for it. Debug builds only.
#[cfg(debug_assertions)]
const DEADLINE_TEST_ENV: &str = "DEGU_QUOTA_TEST_DEADLINE_MS";

type Survey = fn(&Path) -> Result<QuotaSnapshot, ProbeError>;

pub(crate) fn run(args: QuotaArgs, ui: Ui) -> Result<()> {
    let json = args.output.json;
    let target = resolve_target(args.path)?;
    let report = read_report(target, crate::quota::survey, survey_deadline())?;
    output::print(&report, json, ui)?;
    guidance::print(Request {
        output: output_mode(json, ui),
        workflow: Workflow::Quota,
        home: None,
    })?;
    Ok(())
}

/// Reads the report on a thread that can be left behind. Resolving the path and
/// `statfs` both ask the filesystem, and on a hard NFS mount whose server is away
/// they wait for as long as it stays away, before any tool's own time limit starts.
/// Past the deadline this reports the filesystem as unavailable and the process
/// exits, which ends the waiting thread and, through its parent-death signal, any
/// tool that thread had running. A client stuck in a wait that cannot be killed can
/// still hold up that exit, after the message has been printed.
fn read_report(target: PathBuf, survey: Survey, deadline: Duration) -> Result<QuotaSnapshot> {
    let target_text = escape_terminal_text(&target.display().to_string());
    let (sender, receiver) = mpsc::channel();
    let worker_text = target_text.clone();
    std::thread::spawn(move || {
        let read = || -> Result<QuotaSnapshot> {
            let canonical = std::fs::canonicalize(&target)
                .with_context(|| format!("quota target is unavailable: {worker_text}"))?;
            Ok(survey(&canonical)?)
        };
        // A closed channel means the deadline passed and nobody wants the answer.
        let _ = sender.send(read());
    });
    match receiver.recv_timeout(deadline) {
        Ok(report) => report,
        Err(RecvTimeoutError::Timeout) => Err(anyhow!(
            "quota provider unavailable for {target_text}: the filesystem did not answer within {} seconds",
            deadline.as_secs()
        )),
        Err(RecvTimeoutError::Disconnected) => Err(anyhow!(
            "the quota probe for {target_text} stopped without an answer"
        )),
    }
}

fn survey_deadline() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var(DEADLINE_TEST_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return Duration::from_millis(milliseconds);
    }
    SURVEY_DEADLINE
}

fn output_mode(json: bool, ui: Ui) -> OutputMode {
    if json {
        OutputMode::Json
    } else {
        OutputMode::Human(ui)
    }
}

fn resolve_target(path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = path {
        return Ok(path);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set; provide an explicit quota path"))
}

#[cfg(test)]
mod tests {
    use super::{Path, ProbeError, QuotaSnapshot, read_report};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn hangs(_: &Path) -> Result<QuotaSnapshot, ProbeError> {
        // Stands in for a statfs waiting on a server that has gone away.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    fn panics(_: &Path) -> Result<QuotaSnapshot, ProbeError> {
        panic!("the probe died");
    }

    fn unsupported(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
        Err(ProbeError::Unsupported {
            filesystem: "testfs".to_owned(),
            mount_point: path.display().to_string(),
            reason: "for this test",
        })
    }

    #[test]
    fn hung_probe_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let error = read_report(dir.path().to_owned(), hangs, Duration::from_millis(100))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(started.elapsed() < Duration::from_secs(30), "{error}");
        assert!(error.contains("quota provider unavailable"), "{error}");
        assert!(error.contains("did not answer within"), "{error}");
    }

    #[test]
    fn dead_probe_reported() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_report(dir.path().to_owned(), panics, Duration::from_secs(30))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("stopped without an answer"), "{error}");
    }

    #[test]
    fn probe_failure_passes() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_report(dir.path().to_owned(), unsupported, Duration::from_secs(30))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("quota unsupported for testfs"), "{error}");
    }

    #[test]
    fn missing_target_named() {
        let error = read_report(
            PathBuf::from("/degu-missing-quota-target"),
            hangs,
            Duration::from_secs(30),
        )
        .map(|_| ())
        .unwrap_err()
        .to_string();
        assert!(error.contains("quota target is unavailable"), "{error}");
        assert!(error.contains("/degu-missing-quota-target"), "{error}");
    }
}
