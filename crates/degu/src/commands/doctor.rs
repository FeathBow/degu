use crate::output::stdoutln;
use crate::presentation::escape_terminal_text;
use anyhow::{Result, anyhow};
use degu_core::local_backend::CertifiedLocalBackend;
use degu_core::store_activation::{
    ActivationAnchorLocator, ActivationAnchorReadinessError, check_activation_anchor_readiness,
};
use serde::Serialize;
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;
const CHECK_ID: &str = "sealed_staging_anchor";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadinessStatus {
    Ready,
    Missing,
    Unsafe,
    Unsupported,
    Uncertain,
}

impl ReadinessStatus {
    fn is_ready(self) -> bool {
        self == Self::Ready
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Missing => "missing",
            Self::Unsafe => "unsafe",
            Self::Unsupported => "unsupported",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    check: &'static str,
    status: ReadinessStatus,
    path: PathBuf,
    backend: Option<&'static str>,
    reason: Option<&'static str>,
    remediation: Option<&'static str>,
    mutated: bool,
}

impl DoctorReport {
    fn ready(path: PathBuf, backend: CertifiedLocalBackend) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            check: CHECK_ID,
            status: ReadinessStatus::Ready,
            path,
            backend: Some(backend_name(backend)),
            reason: None,
            remediation: None,
            mutated: false,
        }
    }

    fn failed(path: PathBuf, error: &ActivationAnchorReadinessError) -> Self {
        let (status, reason, remediation) = classify_error(error);
        Self {
            schema_version: SCHEMA_VERSION,
            check: CHECK_ID,
            status,
            path,
            backend: None,
            reason: Some(reason),
            remediation: Some(remediation),
            mutated: false,
        }
    }
}

pub(crate) fn run(json: bool) -> Result<()> {
    let locator = ActivationAnchorLocator::for_current_euid()
        .map_err(|error| anyhow!("cannot derive this account's activation anchor: {error}"))?;
    let path = locator.as_path().to_path_buf();
    let report = match check_activation_anchor_readiness(&locator) {
        Ok(readiness) => DoctorReport::ready(path, readiness.backend()),
        Err(error) => DoctorReport::failed(path, &error),
    };
    finish_report(&report, print_report(&report, json))
}

fn finish_report(report: &DoctorReport, print_result: Result<()>) -> Result<()> {
    if report.status.is_ready() {
        return print_result;
    }
    // The process-wide broken-pipe convention treats closed stdout as success.
    // That is valid for a ready report, but must not turn a failed readiness
    // check into exit 0. Other output failures remain the primary error.
    if let Err(error) = print_result
        && !crate::output::is_stdout_closed(&error)
    {
        return Err(error);
    }
    Err(anyhow!(
        "doctor found sealed-staging readiness status '{}'",
        report.status.as_str()
    ))
}

fn print_report(report: &DoctorReport, json: bool) -> Result<()> {
    if json {
        stdoutln!("{}", serde_json::to_string_pretty(report)?)
    } else {
        stdoutln!("{}", render_human(report))
    }
}

fn render_human(report: &DoctorReport) -> String {
    let path = escape_terminal_text(&report.path.display().to_string());
    let mut output = format!(
        "Account readiness\n\nSealed staging  {}\nSystem anchor   {path}\nWrites degu state no",
        report.status.as_str()
    );
    if let Some(backend) = report.backend {
        output.push_str(&format!("\nBackend         {backend}"));
    }
    if let Some(reason) = report.reason {
        output.push_str(&format!(
            "\nReason          {}",
            escape_terminal_text(reason)
        ));
    }
    if let Some(remediation) = report.remediation {
        output.push_str(&format!(
            "\n\nNext step\n  {}",
            escape_terminal_text(remediation)
        ));
    }
    output
}

fn classify_error(
    error: &ActivationAnchorReadinessError,
) -> (ReadinessStatus, &'static str, &'static str) {
    match error {
        ActivationAnchorReadinessError::Missing { .. } => (
            ReadinessStatus::Missing,
            "the fixed current-user system anchor is not provisioned",
            "ask an administrator to provision the exact path above; degu will not create it",
        ),
        ActivationAnchorReadinessError::Unsupported { .. } => (
            ReadinessStatus::Unsupported,
            "the system anchor namespace is not on a certified ext4, XFS, or APFS backend",
            "keep sealed staging disabled; do not move authority to HOME, XDG, configuration, or a network filesystem",
        ),
        ActivationAnchorReadinessError::Uncertain { .. } => (
            ReadinessStatus::Uncertain,
            "the system anchor namespace could not be authenticated with certainty",
            "retry after resolving I/O, lock, ACL, mount, or backend inspection failures; do not recreate the anchor",
        ),
        ActivationAnchorReadinessError::Unsafe { .. } => (
            ReadinessStatus::Unsafe,
            "the existing system anchor or its namespace failed safety validation",
            "ask an administrator to inspect ownership, exact mode 0700, ACLs, type, and parent namespace; do not replace or repair it automatically",
        ),
    }
}

fn backend_name(backend: CertifiedLocalBackend) -> &'static str {
    match backend {
        CertifiedLocalBackend::Ext4 => "ext4",
        CertifiedLocalBackend::Xfs => "xfs",
        CertifiedLocalBackend::Apfs => "apfs",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use degu_core::local_backend::CertificationError;
    use degu_core::store_activation::StoreActivationError;
    use std::io;
    use std::path::Path;

    fn path() -> PathBuf {
        Path::new("/fixed/system/anchor").to_path_buf()
    }

    fn uncertain_source() -> StoreActivationError {
        StoreActivationError::Io {
            path: path(),
            source: io::Error::from_raw_os_error(libc::EIO),
        }
    }

    #[test]
    fn every_failure_class_is_stable_and_non_mutating() {
        let cases = [
            (
                ActivationAnchorReadinessError::Missing { path: path() },
                ReadinessStatus::Missing,
            ),
            (
                ActivationAnchorReadinessError::Unsafe {
                    path: path(),
                    source: StoreActivationError::InvalidLocator,
                },
                ReadinessStatus::Unsafe,
            ),
            (
                ActivationAnchorReadinessError::Unsupported {
                    path: path(),
                    source: StoreActivationError::Backend(
                        CertificationError::UnsupportedFilesystem,
                    ),
                },
                ReadinessStatus::Unsupported,
            ),
            (
                ActivationAnchorReadinessError::Uncertain {
                    path: path(),
                    source: uncertain_source(),
                },
                ReadinessStatus::Uncertain,
            ),
        ];
        for (error, expected) in cases {
            let report = DoctorReport::failed(path(), &error);
            assert_eq!(report.status, expected);
            assert!(!report.mutated);
            assert!(report.reason.is_some());
            assert!(report.remediation.is_some());
        }
    }

    #[test]
    fn ready_json_contract_is_explicit() {
        let report = DoctorReport::ready(path(), CertifiedLocalBackend::Ext4);
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["check"], CHECK_ID);
        assert_eq!(value["status"], "ready");
        assert_eq!(value["path"], "/fixed/system/anchor");
        assert_eq!(value["backend"], "ext4");
        assert_eq!(value["reason"], serde_json::Value::Null);
        assert_eq!(value["remediation"], serde_json::Value::Null);
        assert_eq!(value["mutated"], false);
    }

    #[test]
    fn non_ready_broken_pipe_cannot_become_success() {
        let readiness = ActivationAnchorReadinessError::Missing { path: path() };
        let report = DoctorReport::failed(path(), &readiness);
        let error = finish_report(&report, Err(crate::output::stdout_closed_error())).unwrap_err();
        assert!(!crate::output::is_stdout_closed(&error));
        assert!(error.to_string().contains("readiness status 'missing'"));
    }

    #[test]
    fn human_failure_names_one_short_command_concept() {
        let readiness = ActivationAnchorReadinessError::Missing { path: path() };
        let report = DoctorReport::failed(path(), &readiness);
        let output = render_human(&report);
        assert!(output.contains("Sealed staging  missing"));
        assert!(output.contains("Writes degu state no"));
        assert!(output.contains("Next step"));
        assert!(!output.contains("activation-anchor"));
    }
}
