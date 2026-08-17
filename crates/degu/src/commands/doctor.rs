use crate::output::stdoutln;
use crate::presentation::escape_terminal_text;
use anyhow::{Result, anyhow};
use degu_core::activation::{
    ActivationAuthorityMode, CurrentEuidAuthorityReadiness, StoreActivationError,
    StoreActivationKind, check_current_euid_authority_readiness,
};
use degu_core::local_backend::{CertificationError, CertifiedLocalBackend};
use serde::Serialize;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 2;
const CHECK_ID: &str = "account_readiness";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadinessStatus {
    Ready,
    Missing,
    SplitAuthority,
    RecoveryRequired,
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
            Self::SplitAuthority => "split_authority",
            Self::RecoveryRequired => "recovery_required",
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
    authority_mode: Option<&'static str>,
    activation_state: Option<&'static str>,
    path: Option<PathBuf>,
    system_path: Option<PathBuf>,
    self_managed_path: Option<PathBuf>,
    backend: Option<&'static str>,
    reason: Option<&'static str>,
    remediation: Option<&'static str>,
    mutated: bool,
}

impl DoctorReport {
    fn from_readiness(readiness: CurrentEuidAuthorityReadiness) -> Self {
        Self::ready(
            readiness.mode(),
            readiness.path(),
            readiness.backend(),
            readiness.activation(),
        )
    }

    fn ready(
        mode: ActivationAuthorityMode,
        path: &Path,
        backend: CertifiedLocalBackend,
        activation: StoreActivationKind,
    ) -> Self {
        let (status, reason, remediation) = match activation {
            StoreActivationKind::Lost | StoreActivationKind::CorruptOrReplaced => (
                ReadinessStatus::RecoveryRequired,
                Some("the selected authority records no longer authenticate their exact store"),
                Some(
                    "stop mutation and investigate the recorded anchor and store; init or administrator setup cannot clear recovery state",
                ),
            ),
            StoreActivationKind::NeverActivated
            | StoreActivationKind::Preparing
            | StoreActivationKind::Activated => (ReadinessStatus::Ready, None, None),
        };
        Self {
            schema_version: SCHEMA_VERSION,
            check: CHECK_ID,
            status,
            authority_mode: Some(mode_name(mode)),
            activation_state: Some(activation_name(activation)),
            path: Some(path.to_path_buf()),
            system_path: None,
            self_managed_path: None,
            backend: Some(backend_name(backend)),
            reason,
            remediation,
            mutated: false,
        }
    }

    fn failed(error: &StoreActivationError) -> Self {
        let (status, path, system_path, self_managed_path, reason, remediation) =
            classify_error(error);
        Self {
            schema_version: SCHEMA_VERSION,
            check: CHECK_ID,
            status,
            authority_mode: None,
            activation_state: None,
            path,
            system_path,
            self_managed_path,
            backend: None,
            reason: Some(reason),
            remediation: Some(remediation),
            mutated: false,
        }
    }
}

pub(crate) fn run(json: bool) -> Result<()> {
    let report = match check_current_euid_authority_readiness() {
        Ok(readiness) => DoctorReport::from_readiness(readiness),
        Err(error) => DoctorReport::failed(&error),
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
        "doctor found account readiness status '{}'",
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
    let mut output = format!(
        "Account readiness\n\nSetup status    {}\nWrites degu state no",
        report.status.as_str()
    );
    if let Some(mode) = report.authority_mode {
        output.push_str(&format!("\nAuthority mode  {mode}"));
    }
    if let Some(state) = report.activation_state {
        output.push_str(&format!("\nActivation      {state}"));
    }
    if let Some(path) = &report.path {
        output.push_str(&format!(
            "\nAuthority path  {}",
            escape_terminal_text(&path.display().to_string())
        ));
    }
    if let Some(path) = &report.system_path {
        output.push_str(&format!(
            "\nSystem path     {}",
            escape_terminal_text(&path.display().to_string())
        ));
    }
    if let Some(path) = &report.self_managed_path {
        output.push_str(&format!(
            "\nSelf path       {}",
            escape_terminal_text(&path.display().to_string())
        ));
    }
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

type FailureClassification = (
    ReadinessStatus,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
    &'static str,
    &'static str,
);

fn classify_error(error: &StoreActivationError) -> FailureClassification {
    match error {
        StoreActivationError::NoAuthority {
            system,
            self_managed,
        } => (
            ReadinessStatus::Missing,
            None,
            Some(system.clone()),
            Some(self_managed.clone()),
            "neither the administrator-hardened nor self-managed authority is provisioned",
            "run 'degu init --initial' only for first use, or ask an administrator to provision the system authority",
        ),
        StoreActivationError::SplitAuthority {
            system,
            self_managed,
        } => (
            ReadinessStatus::SplitAuthority,
            None,
            Some(system.clone()),
            Some(self_managed.clone()),
            "both authority roots carry activation evidence",
            "stop mutation and investigate both recorded stores; never remove, repair, or choose one automatically",
        ),
        StoreActivationError::SelfInitializationRequired
        | StoreActivationError::InitialAssertionRequired => (
            ReadinessStatus::Missing,
            None,
            None,
            None,
            "the self-managed anchor has no durable initial-use declaration",
            "run 'degu init --initial' only if this account has never activated a store; otherwise investigate lost authority",
        ),
        StoreActivationError::AccountBaseChanged { expected, .. } => (
            ReadinessStatus::RecoveryRequired,
            Some(expected.clone()),
            None,
            None,
            "the account-database home changed during self-authority initialization",
            "stop initialization and investigate the account-home change and any committed authority claim; never retry as first use blindly",
        ),
        StoreActivationError::AuthorityClaimInvalid { path } => (
            ReadinessStatus::RecoveryRequired,
            Some(path.clone()),
            None,
            None,
            "the durable authority claim conflicts with the selected anchor or activation records",
            "stop mutation and investigate the authority claim, peer witness, and exact recorded store; never reinitialize",
        ),
        StoreActivationError::SelectedAuthorityLost { selected, witness } => (
            ReadinessStatus::RecoveryRequired,
            Some(selected.clone()),
            None,
            Some(witness.clone()),
            "a surviving peer witness proves that the selected authority is missing",
            "stop mutation and recover the selected authority; init cannot replace a witnessed lost authority",
        ),
        StoreActivationError::SystemAuthorityPresent { path } => (
            ReadinessStatus::Unsafe,
            Some(path.clone()),
            None,
            None,
            "self-managed initialization was requested while a system authority exists",
            "use the existing administrator-hardened authority; do not create a competing self authority",
        ),
        StoreActivationError::AnchorNotProvisioned { path } => (
            ReadinessStatus::Missing,
            Some(path.clone()),
            None,
            None,
            "the selected activation authority is not provisioned",
            "run 'degu init --initial' only if no earlier authority exists; otherwise investigate the missing namespace",
        ),
        StoreActivationError::UnsafeAnchor(_)
        | StoreActivationError::InvalidLocator
        | StoreActivationError::NotResumable => (
            if matches!(error, StoreActivationError::NotResumable) {
                ReadinessStatus::RecoveryRequired
            } else {
                ReadinessStatus::Unsafe
            },
            None,
            None,
            None,
            "an activation authority or recorded store failed deterministic safety validation",
            "do not initialize, replace, repair, or fall back; inspect the authenticated authority and store state",
        ),
        StoreActivationError::Backend(
            CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem,
        ) => (
            ReadinessStatus::Unsupported,
            None,
            None,
            None,
            "an authority role is not on a certified filesystem backend",
            "keep sealed staging dormant; privilege and filesystem magic do not create certification",
        ),
        StoreActivationError::Backend(_)
        | StoreActivationError::Io { .. }
        | StoreActivationError::Identity
        | StoreActivationError::Store(_)
        | StoreActivationError::RecordInspection { .. }
        | StoreActivationError::SyncUncertain(_)
        | StoreActivationError::Random(_)
        | StoreActivationError::AccountBase(_) => (
            ReadinessStatus::Uncertain,
            None,
            None,
            None,
            "the authority selector could not authenticate all candidate state with certainty",
            "retry after resolving account lookup, I/O, lock, ACL, mount, or backend inspection failures; do not initialize or fall back",
        ),
    }
}

fn mode_name(mode: ActivationAuthorityMode) -> &'static str {
    match mode {
        ActivationAuthorityMode::AdministratorHardened => "administrator_hardened",
        ActivationAuthorityMode::SelfManaged => "self_managed",
    }
}

fn activation_name(state: StoreActivationKind) -> &'static str {
    match state {
        StoreActivationKind::NeverActivated => "never_activated",
        StoreActivationKind::Preparing => "preparing",
        StoreActivationKind::Activated => "activated",
        StoreActivationKind::Lost => "lost",
        StoreActivationKind::CorruptOrReplaced => "corrupt_or_replaced",
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
    use std::path::Path;

    fn path() -> PathBuf {
        Path::new("/fixed/system/anchor").to_path_buf()
    }

    #[test]
    fn missing_split_unsupported_and_uncertain_are_non_mutating() {
        let cases = [
            StoreActivationError::NoAuthority {
                system: path(),
                self_managed: PathBuf::from("/fixed/self/anchor"),
            },
            StoreActivationError::SplitAuthority {
                system: path(),
                self_managed: PathBuf::from("/fixed/self/anchor"),
            },
            StoreActivationError::Backend(CertificationError::UnsupportedFilesystem),
            StoreActivationError::Io {
                path: path(),
                source: std::io::Error::from_raw_os_error(libc::EIO),
            },
        ];
        let expected = [
            ReadinessStatus::Missing,
            ReadinessStatus::SplitAuthority,
            ReadinessStatus::Unsupported,
            ReadinessStatus::Uncertain,
        ];
        for (error, expected) in cases.iter().zip(expected) {
            let report = DoctorReport::failed(error);
            assert_eq!(report.status, expected);
            assert!(!report.mutated);
            assert!(report.reason.is_some());
            assert!(report.remediation.is_some());
        }
    }

    #[test]
    fn ready_json_names_the_selected_mode_and_activation_state() {
        let report = DoctorReport::ready(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Activated,
        );
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["check"], CHECK_ID);
        assert_eq!(value["status"], "ready");
        assert_eq!(value["authority_mode"], "self_managed");
        assert_eq!(value["activation_state"], "activated");
        assert_eq!(value["path"], "/fixed/system/anchor");
        assert_eq!(value["backend"], "ext4");
        assert_eq!(value["reason"], serde_json::Value::Null);
        assert_eq!(value["remediation"], serde_json::Value::Null);
        assert_eq!(value["mutated"], false);
    }

    #[test]
    fn lost_or_corrupt_selected_authority_requires_recovery() {
        for state in [
            StoreActivationKind::Lost,
            StoreActivationKind::CorruptOrReplaced,
        ] {
            let report = DoctorReport::ready(
                ActivationAuthorityMode::AdministratorHardened,
                &path(),
                CertifiedLocalBackend::Xfs,
                state,
            );
            assert_eq!(report.status, ReadinessStatus::RecoveryRequired);
            assert!(!report.status.is_ready());
        }
    }

    #[test]
    fn non_ready_broken_pipe_cannot_become_success() {
        let report = DoctorReport::failed(&StoreActivationError::NoAuthority {
            system: path(),
            self_managed: PathBuf::from("/fixed/self/anchor"),
        });
        let error = finish_report(&report, Err(crate::output::stdout_closed_error())).unwrap_err();
        assert!(!crate::output::is_stdout_closed(&error));
        assert!(error.to_string().contains("readiness status 'missing'"));
    }

    #[test]
    fn human_failure_names_both_fixed_candidates_and_the_explicit_init_step() {
        let report = DoctorReport::failed(&StoreActivationError::NoAuthority {
            system: path(),
            self_managed: PathBuf::from("/fixed/self/anchor"),
        });
        let output = render_human(&report);
        assert!(output.contains("Setup status    missing"));
        assert!(output.contains("System path     /fixed/system/anchor"));
        assert!(output.contains("Self path       /fixed/self/anchor"));
        assert!(output.contains("Writes degu state no"));
        assert!(output.contains("run 'degu init --initial'"));
    }
}
