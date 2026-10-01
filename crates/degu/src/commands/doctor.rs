use crate::output::stdoutln;
use crate::presentation::escape_terminal_text;
use anyhow::{Result, anyhow};
use degu_core::activation::{
    ActivationAuthorityMode, CurrentEuidAuthorityReadiness, StoreActivationError,
    StoreActivationKind, check_current_euid_authority_readiness,
};
use degu_core::backend::{CertificationError, CertifiedLocalBackend};
use degu_core::provision::AccountBaseError;
use degu_core::seal::store::StoreError;
use serde::Serialize;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 3;
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
    witness_path: Option<PathBuf>,
    system_path: Option<PathBuf>,
    self_managed_path: Option<PathBuf>,
    /// The store this authority authenticated, and the state directory it belongs to.
    ///
    /// A trash listing that cannot see the account's store sends the reader here for
    /// exactly this. Without it the instruction cannot be followed except by reading
    /// activation records by hand. Both are absent when no store is activated.
    store_path: Option<PathBuf>,
    store_state_home: Option<PathBuf>,
    /// The state directory this run reads, when it is not the store's own. Absent when
    /// they are the same place, which is the ordinary case and needs no explaining.
    other_state_home: Option<PathBuf>,
    backend: Option<&'static str>,
    reason: Option<&'static str>,
    remediation: Option<&'static str>,
    mutated: bool,
}

impl DoctorReport {
    fn from_readiness(readiness: CurrentEuidAuthorityReadiness) -> Self {
        Self::from_selected_authority(
            readiness.mode(),
            readiness.path(),
            readiness.backend(),
            readiness.activation(),
            readiness.store(),
        )
    }

    /// `store` is the location the authority authenticated. `readiness_from` reads it
    /// and the activation kind from one selector state, and only `Activated` carries a
    /// store, so the two agree by construction and the assertion below says so.
    ///
    /// A parameter rather than something attached afterwards: a step that can be skipped
    /// is a step that gets skipped, and this is the one fact a reader sent here by a
    /// trash listing came for.
    fn from_selected_authority(
        mode: ActivationAuthorityMode,
        path: &Path,
        backend: CertifiedLocalBackend,
        activation: StoreActivationKind,
        store: Option<&Path>,
    ) -> Self {
        debug_assert_eq!(
            matches!(activation, StoreActivationKind::Activated),
            store.is_some(),
            "activation state and recorded store disagree"
        );
        let store_state_home = store.and_then(crate::lifecycle::state_home_of);
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
            witness_path: None,
            system_path: None,
            self_managed_path: None,
            store_path: store.map(Path::to_path_buf),
            store_state_home: store_state_home.map(Path::to_path_buf),
            other_state_home: other_state_home(store_state_home),
            backend: Some(backend_name(backend)),
            reason,
            remediation,
            mutated: false,
        }
    }

    fn failed(error: &StoreActivationError) -> Self {
        let classification = classify_error(error);
        Self {
            schema_version: SCHEMA_VERSION,
            check: CHECK_ID,
            status: classification.status,
            authority_mode: None,
            activation_state: None,
            path: classification.path,
            witness_path: classification.witness_path,
            system_path: classification.system_path,
            self_managed_path: classification.self_managed_path,
            store_path: None,
            store_state_home: None,
            other_state_home: None,
            backend: None,
            reason: Some(classification.reason),
            remediation: Some(classification.remediation),
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
    if let Some(path) = &report.witness_path {
        output.push_str(&format!(
            "\nWitness path    {}",
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
    if let Some(path) = &report.store_path {
        output.push_str(&format!(
            "\nStore path      {}",
            escape_terminal_text(&path.display().to_string())
        ));
    }
    if let Some(path) = &report.store_state_home {
        output.push_str(&format!(
            "\nStore state     {}",
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
    // `Store state` alone reads as where the store is, not as somewhere other than
    // here, and a listing that could not see the store is what sends a reader here.
    if let Some(current) = &report.other_state_home {
        output.push_str(&format!(
            "\n\nThis run reads a different state directory\n  {}\n  Trash listings here cover only what it holds; read the store's own state directory to reach the entries it staged.",
            escape_terminal_text(&current.display().to_string())
        ));
    }
    output
}

/// The state directory this run reads, when the store belongs to another one.
///
/// Asked for reporting only. The verdict is about the authority, which no environment
/// variable selects, so this must not reach it.
fn other_state_home(store_state_home: Option<&Path>) -> Option<PathBuf> {
    let store_state_home = store_state_home?;
    let current = degu_core::ecosystem::DetectCtx::from_process()
        .ok()
        .map(|ctx| ctx.xdg_state())?;
    (!crate::lifecycle::same_directory(store_state_home, &current)).then_some(current)
}

struct FailureClassification {
    status: ReadinessStatus,
    path: Option<PathBuf>,
    witness_path: Option<PathBuf>,
    system_path: Option<PathBuf>,
    self_managed_path: Option<PathBuf>,
    reason: &'static str,
    remediation: &'static str,
}

impl FailureClassification {
    fn new(status: ReadinessStatus, reason: &'static str, remediation: &'static str) -> Self {
        Self {
            status,
            path: None,
            witness_path: None,
            system_path: None,
            self_managed_path: None,
            reason,
            remediation,
        }
    }
}

/// What `doctor` would tell someone to do about this activation failure.
///
/// Every command that cannot activate hits the same wall, and the person who
/// hits it is the one who did not run `doctor` first. Reading the remedy from
/// the same classification keeps one answer rather than two that drift.
pub(crate) fn activation_remedy(error: &StoreActivationError) -> &'static str {
    classify_error(error).remediation
}

/// Nothing was decided, so nothing may be changed. The variants that reach here
/// differ in what went unread, not in what the operator should do about it; the
/// ones that name a path attach it so the six causes listed here can be narrowed
/// to one location.
fn uncertain_selection() -> FailureClassification {
    FailureClassification::new(
        ReadinessStatus::Uncertain,
        "the authority selector could not authenticate all candidate state with certainty",
        "retry after resolving account lookup, I/O, lock, ACL, mount, or backend inspection failures; do not initialize or fall back",
    )
}

fn classify_error(error: &StoreActivationError) -> FailureClassification {
    match error {
        StoreActivationError::NoAuthority {
            system,
            self_managed,
        } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::Missing,
                "neither the administrator-hardened nor self-managed authority is provisioned",
                "run 'degu init', which refuses if this account has already activated a store, or ask an administrator to provision the system authority",
            );
            failure.system_path = Some(system.clone());
            failure.self_managed_path = Some(self_managed.clone());
            failure
        }
        StoreActivationError::SplitAuthority {
            system,
            self_managed,
        } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::SplitAuthority,
                "both authority roots carry activation evidence",
                "stop mutation and investigate both recorded stores; never remove, repair, or choose one automatically",
            );
            failure.system_path = Some(system.clone());
            failure.self_managed_path = Some(self_managed.clone());
            failure
        }
        StoreActivationError::SelfInitializationRequired => FailureClassification::new(
            ReadinessStatus::Missing,
            "the self-managed anchor has no durable initial-use declaration",
            "run 'degu init'; it refuses if this account has already activated a store, which would mean the authority was lost rather than never made",
        ),
        StoreActivationError::AccountBaseChanged { expected, .. } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::RecoveryRequired,
                "the account-database home changed during self-authority initialization",
                "stop initialization and investigate the account-home change and any committed authority claim; never retry as first use blindly",
            );
            failure.path = Some(expected.clone());
            failure
        }
        StoreActivationError::AuthorityClaimInvalid { path } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::RecoveryRequired,
                "the durable authority claim conflicts with the selected anchor or activation records",
                "stop mutation and investigate the authority claim, peer witness, and exact recorded store; never reinitialize",
            );
            failure.path = Some(path.clone());
            failure
        }
        StoreActivationError::SelectedAuthorityLost { selected, witness } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::RecoveryRequired,
                "a surviving peer witness proves that the selected authority is missing",
                "stop mutation and recover the selected authority; init cannot replace a witnessed lost authority",
            );
            failure.path = Some(selected.clone());
            failure.witness_path = Some(witness.clone());
            failure
        }
        StoreActivationError::SystemAuthorityPresent { path } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::Unsafe,
                "self-managed initialization was requested while a system authority exists",
                "use the existing administrator-hardened authority; do not create a competing self authority",
            );
            failure.path = Some(path.clone());
            failure
        }
        StoreActivationError::AnchorNotProvisioned { path } => {
            let mut failure = FailureClassification::new(
                ReadinessStatus::Missing,
                "the selected activation authority is not provisioned",
                "run 'degu init'; it refuses if an earlier store was activated, which would mean the namespace is missing rather than absent",
            );
            failure.path = Some(path.clone());
            failure
        }
        StoreActivationError::NotResumable => FailureClassification::new(
            ReadinessStatus::RecoveryRequired,
            "an activation authority or recorded store failed deterministic safety validation",
            "do not initialize, replace, repair, or fall back; inspect the authenticated authority and store state",
        ),
        StoreActivationError::UnsafeAnchor(error) => match unsafe_anchor_status(error) {
            ReadinessStatus::Unsupported => FailureClassification::new(
                ReadinessStatus::Unsupported,
                "the activation authority ancestry is not on a certified backend",
                "keep sealed staging dormant; privilege and filesystem magic do not create certification",
            ),
            ReadinessStatus::Uncertain => FailureClassification::new(
                ReadinessStatus::Uncertain,
                "the activation authority ancestry could not be inspected with certainty",
                "retry after resolving I/O, lock, ACL, mount, or backend inspection failures; do not initialize or fall back",
            ),
            ReadinessStatus::Unsafe => FailureClassification::new(
                ReadinessStatus::Unsafe,
                "an activation authority or recorded store failed deterministic safety validation",
                "do not initialize, replace, repair, or fall back; inspect the authenticated authority and store state",
            ),
            status => unreachable!("unsafe anchor cannot classify as {status:?}"),
        },
        StoreActivationError::InvalidLocator => FailureClassification::new(
            ReadinessStatus::Unsafe,
            "an activation authority or recorded store failed deterministic safety validation",
            "do not initialize, replace, repair, or fall back; inspect the authenticated authority and store state",
        ),
        StoreActivationError::Backend(reason) => match certification_status(reason) {
            ReadinessStatus::Unsupported => FailureClassification::new(
                ReadinessStatus::Unsupported,
                "an authority role is not on a certified filesystem backend",
                "keep sealed staging dormant; privilege and filesystem magic do not create certification",
            ),
            ReadinessStatus::Unsafe => FailureClassification::new(
                ReadinessStatus::Unsafe,
                "an authority role failed deterministic type, ACL, or filesystem identity validation",
                "do not initialize, replace, repair, or fall back; inspect the authenticated authority namespace",
            ),
            ReadinessStatus::Uncertain => uncertain_selection(),
            status => unreachable!("backend cannot classify as {status:?}"),
        },
        // An account fact that no source can supply is settled, not uncertain:
        // the anchor has no home to be derived from and retrying cannot change
        // that. Only a lookup that failed with an errno may succeed later.
        StoreActivationError::AccountBase(AccountBaseError::AccountMissing) => {
            FailureClassification::new(
                ReadinessStatus::Unsupported,
                "no account source this build can consult has an entry for the effective UID",
                "run degu under an account the host resolves, and confirm it with 'getent passwd'; do not initialize or fall back",
            )
        }
        // The resolver failing to answer is transient; the account being
        // absent from every source is not. They must not read alike.
        StoreActivationError::AccountBase(AccountBaseError::ResolverUnavailable) => {
            FailureClassification::new(
                ReadinessStatus::Uncertain,
                "the host's account resolver exists but could not be consulted",
                "retry once the directory service answers; do not initialize or fall back",
            )
        }
        StoreActivationError::AccountBase(AccountBaseError::HomeNotAbsolute) => {
            FailureClassification::new(
                ReadinessStatus::Unsupported,
                "the account entry for the effective UID names an empty or relative home",
                "correct the account entry's home directory; degu will not resolve it against the working directory",
            )
        }
        StoreActivationError::Io { path, .. }
        | StoreActivationError::RecordInspection { path, .. } => {
            let mut failure = uncertain_selection();
            failure.path = Some(path.clone());
            failure
        }
        StoreActivationError::Identity
        | StoreActivationError::Store(_)
        | StoreActivationError::SyncUncertain(_)
        | StoreActivationError::Random(_)
        | StoreActivationError::AccountBase(AccountBaseError::Lookup(_)) => uncertain_selection(),
    }
}

fn unsafe_anchor_status(error: &StoreError) -> ReadinessStatus {
    match error {
        StoreError::ParentBackend { reason, .. } | StoreError::BackendInspection { reason, .. } => {
            certification_status(reason)
        }
        StoreError::Io { .. } | StoreError::Lease(_) => ReadinessStatus::Uncertain,
        StoreError::InvalidPath(_)
        | StoreError::UnsafeDirectory { .. }
        | StoreError::UnsafeWal { .. }
        | StoreError::MissingStore { .. }
        | StoreError::MissingWal { .. } => ReadinessStatus::Unsafe,
    }
}

fn certification_status(reason: &CertificationError) -> ReadinessStatus {
    match reason {
        CertificationError::UnsupportedPlatform | CertificationError::UnsupportedFilesystem => {
            ReadinessStatus::Unsupported
        }
        CertificationError::FilesystemMagicMismatch
        | CertificationError::NotDirectory
        | CertificationError::AclPresent => ReadinessStatus::Unsafe,
        CertificationError::MountIdentityUnavailable
        | CertificationError::MountInfoUnreadable
        | CertificationError::MountInfoMalformed
        | CertificationError::MountInfoMissing
        | CertificationError::MountInfoAmbiguous
        | CertificationError::InspectionFailed
        | CertificationError::AclProbeUnknown
        | CertificationError::ProcessCredentialsUnavailable => ReadinessStatus::Uncertain,
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

    fn assert_exact_json_keys(value: &serde_json::Value) {
        let mut keys = value
            .as_object()
            .expect("doctor report must be an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "activation_state",
                "authority_mode",
                "backend",
                "check",
                "mutated",
                "other_state_home",
                "path",
                "reason",
                "remediation",
                "schema_version",
                "self_managed_path",
                "status",
                "store_path",
                "store_state_home",
                "system_path",
                "witness_path",
            ]
        );
    }

    #[test]
    fn an_uncertain_failure_keeps_the_path_it_named() {
        let cases = [
            StoreActivationError::Io {
                path: path(),
                source: std::io::Error::from_raw_os_error(libc::EIO),
            },
            StoreActivationError::RecordInspection {
                path: path(),
                reason: CertificationError::AclProbeUnknown,
            },
        ];
        for error in cases {
            let report = DoctorReport::failed(&error);
            assert_eq!(report.status, ReadinessStatus::Uncertain);
            assert_eq!(report.path, Some(path()), "{error}");
        }
    }

    /// A trash listing that cannot see the account's store sends the reader here for
    /// the state directory it was activated against. Reporting the anchor and stopping
    /// leaves that instruction unfollowable except by reading activation records.
    #[test]
    fn a_ready_report_names_the_store_and_the_directory_it_belongs_to() {
        let store = PathBuf::from("/recorded/state/degu/sealed-staging");
        let report = DoctorReport::from_selected_authority(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Activated,
            Some(&store),
        );

        assert_eq!(report.store_path.as_deref(), Some(store.as_path()));
        assert_eq!(
            report.store_state_home.as_deref(),
            Some(Path::new("/recorded/state")),
            "the directory the reader was told to use is the store's own"
        );
    }

    /// `docs/safety.md` sends an operator whose recorded store is gone to the
    /// activation record instead, because this report names no store there. Both
    /// directions are asserted: a renamed label would leave the absent case passing
    /// on a report that says nothing the documentation names.
    #[test]
    fn only_an_authenticated_store_is_named() {
        let authenticated = render_human(&DoctorReport::from_selected_authority(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Activated,
            Some(Path::new("/recorded/state/degu/sealed-staging")),
        ));
        assert!(authenticated.contains("Store path"), "{authenticated}");
        assert!(authenticated.contains("Store state"), "{authenticated}");

        let lost = render_human(&DoctorReport::from_selected_authority(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Lost,
            None,
        ));
        assert!(!lost.contains("Store path"), "{lost}");
        assert!(!lost.contains("Store state"), "{lost}");
    }

    /// The human report has to say the directory this run reads is a different one.
    /// `Store state` alone reads as where the store is, not as somewhere else.
    #[test]
    fn a_differing_state_directory_is_named_as_such() {
        let mut report = DoctorReport::from_selected_authority(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Activated,
            Some(Path::new("/recorded/state/degu/sealed-staging")),
        );
        // Set rather than derived: this process reads its own state directory, and the
        // renderer is what this test is about.
        report.other_state_home = Some(PathBuf::from("/somewhere/else"));

        let rendered = render_human(&report);
        assert!(
            rendered.contains("/recorded/state/degu/sealed-staging"),
            "{rendered}"
        );
        assert!(
            rendered.contains("This run reads a different state directory"),
            "{rendered}"
        );
        assert!(rendered.contains("/somewhere/else"), "{rendered}");

        report.other_state_home = None;
        let same = render_human(&report);
        assert!(
            !same.contains("a different state directory"),
            "the same directory was explained as a difference: {same}"
        );
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
    fn backend_failures_distinguish_unsupported_unsafe_and_uncertain() {
        for (reason, expected) in [
            (
                CertificationError::UnsupportedFilesystem,
                ReadinessStatus::Unsupported,
            ),
            (
                CertificationError::FilesystemMagicMismatch,
                ReadinessStatus::Unsafe,
            ),
            (CertificationError::NotDirectory, ReadinessStatus::Unsafe),
            (CertificationError::AclPresent, ReadinessStatus::Unsafe),
            (
                CertificationError::MountIdentityUnavailable,
                ReadinessStatus::Uncertain,
            ),
            (
                CertificationError::AclProbeUnknown,
                ReadinessStatus::Uncertain,
            ),
        ] {
            assert_eq!(
                DoctorReport::failed(&StoreActivationError::Backend(reason)).status,
                expected
            );
        }
    }

    #[test]
    fn unsafe_anchor_preserves_nested_inspection_certainty() {
        let cases = [
            (
                StoreError::UnsafeDirectory {
                    path: path(),
                    reason: "unsafe mode",
                },
                ReadinessStatus::Unsafe,
            ),
            (
                StoreError::BackendInspection {
                    path: path(),
                    reason: CertificationError::AclPresent,
                },
                ReadinessStatus::Unsafe,
            ),
            (
                StoreError::BackendInspection {
                    path: path(),
                    reason: CertificationError::AclProbeUnknown,
                },
                ReadinessStatus::Uncertain,
            ),
            (
                StoreError::Io {
                    path: path(),
                    source: std::io::Error::from_raw_os_error(libc::EIO),
                },
                ReadinessStatus::Uncertain,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                DoctorReport::failed(&StoreActivationError::UnsafeAnchor(error)).status,
                expected
            );
        }
    }

    #[test]
    fn ready_json_names_the_selected_mode_and_activation_state() {
        let report = DoctorReport::from_selected_authority(
            ActivationAuthorityMode::SelfManaged,
            &path(),
            CertifiedLocalBackend::Ext4,
            StoreActivationKind::Activated,
            Some(Path::new("/recorded/state/degu/sealed-staging")),
        );
        let value = serde_json::to_value(report).unwrap();
        assert_exact_json_keys(&value);
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["check"], CHECK_ID);
        assert_eq!(value["status"], "ready");
        assert_eq!(value["authority_mode"], "self_managed");
        assert_eq!(value["activation_state"], "activated");
        assert_eq!(value["path"], "/fixed/system/anchor");
        assert_eq!(value["backend"], "ext4");
        assert_eq!(value["witness_path"], serde_json::Value::Null);
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
            let report = DoctorReport::from_selected_authority(
                ActivationAuthorityMode::AdministratorHardened,
                &path(),
                CertifiedLocalBackend::Xfs,
                state,
                None,
            );
            assert_eq!(report.status, ReadinessStatus::RecoveryRequired);
            assert!(!report.status.is_ready());
        }
    }

    #[test]
    fn selected_loss_reports_a_role_neutral_witness_in_both_directions() {
        for (selected, witness) in [
            ("/fixed/system/anchor", "/fixed/self/anchor"),
            ("/fixed/self/anchor", "/fixed/system/anchor"),
        ] {
            let report = DoctorReport::failed(&StoreActivationError::SelectedAuthorityLost {
                selected: PathBuf::from(selected),
                witness: PathBuf::from(witness),
            });
            assert_eq!(report.status, ReadinessStatus::RecoveryRequired);
            assert_eq!(report.path.as_deref(), Some(Path::new(selected)));
            assert_eq!(report.witness_path.as_deref(), Some(Path::new(witness)));
            assert!(report.system_path.is_none());
            assert!(report.self_managed_path.is_none());
            let output = render_human(&report);
            assert!(output.contains(&format!("Authority path  {selected}")));
            assert!(output.contains(&format!("Witness path    {witness}")));
            assert!(!output.contains("System path"));
            assert!(!output.contains("Self path"));
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
        assert!(output.contains("run 'degu init'"));
    }
}
