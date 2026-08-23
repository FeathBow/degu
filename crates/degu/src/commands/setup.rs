use crate::output::stdoutln;
use anyhow::Result;
use degu_core::activation::{
    AuthorityClaimPublicationState, SelfAuthorityInitializationPostProvisionError,
};
use degu_core::backend::CertifiedLocalBackend;
use degu_core::provision::{
    ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningStatus,
};
use serde::Serialize;
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct ProvisionReport {
    schema_version: u32,
    action: &'static str,
    status: &'static str,
    path: PathBuf,
    uid: u32,
    backend: &'static str,
    mutated: bool,
}

impl ProvisionReport {
    fn new(
        action: &'static str,
        outcome: ActivationAnchorProvisioningOutcome,
        mutated: bool,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            action,
            status: provisioning_status_name(outcome.status),
            path: outcome.path,
            uid: outcome.uid,
            backend: backend_name(outcome.backend),
            mutated,
        }
    }
}

#[derive(Debug, Serialize)]
struct PostProvisionFailureReport {
    schema_version: u32,
    action: &'static str,
    status: &'static str,
    path: PathBuf,
    uid: u32,
    backend: &'static str,
    provisioning_status: &'static str,
    provisioning_mutated: bool,
    authority_claim: &'static str,
    rollback: &'static str,
    error: String,
}

impl PostProvisionFailureReport {
    fn new(
        action: &'static str,
        provisioning: &ActivationAnchorProvisioningOutcome,
        authority_claim: AuthorityClaimPublicationState,
        error: &str,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            action,
            status: "failed",
            path: provisioning.path.clone(),
            uid: provisioning.uid,
            backend: backend_name(provisioning.backend),
            provisioning_status: provisioning_status_name(provisioning.status),
            provisioning_mutated: provisioning.mutated(),
            authority_claim: authority_claim.as_str(),
            rollback: "not_attempted",
            error: error.to_owned(),
        }
    }
}

pub(super) fn print_provisioning_outcome(
    action: &'static str,
    human_subject: &'static str,
    outcome: ActivationAnchorProvisioningOutcome,
    mutated: bool,
    json: bool,
) -> Result<()> {
    let report = ProvisionReport::new(action, outcome, mutated);
    if json {
        stdoutln!("{}", serde_json::to_string_pretty(&report)?)
    } else {
        stdoutln!(
            "{human_subject} {} for UID {} at {} ({}, mutated={})",
            report.status,
            report.uid,
            crate::presentation::escape_terminal_text(&report.path.display().to_string()),
            report.backend,
            report.mutated
        )
    }
}

pub(super) fn print_post_provision_failure(
    action: &'static str,
    human_subject: &'static str,
    failure: &SelfAuthorityInitializationPostProvisionError,
    json: bool,
) -> Result<()> {
    let report = PostProvisionFailureReport::new(
        action,
        failure.provisioning(),
        failure.authority_claim(),
        &failure.authority_error().to_string(),
    );
    if json {
        stdoutln!("{}", serde_json::to_string_pretty(&report)?)
    } else {
        stdoutln!("{}", render_post_provision_failure(human_subject, &report))
    }
}

fn render_post_provision_failure(
    human_subject: &str,
    report: &PostProvisionFailureReport,
) -> String {
    format!(
        "{human_subject} failed after activation-anchor provisioning

Activation anchor  {} at {} (mutated={})
Authority claim    {}
Rollback           not attempted; the committed anchor remains in place
Failure            {}",
        report.provisioning_status,
        crate::presentation::escape_terminal_text(&report.path.display().to_string()),
        report.provisioning_mutated,
        report.authority_claim,
        crate::presentation::escape_terminal_text(&report.error),
    )
}

fn provisioning_status_name(status: ActivationAnchorProvisioningStatus) -> &'static str {
    match status {
        ActivationAnchorProvisioningStatus::Created => "created",
        ActivationAnchorProvisioningStatus::AlreadyProvisioned => "already_provisioned",
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

    #[test]
    fn report_shape_distinguishes_creation_from_idempotent_validation() {
        for (status, status_name, mutated) in [
            (ActivationAnchorProvisioningStatus::Created, "created", true),
            (
                ActivationAnchorProvisioningStatus::AlreadyProvisioned,
                "already_provisioned",
                false,
            ),
        ] {
            let report = ProvisionReport::new(
                "account_setup",
                ActivationAnchorProvisioningOutcome {
                    path: PathBuf::from("/fixed/activation/1000"),
                    uid: 1000,
                    backend: CertifiedLocalBackend::Ext4,
                    status,
                },
                mutated,
            );
            let value = serde_json::to_value(&report).unwrap();
            assert_eq!(value["schema_version"], SCHEMA_VERSION);
            assert_eq!(value["action"], "account_setup");
            assert_eq!(value["status"], status_name);
            assert_eq!(value["uid"], 1000);
            assert_eq!(value["backend"], "ext4");
            assert_eq!(value["mutated"], mutated);
        }
    }

    #[test]
    fn post_provision_failure_report_separates_committed_and_uncertain_mutation() {
        let provisioning = ActivationAnchorProvisioningOutcome {
            path: PathBuf::from("/fixed/self/activation/1000"),
            uid: 1000,
            backend: CertifiedLocalBackend::Ext4,
            status: ActivationAnchorProvisioningStatus::Created,
        };
        for (authority_claim, expected) in [
            (
                AuthorityClaimPublicationState::NotAttempted,
                "not_attempted",
            ),
            (
                AuthorityClaimPublicationState::MayHavePublished,
                "may_have_published",
            ),
            (AuthorityClaimPublicationState::Published, "published"),
        ] {
            let report = PostProvisionFailureReport::new(
                "self_managed_account_setup",
                &provisioning,
                authority_claim,
                "claim sync failed",
            );
            let value = serde_json::to_value(&report).unwrap();
            let mut keys = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "action",
                    "authority_claim",
                    "backend",
                    "error",
                    "path",
                    "provisioning_mutated",
                    "provisioning_status",
                    "rollback",
                    "schema_version",
                    "status",
                    "uid",
                ]
            );
            assert_eq!(value["schema_version"], SCHEMA_VERSION);
            assert_eq!(value["status"], "failed");
            assert_eq!(value["path"], "/fixed/self/activation/1000");
            assert_eq!(value["provisioning_status"], "created");
            assert_eq!(value["provisioning_mutated"], true);
            assert_eq!(value["authority_claim"], expected);
            assert_eq!(value["rollback"], "not_attempted");
            assert_eq!(value["error"], "claim sync failed");
        }
    }

    #[test]
    fn human_post_provision_failure_discloses_no_rollback() {
        let report = PostProvisionFailureReport::new(
            "self_managed_account_setup",
            &ActivationAnchorProvisioningOutcome {
                path: PathBuf::from("/fixed/self/activation/1000"),
                uid: 1000,
                backend: CertifiedLocalBackend::Ext4,
                status: ActivationAnchorProvisioningStatus::Created,
            },
            AuthorityClaimPublicationState::MayHavePublished,
            "claim sync failed",
        );
        let output = render_post_provision_failure("Self-managed account setup", &report);
        assert!(output.contains("Activation anchor  created"));
        assert!(output.contains("Authority claim    may_have_published"));
        assert!(output.contains("not attempted; the committed anchor remains in place"));
        assert!(output.contains("Failure            claim sync failed"));
    }
}
