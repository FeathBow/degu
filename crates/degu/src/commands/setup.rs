use crate::output::stdoutln;
use anyhow::Result;
use degu_core::local_backend::CertifiedLocalBackend;
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
            status: match outcome.status {
                ActivationAnchorProvisioningStatus::Created => "created",
                ActivationAnchorProvisioningStatus::AlreadyProvisioned => "already_provisioned",
            },
            path: outcome.path,
            uid: outcome.uid,
            backend: backend_name(outcome.backend),
            mutated,
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
}
