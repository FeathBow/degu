use crate::cli::AdminCommand;
use crate::output::stdoutln;
use anyhow::{Context, Result, bail};
use degu_core::local_backend::CertifiedLocalBackend;
use degu_core::provision::{
    ActivationAnchorProvisioningOutcome, ActivationAnchorProvisioningStatus,
    provision_activation_anchor,
};
use serde::Serialize;
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;
const ACTION: &str = "account_setup";

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

impl From<ActivationAnchorProvisioningOutcome> for ProvisionReport {
    fn from(outcome: ActivationAnchorProvisioningOutcome) -> Self {
        let mutated = outcome.mutated();
        Self {
            schema_version: SCHEMA_VERSION,
            action: ACTION,
            status: match outcome.status {
                ActivationAnchorProvisioningStatus::Created => "created",
                ActivationAnchorProvisioningStatus::AlreadyProvisioned => "already_provisioned",
            },
            path: outcome.path,
            uid: outcome.uid,
            backend: match outcome.backend {
                CertifiedLocalBackend::Ext4 => "ext4",
                CertifiedLocalBackend::Xfs => "xfs",
                CertifiedLocalBackend::Apfs => "apfs",
            },
            mutated,
        }
    }
}

pub(crate) fn run(command: AdminCommand) -> Result<()> {
    // This dispatch is deliberately outside the generic root policy. It does
    // not accept the container marker or DEGU_ALLOW_ROOT as a substitute.
    if !rustix::process::geteuid().is_root() {
        bail!("account setup requires effective UID 0");
    }
    let AdminCommand::Setup(args) = command;
    let report: ProvisionReport = provision_activation_anchor(args.uid, args.initial)
        .with_context(|| {
            format!(
                "refused create-only account setup for numeric UID {}",
                args.uid
            )
        })?
        .into();
    if args.output.json {
        stdoutln!("{}", serde_json::to_string_pretty(&report)?)
    } else {
        stdoutln!(
            "Account setup {} for UID {} at {} ({}, mutated={})",
            report.status,
            report.uid,
            crate::presentation::escape_terminal_text(&report.path.display().to_string()),
            report.backend,
            report.mutated
        )
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
            let report: ProvisionReport = ActivationAnchorProvisioningOutcome {
                path: PathBuf::from("/var/lib/degu/store-activation/1000"),
                uid: 1000,
                backend: CertifiedLocalBackend::Ext4,
                status,
            }
            .into();
            let value = serde_json::to_value(&report).unwrap();
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["action"], ACTION);
            assert_eq!(value["status"], status_name);
            assert_eq!(value["uid"], 1000);
            assert_eq!(value["backend"], "ext4");
            assert_eq!(value["mutated"], mutated);
        }
    }
}
