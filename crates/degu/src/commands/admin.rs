use crate::cli::AdminCommand;
use anyhow::{Context, Result, bail};
use degu_core::provision::provision_activation_anchor;

const ACTION: &str = "account_setup";

pub(crate) fn run(command: AdminCommand) -> Result<()> {
    // This dispatch is deliberately outside the generic root policy. It does
    // not accept the container marker or DEGU_ALLOW_ROOT as a substitute.
    if !rustix::process::geteuid().is_root() {
        bail!("account setup requires effective UID 0");
    }
    let AdminCommand::Setup(args) = command;
    let outcome = provision_activation_anchor(args.uid, args.initial).with_context(|| {
        format!(
            "refused create-only account setup for numeric UID {}",
            args.uid
        )
    })?;
    let mutated = outcome.mutated();
    super::setup::print_provisioning_outcome(
        ACTION,
        "Account setup",
        outcome,
        mutated,
        args.output.json,
    )
}
