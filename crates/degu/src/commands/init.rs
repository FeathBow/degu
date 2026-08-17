use anyhow::{Context, Result};
use degu_core::activation::initialize_current_euid_self_authority;

const ACTION: &str = "self_managed_account_setup";

/// Explicitly provision only the fixed anchor for the current non-root EUID.
/// Store activation remains a separate, selector-guarded lifecycle transition.
pub(crate) fn run(initial: bool, json: bool) -> Result<()> {
    let outcome = initialize_current_euid_self_authority(initial)
        .context("refused create-only self-managed account setup")?;
    let mutated = outcome.mutated();
    super::setup::print_provisioning_outcome(
        ACTION,
        "Self-managed account setup",
        outcome.provisioning,
        mutated,
        json,
    )
}
