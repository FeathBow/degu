use anyhow::{Context, Result};
use degu_core::activation::{
    SelfAuthorityInitializationError, initialize_current_euid_self_authority,
};

const ACTION: &str = "self_managed_account_setup";

/// Provision the fixed current-account anchor and durably declare it as the
/// self-managed authority. Store activation remains a separate, selector-guarded
/// lifecycle transition.
pub(crate) fn run(initial: bool, json: bool) -> Result<()> {
    let outcome = match initialize_current_euid_self_authority(initial) {
        Ok(outcome) => outcome,
        Err(error @ SelfAuthorityInitializationError::PostProvision(_)) => {
            let SelfAuthorityInitializationError::PostProvision(failure) = &error else {
                unreachable!("matched post-provision initialization error")
            };
            let output_result = super::setup::print_post_provision_failure(
                ACTION,
                "Self-managed account setup",
                failure,
                json,
            );
            let domain_error =
                anyhow::Error::new(error).context("refused create-only self-managed account setup");
            return finish_failed_initialization(output_result, domain_error);
        }
        Err(error) => {
            return Err(error).context("refused create-only self-managed account setup");
        }
    };
    let mutated = outcome.mutated();
    super::setup::print_provisioning_outcome(
        ACTION,
        "Self-managed account setup",
        outcome.provisioning,
        mutated,
        json,
    )
}

fn finish_failed_initialization(
    output_result: Result<()>,
    domain_error: anyhow::Error,
) -> Result<()> {
    // A committed provisioning or uncertain claim failure remains a command
    // failure even when its final report consumer has disappeared. The report
    // was already attempted; the domain failure is the primary result.
    drop(output_result);
    Err(domain_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_provision_failure_dominates_a_closed_stdout_consumer() {
        let error = finish_failed_initialization(
            Err(crate::output::stdout_closed_error()),
            anyhow::anyhow!("post-provision initialization failure"),
        )
        .unwrap_err();
        assert!(!crate::output::is_stdout_closed(&error));
        assert!(
            error
                .to_string()
                .contains("post-provision initialization failure")
        );
    }
}
