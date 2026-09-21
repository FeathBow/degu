use anyhow::{Context, Result};
use degu_core::activation::{
    SelfAuthorityInitializationError, initialize_current_euid_self_authority,
};
use degu_core::ecosystem::DetectCtx;

const ACTION: &str = "self_managed_account_setup";

/// Provision the fixed current-account anchor and durably declare it as the
/// self-managed authority. Store activation remains a separate, selector-guarded
/// lifecycle transition.
/// Refuse to publish a fresh authority over a store that has already been
/// activated.
///
/// The two situations `missing` covers are first use and an authority that
/// went missing, and only the second is dangerous: a new authority does not
/// authenticate the existing store, so everything staged in it becomes
/// visible through `degu trash list` and unrecoverable through `degu undo`.
///
/// degu used to ask the person to assert which situation this was, through a
/// mandatory `--initial`. The assertion was unverifiable by construction and
/// unenforced in practice — nothing looked — so it refused first use and let
/// the dangerous case through. The store says which situation this is, and
/// says it in the same record that later refuses the undo.
fn refuse_if_a_store_is_already_activated() -> Result<()> {
    let ctx = DetectCtx::from_process().context("failed to read this account's environment")?;
    refuse_activated_store_in(&ctx)
}

fn refuse_activated_store_in(ctx: &DetectCtx) -> Result<()> {
    let store = crate::lifecycle::sealed_staging_store_path(ctx);
    let binding = store.join(degu_core::activation::STORE_BINDING_NAME);
    if !binding.exists() {
        return Ok(());
    }
    anyhow::bail!(
        "this account has already activated a sealed-staging store at {}, so its authority is \
         missing rather than absent. Publishing a new one would leave everything staged in that \
         store unrecoverable. Run 'degu doctor' and inspect the recorded anchor and store before \
         changing either.",
        store.display()
    )
}

pub(crate) fn run(json: bool) -> Result<()> {
    refuse_if_a_store_is_already_activated()?;
    let outcome = match initialize_current_euid_self_authority() {
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

    fn ctx_with_state(state: &std::path::Path) -> DetectCtx {
        DetectCtx::for_test(
            state.to_path_buf(),
            [("XDG_STATE_HOME".to_owned(), state.as_os_str().to_owned())],
        )
    }

    /// The refusal that replaced `--initial`.
    ///
    /// Exercised here rather than through the binary because `degu init`
    /// derives its target from the account database: a test that ran it would
    /// provision whoever ran the suite.
    #[test]
    fn a_store_that_was_activated_refuses_a_fresh_authority() {
        let state = tempfile::tempdir().unwrap();
        let ctx = ctx_with_state(state.path());
        refuse_activated_store_in(&ctx).expect("nothing staged yet");

        let store = crate::lifecycle::sealed_staging_store_path(&ctx);
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join(degu_core::activation::STORE_BINDING_NAME), b"").unwrap();

        let refusal = refuse_activated_store_in(&ctx).expect_err("an activated store refuses");
        let message = format!("{refusal}");
        assert!(message.contains("already activated"), "{message}");
        assert!(message.contains("unrecoverable"), "{message}");
    }

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
