use anyhow::{Context, Result};
use degu_core::activation::{
    SelfAuthorityInitializationError, initialize_current_euid_self_authority,
};
use degu_core::ecosystem::DetectCtx;

const ACTION: &str = "self_managed_account_setup";

fn refuse_if_a_store_is_already_activated() -> Result<()> {
    let ctx = DetectCtx::from_process().context("failed to read this account's environment")?;
    refuse_activated_store_in(&ctx, authenticated_store().as_deref())
}

/// The store this account's authority authenticates, when it can be read.
///
/// The same question, and so the same selector, that `activated_store_coverage`
/// asks to decide whether a trash listing covers the activated store. `None`
/// covers first use, an authority that authenticates no store, and an authority
/// this environment could not read: none of them is evidence that the store below
/// is authenticated, and the refusal is the safe answer to all three.
fn authenticated_store() -> Option<std::path::PathBuf> {
    degu_core::activation::check_current_euid_mutation_readiness()
        .ok()?
        .store()
        .map(std::path::Path::to_path_buf)
}

fn refuse_activated_store_in(
    ctx: &DetectCtx,
    authenticated: Option<&std::path::Path>,
) -> Result<()> {
    let store = crate::lifecycle::sealed_staging_store_path(ctx);
    let binding = store.join(degu_core::activation::STORE_BINDING_NAME);
    // `exists()` answers "no" for a path it cannot stat and for a dangling
    // symlink, which are not absence.
    match std::fs::symlink_metadata(&binding) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", binding.display()));
        }
        Ok(_) => {}
    }
    // An authority that authenticates this very store is the account this command
    // is for having already been set up, which is neither of the two situations
    // below. Saying its authority is missing would be false, and `degu init` would
    // fail on every healthy account that has activated a store.
    if authenticated.is_some_and(|recorded| crate::lifecycle::same_directory(recorded, &store)) {
        return Ok(());
    }
    // Not a command to run: 'degu doctor' reports the same missing authority and
    // names this refusal as the way forward, so sending the reader there closes a
    // loop neither end can open. Saying so is the only honest thing this refusal
    // can do until a supported way out exists.
    anyhow::bail!(
        "this account has already activated a sealed-staging store at {}, so its authority is \
         missing rather than absent. Publishing a new one would abandon whatever that store still \
         holds, and degu cannot tell from here what is recoverable in it. Inspect the recorded \
         anchor and that store directly before changing either; 'degu doctor' reports the same \
         missing authority and cannot resolve it.",
        store.display()
    )
}

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
/// A present store binding is not by itself the dangerous case. The authority is
/// asked as well, and when it authenticates this very store the account is simply
/// already set up, which this reports as such: claiming the authority was missing
/// failed `degu init` on every healthy account that had activated a store.
///
/// degu used to ask the person to assert which situation this was, through a
/// mandatory `--initial`. The assertion was unverifiable by construction and
/// unenforced in practice — nothing looked — so it refused first use and let
/// the dangerous case through. The store says which situation this is, in the
/// same record that later refuses the undo.
///
/// This reads the store the current environment points at. A store staged
/// under a different `XDG_STATE_HOME` is not visible here, so a clean result
/// is evidence and not proof: it catches the case degu itself creates by
/// default, which is the one people land in.
pub(crate) fn run(json: bool) -> Result<()> {
    let cleared = every_refusal_made_first()?;
    publish_the_namespace_provisioning_requires(&cleared)?;
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

/// The refusals, and the evidence that they ran, in a namespace of their own.
///
/// `RefusalsCleared` is unforgeable outside this module: its field is private, so
/// nothing in the command body can produce one without calling the function that
/// makes every refusal. The only mutation this command performs ahead of
/// provisioning takes one, so the two cannot be reordered without failing to
/// compile. The fault that buys is not hypothetical — an earlier draft published
/// the namespace and only then asked whether a system authority already claimed
/// the account, so an account that was always going to be refused had its
/// directories changed on the way to hearing so.
mod refusal {
    use super::{
        refuse_if_a_store_is_already_activated, refuse_if_a_system_authority_claims_this_account,
        refuse_if_root_cannot_self_provision,
    };
    use anyhow::Result;

    pub(super) struct RefusalsCleared(());

    pub(super) fn every_refusal_made_first() -> Result<RefusalsCleared> {
        refuse_if_a_store_is_already_activated()?;
        refuse_if_root_cannot_self_provision()?;
        refuse_if_a_system_authority_claims_this_account()?;
        Ok(RefusalsCleared(()))
    }
}

use refusal::{RefusalsCleared, every_refusal_made_first};

/// Root cannot provision a self-managed authority, and provisioning says so — after
/// this command has already published a namespace on the way there.
fn refuse_if_root_cannot_self_provision() -> Result<()> {
    if rustix::process::geteuid().is_root() {
        anyhow::bail!("refused create-only self-managed account setup: root cannot self-provision");
    }
    Ok(())
}

/// Every refusal this command can make, made before it changes anything.
///
/// Provisioning refuses an account a system authority already claims, and it does
/// that before it provisions. A step that runs ahead of provisioning has to ask
/// the same question first, or an account that was always going to be refused
/// gets its directories changed on the way to hearing so.
fn refuse_if_a_system_authority_claims_this_account() -> Result<()> {
    let present = degu_core::activation::current_euid_system_authority()
        .context("failed to read this account's activation authority")?;
    match present {
        None => Ok(()),
        Some(path) => anyhow::bail!(
            "refused create-only self-managed account setup: a system authority already claims this account at {}",
            path.display()
        ),
    }
}

/// Bring the namespace provisioning publishes to the mode it requires.
///
/// An account an earlier version set up has it owner-only, and provisioning wants
/// exactly `0755`. This creates nothing: an absent namespace is provisioning's to
/// create, at the published mode with private ancestors, and a chain that is not
/// already a plain owned directory chain is provisioning's to refuse.
fn publish_the_namespace_provisioning_requires(_cleared: &RefusalsCleared) -> Result<()> {
    let home = degu_core::provision::current_euid_account_home()
        .context("failed to resolve this account's base directory")?;
    let namespace = degu_core::provision::current_euid_published_namespace()
        .context("failed to resolve this account's degu state namespace")?;
    crate::lifecycle::publish_existing_namespace(&home, &namespace).with_context(|| {
        format!(
            "failed to prepare {} for account setup",
            namespace.display()
        )
    })
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
        refuse_activated_store_in(&ctx, None).expect("nothing staged yet");

        let store = crate::lifecycle::sealed_staging_store_path(&ctx);
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join(degu_core::activation::STORE_BINDING_NAME), b"").unwrap();

        let refusal =
            refuse_activated_store_in(&ctx, None).expect_err("an activated store refuses");
        let message = format!("{refusal}");
        assert!(message.contains("already activated"), "{message}");
        assert!(message.contains(&store.display().to_string()), "{message}");
        // 'degu doctor' answers this state by naming 'degu init', so a refusal
        // that sent the reader there would leave them circling.
        assert!(!message.contains("Run 'degu doctor'"), "{message}");
    }

    /// The account this command exists for, already set up: a store at this
    /// environment's path and an authority that authenticates exactly it. Reported
    /// as `init` exiting 1 with a claim that the authority was missing, while
    /// `doctor` called the same account ready.
    ///
    /// A different store is still refused, in the same test, because a check that
    /// accepted any authenticated store at all would pass the case above while
    /// letting a fresh authority be published over a store this one never
    /// authenticated — which is what the refusal is for.
    #[test]
    fn a_store_this_authority_authenticates_is_already_set_up() {
        let state = tempfile::tempdir().unwrap();
        let ctx = ctx_with_state(state.path());
        let store = crate::lifecycle::sealed_staging_store_path(&ctx);
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join(degu_core::activation::STORE_BINDING_NAME), b"").unwrap();

        refuse_activated_store_in(&ctx, Some(&store))
            .expect("an authority that authenticates this store means the account is set up");

        let elsewhere = state.path().join("another-store");
        let refusal = refuse_activated_store_in(&ctx, Some(&elsewhere))
            .expect_err("an authority that authenticates some other store still refuses");
        assert!(
            format!("{refusal}").contains("already activated"),
            "{refusal}"
        );
    }

    /// The recorded store and this environment's are compared as directories, not
    /// as strings: a state home reached through a symlink names the same store by a
    /// different path, and refusing it would fail the healthy account again by a
    /// different route.
    #[test]
    fn a_store_recorded_through_a_symlink_is_the_same_store() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real-state");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.path().join("linked-state");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let ctx = ctx_with_state(&link);
        let store = crate::lifecycle::sealed_staging_store_path(&ctx);
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join(degu_core::activation::STORE_BINDING_NAME), b"").unwrap();

        let recorded = store.canonicalize().unwrap();
        assert_ne!(recorded, store, "the fixture must name the store two ways");
        refuse_activated_store_in(&ctx, Some(&recorded))
            .expect("the same store reached through a link is not a store to abandon");
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
