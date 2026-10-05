use anyhow::Result;
use degu_core::ecosystem::DetectCtx;

use crate::cli::TrashForgetArgs;
use crate::commands::prompt::confirm_required;
use crate::output::{flush_stdout, stdoutln};
use crate::presentation::display_path;

pub(super) fn run(args: TrashForgetArgs, _ui: crate::runtime::Ui) -> Result<()> {
    let ctx = DetectCtx::from_process()?;
    let shown = display_path(&args.root, &ctx.home);
    // Described here rather than ahead of the checks: a root that is not
    // registered, or one that is still there, is refused by the call below, and
    // announcing an action before asking whether it is allowed reads as a promise.
    if !args.yes {
        stdoutln!(
            "About to forget the registration for {shown}. Nothing under that root is deleted, and the operation and recovery logs are left as they are."
        )?;
        flush_stdout()?;
        if !confirm_required(
            "forgetting a trash-root registration requires --yes when stdin is not a terminal",
        )? {
            anyhow::bail!("Forget cancelled; the registration was left in place.");
        }
    }
    crate::lifecycle::forget_trash_root(&ctx, &args.root)?;
    stdoutln!("Forgot the registration for {shown}")?;
    // The registration is the only record that says to look there, so the root
    // coming back is exactly when someone would expect the listing to find it.
    stdoutln!(
        "If that filesystem is reconnected, nothing points degu at it any more, so 'degu trash list' will not reach what it holds until a clean stages there again."
    )?;
    Ok(())
}
