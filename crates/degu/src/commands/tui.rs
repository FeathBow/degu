use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::cli::{CleanArgs, ScanLimitArgs, TrashCommand, TuiArgs};
use crate::findings::Filters;
use crate::runtime::Ui;
use crate::tui::{App, Outcome};

struct Review {
    app: App,
    filters: Filters,
    limits: ScanLimitArgs,
}

impl Review {
    fn collect(args: TuiArgs, ui: Ui) -> Result<Self> {
        let limits = args.limits;
        let args = crate::cli::ScanArgs::from(args);
        let (report, filters, ctx) = crate::commands::scan::collect_for_review(args, ui)?;
        // One read-only pass over the trash. Each row already carries whether
        // a confirmed clean would expire it, so asking the expiry planner as
        // well would re-read the operation log and capture execution-grade
        // identities that this screen then discards.
        let staged =
            crate::tui::Staged::new(crate::lifecycle::Lifecycle::new(&ctx).trash_entries()?);
        Ok(Self {
            app: App::new(report, staged, ctx.home),
            filters,
            limits,
        })
    }

    fn clean_args(&self, dry_run: bool) -> Option<CleanArgs> {
        self.app
            .decisions()
            .clean_args(&self.filters, self.limits, dry_run)
    }
}

pub(crate) fn run(args: TuiArgs, ui: Ui) -> Result<()> {
    // Redirected stdin cannot supply keys even when stdout is a terminal.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!(
            "degu tui requires an interactive terminal; use 'degu scan' for output that survives a pipe or a log"
        );
    }
    let mut review = Review::collect(args, ui)?;

    // Restore the terminal before commands run so plans and prompts remain in scrollback.
    loop {
        match browse(&mut review.app)? {
            Outcome::Quit => return Ok(()),
            Outcome::Preview => {
                if let Some(args) = review.clean_args(true) {
                    run_clean(args, ui)?;
                } else {
                    crate::output::stdoutln!(
                        "Nothing chosen to clean; no clean or expiry will run."
                    )?;
                }
                if !resume(ui)? {
                    return Ok(());
                }
            }
            Outcome::Clean => return execute(&review, ui),
        }
    }
}

fn execute(review: &Review, ui: Ui) -> Result<()> {
    let app = &review.app;
    let clean = review.clean_args(false);
    if let Some(args) = app.staged().purge_args() {
        announce(crate::commands::guidance::purge_command(&args), ui)?;
        let purged = crate::commands::trash::run(TrashCommand::Purge(args), ui);
        if clean.is_some() {
            // The two halves are sequential, not atomic. Anything that stops
            // the purge — a declined confirmation, an entry that moved since
            // the screen was drawn, a held lock, or a failure after some
            // entries were already destroyed — stops the clean as well, so the
            // message says what did not happen rather than naming one cause.
            purged.context("the clean was not run either")?;
        } else {
            purged?;
        }
    }
    match clean {
        Some(args) => run_clean(args, ui),
        None => Ok(()),
    }
}

fn run_clean(args: CleanArgs, ui: Ui) -> Result<()> {
    announce(crate::commands::guidance::clean_command(&args), ui)?;
    crate::commands::clean::run(args, ui)
}

fn announce(command: Option<String>, ui: Ui) -> Result<()> {
    match command {
        Some(command) => crate::output::stdoutln!("{command}"),
        None => crate::output::stdoutln!(
            "{}",
            ui.prose("Equivalent command unavailable: an argument cannot be represented safely as shell text.")
        ),
    }
}

fn browse(app: &mut App) -> Result<Outcome> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            ratatui::restore();
            return Err(error).context("could not start the interactive terminal");
        }
    };
    let outcome = event_loop(&mut terminal, app);
    ratatui::restore();
    outcome
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<Outcome> {
    loop {
        terminal.draw(|frame| crate::tui::draw(frame, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(outcome) = app.handle(key)
        {
            return Ok(outcome);
        }
    }
}

// Returning to the TUI needs separate wording from confirming the displayed plan.
fn resume(ui: Ui) -> Result<bool> {
    crate::output::stdoutln!(
        "{}",
        ui.prose("Answer y to go back to the review, or n to stop here.")
    )?;
    crate::commands::prompt::confirm_required("returning to the review requires a terminal")
}
