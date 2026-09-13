use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::cli::ScanArgs;
use crate::runtime::Ui;
use crate::tui::{App, Outcome};

pub(crate) fn run(args: ScanArgs, ui: Ui) -> Result<()> {
    // Refuse before taking the screen rather than inside terminal setup: with
    // only stdout checked, a redirected stdin enters the alternate screen and
    // then waits for a key that can never arrive.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!(
            "degu tui requires an interactive terminal; use 'degu scan' for output that survives a pipe or a log"
        );
    }
    let limits = args.limits;
    let report = crate::commands::scan::collect_for_review(args, ui)?;
    let mut app = App::new(report, limits);

    // Nothing executes while the alternate screen is up. Previewing returns to
    // the interface; cleaning ends it. Either way the plan and its confirmation
    // print to the restored terminal, so the scrollback holds what it would
    // have held if the command had been typed.
    loop {
        match browse(&mut app)? {
            Outcome::Quit => return Ok(()),
            Outcome::Preview => {
                announce(&app, ui, true)?;
                crate::commands::clean::run(app.clean_args(true), ui)?;
                if !resume(ui)? {
                    return Ok(());
                }
            }
            Outcome::Clean => {
                announce(&app, ui, false)?;
                return crate::commands::clean::run(app.clean_args(false), ui);
            }
        }
    }
}

/// Show the command these decisions amount to before running it, so a reader
/// who wants the rule rather than the judgement next time can see how to say it
/// on a command line.
fn announce(app: &App, ui: Ui, dry_run: bool) -> Result<()> {
    crate::output::stdoutln!("{}", ui.prose(&app.decisions().command_line(dry_run)))
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

/// A preview leaves the reader at a shell prompt holding the plan they asked
/// to read; reopening over it would take it away before they had read it. The
/// prompt says what it is asking, because on its own "Proceed?" right under a
/// plan reads as consent to run that plan.
fn resume(ui: Ui) -> Result<bool> {
    crate::output::stdoutln!(
        "{}",
        ui.prose("Answer y to go back to the review, or n to stop here.")
    )?;
    crate::commands::prompt::confirm_required("returning to the review requires a terminal")
}
