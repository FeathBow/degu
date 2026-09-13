use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::cli::ScanArgs;
use crate::runtime::Ui;
use crate::tui::App;

pub(crate) fn run(args: ScanArgs, ui: Ui) -> Result<()> {
    // Refuse before taking the screen rather than inside terminal setup: with
    // only stdout checked, a redirected stdin enters the alternate screen and
    // then waits for a key that can never arrive.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!(
            "degu tui requires an interactive terminal; use 'degu scan' for output that survives a pipe or a log"
        );
    }
    let report = crate::commands::scan::collect_for_review(args, ui)?;
    draw(App::new(report, String::new()))
}

fn draw(mut app: App) -> Result<()> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            ratatui::restore();
            return Err(error).context("could not start the interactive terminal");
        }
    };
    let outcome = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    outcome
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| crate::tui::draw(frame, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press && app.handle(key) => {
                return Ok(());
            }
            _ => {}
        }
    }
}
