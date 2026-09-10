//! Browse a saved report without traversing or mutating its recorded paths.
mod browser;
mod escape;
mod report;
mod ui;

use std::io::{IsTerminal, Read};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use report::ScanReport;
use ui::App;

const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(250);

const USAGE: &str = "\
degu-tui — browse a saved degu scan report

USAGE:
    degu scan --json > scan.json
    degu-tui scan.json

KEYS:";

fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() > 1 {
        bail!(
            "degu-tui takes one saved report; {} arguments were given",
            arguments.len()
        );
    }
    let argument = arguments.into_iter().next();
    let source = match argument {
        None => {
            print_help();
            return Ok(());
        }
        Some(argument) if matches!(argument.as_str(), "-h" | "--help") => {
            print_help();
            return Ok(());
        }
        Some(argument) if argument == "-" => bail!(
            "degu-tui reads a saved report, not a pipe; \
             write it first with 'degu scan --json > scan.json'"
        ),
        Some(path) => path,
    };
    let report = read_report(&source)?;
    require_terminal()?;
    run(App::new(report, source))
}

fn print_help() {
    println!("{USAGE}\n{}", ui::help::KEY_HELP);
}

fn read_report(path: &str) -> Result<ScanReport> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("could not open the report at {path}"))?;
    let length = file
        .metadata()
        .with_context(|| format!("could not inspect the report at {path}"))?
        .len();
    if length > MAX_REPORT_BYTES {
        bail!("{path} is {length} bytes; a scan report above {MAX_REPORT_BYTES} bytes is refused");
    }
    let mut json = String::new();
    // One extra byte distinguishes an exact-size report from a truncated read.
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_string(&mut json)
        .context("could not read the report")?;
    if json.len() as u64 > MAX_REPORT_BYTES {
        bail!("the report exceeds {MAX_REPORT_BYTES} bytes and is refused");
    }
    let report: ScanReport = serde_json::from_str(&json).context(
        "that file is not a degu scan report; produce one with 'degu scan --json > scan.json'",
    )?;
    let findings = report.findings.len() + report.runtime.len();
    if findings > MAX_FINDINGS {
        bail!(
            "that report has {findings} findings; above {MAX_FINDINGS} it is refused as malformed"
        );
    }
    Ok(report)
}

fn require_terminal() -> Result<()> {
    if !std::io::stdout().is_terminal() {
        bail!(
            "degu-tui requires an interactive terminal; \
               use 'degu scan' for output that survives a pipe or a log"
        );
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "degu-tui reads keys from standard input, which is not a terminal here; \
               run it directly rather than with input redirected"
        );
    }
    Ok(())
}

fn run(mut app: App) -> Result<()> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            // Initialization can fail after entering raw mode.
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
        terminal.draw(|frame| ui::draw(frame, app))?;
        if !event::poll(EVENT_POLL_INTERVAL)? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press && app.handle(key) => return Ok(()),
            _ => {}
        }
    }
}
