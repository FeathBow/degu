mod output;

use crate::cli::QuotaArgs;
use crate::commands::next_action::{self, OutputMode, Request, Workflow};
use crate::presentation::escape_terminal_text;
use crate::runtime::Ui;
use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;

pub(crate) fn run(args: QuotaArgs, ui: Ui) -> Result<()> {
    let json = args.output.json;
    let target = resolve_target(args.path)?;
    let target_text = escape_terminal_text(&target.display().to_string());
    let canonical = std::fs::canonicalize(&target)
        .with_context(|| format!("quota target is unavailable: {target_text}"))?;
    let report = crate::quota::probe(&canonical)?;
    output::print(&report, json, ui)?;
    next_action::print(Request {
        output: output_mode(json, ui),
        workflow: Workflow::Quota,
        home: None,
    })?;
    Ok(())
}

fn output_mode(json: bool, ui: Ui) -> OutputMode {
    if json {
        OutputMode::Json
    } else {
        OutputMode::Human(ui)
    }
}

fn resolve_target(path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = path {
        return Ok(path);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set; provide an explicit quota path"))
}
