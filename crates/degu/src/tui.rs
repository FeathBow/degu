//! Interactive review; execution is delegated to the existing CLI commands.

mod browser;
mod decision;
mod report;
mod staged;
mod ui;

pub(crate) use report::ScanReport;
pub(crate) use staged::Staged;
pub(crate) use ui::{App, Outcome, draw};
