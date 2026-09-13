//! Interactive review of a scan, over the same plan the CLI executes.

mod browser;
mod decision;
mod escape;
mod report;
mod ui;

pub(crate) use report::ScanReport;
pub(crate) use ui::{App, Outcome, draw};
