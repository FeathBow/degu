//! Interactive review of a scan and the staging trash. Decisions made here
//! become the arguments the ordinary commands already take; nothing in this
//! module scans, admits, stages or deletes.

mod browser;
mod decision;
mod escape;
mod report;
mod staged;
mod ui;

pub(crate) use report::ScanReport;
pub(crate) use staged::Staged;
pub(crate) use ui::{App, Outcome, draw};
