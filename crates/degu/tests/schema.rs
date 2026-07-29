//! JSON stdout schema freeze for degu commands.
//! A failure here means a user-visible contract change.
//! Consumers must treat unknown enum values in authority-related fields
//! conservatively.

#[path = "support/clean_run.rs"]
mod clean_run;
#[path = "schema/clean_scan_summary.rs"]
mod clean_scan_summary;
#[path = "support/mod.rs"]
mod common;
#[path = "schema/operations.rs"]
mod operations;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "schema/relocate.rs"]
mod relocate;
#[path = "schema/scan.rs"]
mod scan;
#[path = "schema/support.rs"]
mod support;
