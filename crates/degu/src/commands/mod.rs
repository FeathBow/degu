use crate::cli::{JsonArgs, ScanLimitArgs};
use crate::runtime::OutputColors;
use std::num::NonZeroUsize;
use std::time::Duration;

pub(crate) mod adapters;
pub(crate) mod completions;
pub(crate) mod man;
pub(crate) mod next_action;
pub(crate) mod ops;
pub(crate) mod scan;
mod scope;
pub(crate) mod trash;

pub(crate) struct CollectionRunOptions {
    pub(crate) json: bool,
    pub(crate) indicator_color_enabled: bool,
    pub(crate) max_concurrency: Option<NonZeroUsize>,
    pub(crate) budget: Option<Duration>,
}

impl CollectionRunOptions {
    pub(crate) fn new(output: JsonArgs, limits: ScanLimitArgs, colors: OutputColors) -> Self {
        Self {
            json: output.json,
            indicator_color_enabled: colors.stderr,
            max_concurrency: limits.max_concurrency,
            budget: limits.budget,
        }
    }
}
