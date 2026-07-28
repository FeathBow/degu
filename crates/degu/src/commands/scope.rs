use crate::cli::ScanArgs;
use crate::filters::Filters;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(crate) struct ScanScope {
    pub(super) filters: Filters,
    pub(super) runtime: bool,
}

impl ScanScope {
    pub(crate) fn from_args(args: &ScanArgs) -> Self {
        Self {
            filters: Filters {
                roots: args.roots.clone(),
                only: args.only.clone(),
            },
            runtime: args.runtime,
        }
    }

    pub(crate) fn roots(&self) -> &[PathBuf] {
        &self.filters.roots
    }

    pub(crate) fn only_ids(&self) -> &[String] {
        &self.filters.only
    }

    pub(crate) fn runtime_requested(&self) -> bool {
        self.runtime
    }
}
