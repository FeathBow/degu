use crate::cli::ScanArgs;
use crate::filters::Filters;
use crate::source_selection::project_sources_selected;
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
                older_than: args.older_than,
                min_size: args.min_size,
                top: args.top,
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

    pub(crate) fn filters(&self) -> &Filters {
        &self.filters
    }

    pub(crate) fn runtime_requested(&self) -> bool {
        self.runtime
    }

    pub(crate) fn has_explicit_roots(&self) -> bool {
        !self.filters.roots.is_empty()
    }

    pub(crate) fn includes_project_sources(&self) -> bool {
        project_sources_selected(&self.filters.only)
    }

    pub(super) fn project_scan_scope(&self) -> Option<Self> {
        if !self.includes_project_sources() {
            return None;
        }
        let mut scope = self.clone();
        scope.filters.roots.push(PathBuf::from("."));
        Some(scope)
    }
}
