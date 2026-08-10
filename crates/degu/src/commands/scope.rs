use crate::cli::{CleanArgs, ScanArgs};
use crate::findings::Filters;
use crate::selection::{clean_only_ids, project_sources_selected};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct ScanScope {
    pub(super) filters: Filters,
    pub(super) runtime: bool,
}

impl ScanScope {
    pub(super) fn empty() -> Self {
        Self {
            filters: Filters::default(),
            runtime: false,
        }
    }

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

    pub(super) fn clean_scope(&self) -> CleanScope {
        let mut filters = self.filters.clone();
        filters.only = clean_only_ids(&filters.only);
        CleanScope {
            filters,
            paths: Vec::new(),
            include_review: false,
        }
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

#[derive(Clone, Debug)]
pub(crate) struct CleanScope {
    pub(super) filters: Filters,
    pub(super) paths: Vec<PathBuf>,
    pub(super) include_review: bool,
}

impl CleanScope {
    pub(crate) fn from_args(args: &CleanArgs) -> Self {
        Self {
            filters: Filters {
                roots: args.roots.clone(),
                only: args.only.clone(),
                older_than: args.older_than,
                min_size: args.min_size,
                top: args.top,
            },
            paths: args.path.clone(),
            include_review: args.include_review,
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

    pub(crate) fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    pub(crate) fn include_review(&self) -> bool {
        self.include_review
    }

    pub(crate) fn has_paths(&self) -> bool {
        !self.paths.is_empty()
    }

    pub(super) fn for_review_path(&self, path: &Path) -> Self {
        Self {
            paths: vec![path.to_path_buf()],
            include_review: true,
            ..self.clone()
        }
    }
}
