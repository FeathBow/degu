use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub(crate) struct Filters {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) only: Vec<String>,
    pub(crate) older_than: Option<u64>,
    pub(crate) min_size: Option<u64>,
    pub(crate) top: Option<usize>,
}
