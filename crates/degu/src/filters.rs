use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub(crate) struct Filters {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) only: Vec<String>,
}
