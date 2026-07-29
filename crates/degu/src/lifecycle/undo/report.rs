use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct UndoEntry {
    pub(crate) path: PathBuf,
    pub(crate) trash_entry: PathBuf,
}

#[derive(Debug)]
pub(crate) struct UndoAmbiguousEntry {
    pub(crate) path: PathBuf,
    pub(crate) trash_entry: PathBuf,
    pub(crate) reclamation_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct UndoFailedEntry {
    pub(crate) path: PathBuf,
    pub(crate) trash_entry: PathBuf,
    pub(crate) reason: String,
}

#[derive(Debug)]
pub(crate) struct UndoLogFailure {
    pub(crate) path: PathBuf,
    pub(crate) trash_entry: PathBuf,
    pub(crate) reason: String,
    pub(crate) restored: bool,
}

#[derive(Debug)]
pub(crate) struct UndoReport {
    pub(crate) reclamation_id: Option<String>,
    pub(crate) restored: Vec<UndoEntry>,
    pub(crate) failed: Vec<UndoFailedEntry>,
    pub(crate) log_failures: Vec<UndoLogFailure>,
    pub(crate) gone: Vec<UndoEntry>,
    pub(crate) ambiguous: Vec<UndoAmbiguousEntry>,
}

impl UndoReport {
    pub(crate) fn new(reclamation_id: Option<String>) -> Self {
        Self {
            reclamation_id,
            restored: Vec::new(),
            failed: Vec::new(),
            log_failures: Vec::new(),
            gone: Vec::new(),
            ambiguous: Vec::new(),
        }
    }

    pub(crate) fn ambiguous_entries(&self) -> impl Iterator<Item = &UndoAmbiguousEntry> {
        self.ambiguous.iter()
    }

    pub(crate) fn has_ambiguity(&self) -> bool {
        !self.ambiguous.is_empty()
    }

    pub(crate) fn failure_count(&self) -> usize {
        self.failed.len().saturating_add(
            self.log_failures
                .iter()
                .filter(|failure| failure.restored)
                .count(),
        )
    }

    pub(crate) fn has_failures(&self) -> bool {
        !self.failed.is_empty() || !self.log_failures.is_empty()
    }
}
