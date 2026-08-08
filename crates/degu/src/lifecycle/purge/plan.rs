use std::io;
use std::path::{Path, PathBuf};

use super::super::identity::EntryIdentity;

pub(crate) struct ExpiryPlan {
    pub(super) batches: Vec<PurgePlanBatch<PlannedTrashEntry>>,
}

pub(crate) struct TrashPurgePlan {
    pub(super) batches: Vec<PurgePlanBatch<PlannedTrashEntry>>,
}

pub(super) struct PurgePlanBatch<T> {
    pub(super) trash_root: PathBuf,
    pub(super) entries: Vec<T>,
}

#[derive(Clone)]
pub(crate) struct PlannedTrashEntry {
    path: PathBuf,
    identity: EntryIdentity,
}

impl ExpiryPlan {
    pub(crate) fn trash_roots(&self) -> impl Iterator<Item = &Path> {
        self.batches.iter().map(|batch| batch.trash_root.as_path())
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = &Path> {
        self.batches
            .iter()
            .flat_map(|batch| &batch.entries)
            .map(PlannedTrashEntry::path)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    /// Even an entry-empty batch may purge aged numeric claim markers.
    pub(crate) fn has_housekeeping_scope(&self) -> bool {
        !self.batches.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        batch_entry_count(&self.batches)
    }
}

impl TrashPurgePlan {
    pub(crate) fn trash_roots(&self) -> impl Iterator<Item = &Path> {
        self.batches.iter().map(|batch| batch.trash_root.as_path())
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = &Path> {
        self.batches
            .iter()
            .flat_map(|batch| &batch.entries)
            .map(PlannedTrashEntry::path)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Even an entry-empty batch may purge aged numeric claim markers.
    pub(crate) fn has_housekeeping_scope(&self) -> bool {
        !self.batches.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        batch_entry_count(&self.batches)
    }
}

fn batch_entry_count<T>(batches: &[PurgePlanBatch<T>]) -> usize {
    batches.iter().fold(0usize, |total, batch| {
        total.saturating_add(batch.entries.len())
    })
}

impl PlannedTrashEntry {
    pub(super) fn capture(path: PathBuf) -> io::Result<Self> {
        let identity = EntryIdentity::capture(&path)?;
        Ok(Self { path, identity })
    }

    pub(crate) fn new(path: PathBuf, identity: EntryIdentity) -> Self {
        Self { path, identity }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn into_parts(self) -> (PathBuf, EntryIdentity) {
        (self.path, self.identity)
    }
}
