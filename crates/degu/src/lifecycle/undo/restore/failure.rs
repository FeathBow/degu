use std::io;
use std::path::{Path, PathBuf};

use crate::lifecycle::identity::RenameFailure;

#[derive(Debug)]
pub(super) enum RestoreFailure {
    AtTrashSource {
        path: PathBuf,
        error: io::Error,
    },
    UnauthenticatedParent {
        original: PathBuf,
        trash_entry: PathBuf,
    },
    UnverifiedParent {
        parent: PathBuf,
        error: io::Error,
    },
    UnverifiedOriginal {
        path: PathBuf,
        error: io::Error,
    },
}

impl RestoreFailure {
    pub(super) fn at_trash_source(path: &Path, error: io::Error) -> Self {
        Self::AtTrashSource {
            path: path.to_path_buf(),
            error: normalize_restore_error(error),
        }
    }

    pub(super) fn unauthenticated_parent(original: &Path, trash_entry: &Path) -> Self {
        Self::UnauthenticatedParent {
            original: original.to_path_buf(),
            trash_entry: trash_entry.to_path_buf(),
        }
    }

    pub(super) fn from_rename(trash_entry: &Path, failure: RenameFailure) -> Self {
        match failure {
            RenameFailure::Source(error) => Self::at_trash_source(trash_entry, error),
            RenameFailure::UnauthenticatedParent { parent, error } => {
                Self::UnverifiedParent { parent, error }
            }
            RenameFailure::UnverifiedDestination { destination, error } => {
                Self::UnverifiedOriginal {
                    path: destination,
                    error,
                }
            }
        }
    }

    pub(super) fn reason(&self) -> String {
        match self {
            Self::AtTrashSource { path, error } => {
                format!(
                    "restore did not complete; inspect the trash source at {}: {error}",
                    path.display()
                )
            }
            Self::UnauthenticatedParent {
                original,
                trash_entry,
            } => format!(
                "restore refused: this trash entry predates destination-parent verification, \
                 so the parent of {} cannot be authenticated against an ancestor-symlink swap; \
                 the trash entry at {} is intact, restore it manually with \
                 `mv {} {}`",
                original.display(),
                trash_entry.display(),
                trash_entry.display(),
                original.display()
            ),
            Self::UnverifiedParent { parent, error } => format!(
                "restore refused: the destination parent {} could not be authenticated; \
                 the trash entry is intact and nothing was moved: {error}",
                parent.display()
            ),
            Self::UnverifiedOriginal { path, error } => format!(
                "restore could not be verified; inspect the unverified original path at {}: {error}",
                path.display()
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        match self {
            Self::AtTrashSource { path, .. } | Self::UnverifiedOriginal { path, .. } => path,
            Self::UnverifiedParent { parent, .. } => parent,
            Self::UnauthenticatedParent { original, .. } => original,
        }
    }
}

fn normalize_restore_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::AlreadyExists {
        io::Error::new(error.kind(), "restore target already exists")
    } else {
        error
    }
}
