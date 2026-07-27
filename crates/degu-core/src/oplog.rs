use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One write-ahead intent or final outcome in the append-only operation history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpRecord {
    /// RFC3339 timestamp supplied by the application.
    pub ts: String,
    pub tool_version: String,
    /// Logical command name, such as `clean` or `trash purge`.
    pub command: String,
    pub action: OpAction,
    pub path: PathBuf,
    pub bytes_allocated: u64,
    pub inodes: u64,
    /// Trash path involved in a staged mutation; None when no trash path exists.
    pub trash_entry: Option<PathBuf>,
    /// Groups records associated with one reclamation; None for legacy or
    /// unassociated records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclamation_id: Option<String>,
    /// Object identity used to reconcile this record with filesystem state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_identity: Option<ObjectIdentity>,
    /// Identity of the directory that must hold the restored entry, resolved
    /// through ancestor symlinks at stage time. Absent on legacy records, which
    /// restore refuses because the destination parent cannot be authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_parent: Option<ObjectIdentity>,
    pub outcome: OpOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub kind: ObjectKind,
    pub device: u64,
    pub inode: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Directory,
    File,
    Symlink,
    Other,
}

impl ObjectIdentity {
    pub fn capture(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(Self::from_metadata(&metadata))
    }

    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            ObjectKind::Directory
        } else if file_type.is_file() {
            ObjectKind::File
        } else if file_type.is_symlink() {
            ObjectKind::Symlink
        } else {
            ObjectKind::Other
        };
        Self {
            kind,
            device: metadata.dev(),
            inode: metadata.ino(),
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
        }
    }

    pub fn same_object(&self, other: &Self) -> bool {
        self.kind == other.kind && self.device == other.device && self.inode == other.inode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpAction {
    Trash,
    Purge,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    Pending,
    Ok,
    Failed { reason: String },
}

/// Filesystem-derived state of a pending rename whose final record never
/// made it into the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    /// Source gone, destination present: the rename completed.
    Moved,
    /// Source present, destination gone: the rename never happened.
    NotMoved,
    /// Both paths exist, so the rename outcome cannot be inferred.
    AmbiguousBothExist,
    /// Both paths are missing, so the rename outcome cannot be inferred.
    AmbiguousBothMissing,
    /// The recorded identity was absent, could not be probed, or no longer
    /// matches the object at its inferred location.
    AmbiguousIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingProbe {
    Missing,
    Present(ObjectIdentity),
    Failed,
}

pub fn reconcile_pending_move(
    source: PendingProbe,
    destination: PendingProbe,
    expected: Option<ObjectIdentity>,
) -> PendingState {
    let probes = PendingMoveProbes {
        source,
        destination,
        expected,
    };
    probes.verify_identity(probes.infer_layout())
}

#[derive(Clone, Copy)]
struct PendingMoveProbes {
    source: PendingProbe,
    destination: PendingProbe,
    expected: Option<ObjectIdentity>,
}

impl PendingMoveProbes {
    fn infer_layout(self) -> PendingState {
        match (self.source.exists(), self.destination.exists()) {
            (Some(false), Some(true)) => PendingState::Moved,
            (Some(true), Some(false)) => PendingState::NotMoved,
            (Some(true), Some(true)) => PendingState::AmbiguousBothExist,
            (Some(false), Some(false)) => PendingState::AmbiguousBothMissing,
            _ => PendingState::AmbiguousIdentity,
        }
    }

    fn verify_identity(self, state: PendingState) -> PendingState {
        match (state, self.source, self.destination, self.expected) {
            (PendingState::Moved, _, PendingProbe::Present(actual), Some(expected))
                if expected.same_object(&actual) =>
            {
                state
            }
            (PendingState::NotMoved, PendingProbe::Present(actual), _, Some(expected))
                if expected == actual =>
            {
                state
            }
            (PendingState::Moved | PendingState::NotMoved, _, _, _) => {
                PendingState::AmbiguousIdentity
            }
            _ => state,
        }
    }
}

impl PendingProbe {
    fn exists(self) -> Option<bool> {
        match self {
            Self::Missing => Some(false),
            Self::Present(_) => Some(true),
            Self::Failed => None,
        }
    }
}

#[cfg(test)]
mod tests;
