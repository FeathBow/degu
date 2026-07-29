use std::io;
use std::path::{Path, PathBuf};

use degu_core::oplog::ObjectIdentity;

use crate::lifecycle::trash::Trash;

use super::plan::PlannedTrashEntry;
use crate::lifecycle::claims::{MAX_CLAIM_ATTEMPTS, prepare_claims_dir};
use crate::lifecycle::identity::{EntryIdentity, RenameFailure, capture_parent_following};

const CLAIM_RANDOM_BYTES: usize = 16;

#[derive(Debug)]
pub(super) struct ClaimedTrashEntry {
    original: PathBuf,
    claimed: PathBuf,
    identity: EntryIdentity,
    /// Identity of the directory the claim must be restored into (the trash
    /// root), captured through ancestor symlinks before the claim rename so a
    /// later rollback cannot be diverted by an ancestor-symlink swap.
    original_parent: ObjectIdentity,
}

#[derive(Debug)]
pub(super) struct LocatedFailure {
    path: PathBuf,
    error: io::Error,
    location: FailureLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureLocation {
    Source,
    UnauthenticatedParent,
    UnverifiedDestination,
    Current,
}

#[derive(Debug)]
pub(super) struct ClaimFailure {
    path: PathBuf,
    error: io::Error,
    identity_changed: bool,
}

impl LocatedFailure {
    pub(super) fn new(path: PathBuf, error: io::Error) -> Self {
        Self::at(path, error, FailureLocation::Current)
    }

    fn at(path: PathBuf, error: io::Error, location: FailureLocation) -> Self {
        Self {
            path,
            error,
            location,
        }
    }

    fn from_rename(source: &Path, failure: RenameFailure) -> Self {
        match failure {
            RenameFailure::Source(error) => {
                Self::at(source.to_path_buf(), error, FailureLocation::Source)
            }
            RenameFailure::UnauthenticatedParent { parent, error } => {
                Self::at(parent, error, FailureLocation::UnauthenticatedParent)
            }
            RenameFailure::UnverifiedDestination { destination, error } => {
                Self::at(destination, error, FailureLocation::UnverifiedDestination)
            }
        }
    }

    pub(super) fn into_parts(self) -> (PathBuf, io::Error, FailureLocation) {
        (self.path, self.error, self.location)
    }
}

impl ClaimFailure {
    fn setup(path: PathBuf, error: io::Error) -> Self {
        Self {
            path,
            error,
            identity_changed: false,
        }
    }

    pub(super) fn from_rename(source: &Path, failure: RenameFailure) -> Self {
        match failure {
            RenameFailure::Source(error) => Self {
                path: source.to_path_buf(),
                identity_changed: error.kind() == io::ErrorKind::InvalidData,
                error,
            },
            RenameFailure::UnauthenticatedParent { parent, error } => Self {
                path: parent,
                error,
                identity_changed: true,
            },
            RenameFailure::UnverifiedDestination { destination, error } => Self {
                path: destination,
                error,
                identity_changed: true,
            },
        }
    }

    pub(super) fn into_parts(self) -> (PathBuf, io::Error, bool) {
        (self.path, self.error, self.identity_changed)
    }
}

impl ClaimedTrashEntry {
    pub(super) fn acquire(
        entry: PlannedTrashEntry,
        trash_root: &Path,
    ) -> Result<Self, ClaimFailure> {
        let (original, identity) = entry.into_parts();
        validate_before_claim(&original, &identity)?;
        // Snapshot the restore-destination directory (the trash root) BEFORE the
        // claim rename, while the entry and its parent are present. The rollback
        // check uses `Stable` (device+inode+kind), which the claim rename does
        // not change, so a pre-claim capture authenticates the same directory a
        // rollback will find; capturing after the claim could strand the entry if
        // the capture failed once the claim rename had already run.
        let original_parent = capture_original_parent(&original)?;
        let claims = prepare_claims_dir(trash_root)
            .map_err(|error| ClaimFailure::setup(original.clone(), error))?;
        for _ in 0..MAX_CLAIM_ATTEMPTS {
            let claimed = next_claim_path(&claims)
                .map_err(|error| ClaimFailure::setup(original.clone(), error))?;
            match identity.rename_verified_located(&original, &claimed) {
                Ok(claimed_identity) => {
                    return Ok(Self {
                        original,
                        claimed,
                        identity: claimed_identity,
                        original_parent,
                    });
                }
                Err(RenameFailure::Source(error))
                    if error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) => return Err(ClaimFailure::from_rename(&original, error)),
            }
        }
        Err(ClaimFailure::setup(
            original,
            io::Error::new(io::ErrorKind::AlreadyExists, "purge claim names exhausted"),
        ))
    }

    pub(super) fn original(&self) -> &Path {
        &self.original
    }

    pub(super) fn purge(self) -> Result<(), LocatedFailure> {
        let Some(parent) = self.claimed.parent() else {
            return Err(LocatedFailure::new(
                self.claimed.clone(),
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("purge claim has no parent: {}", self.claimed.display()),
                ),
            ));
        };
        let trash = Trash::new(parent.to_path_buf());
        match trash.purge_entry_verified(&self.claimed, self.identity.oplog_identity()) {
            Ok(()) => Ok(()),
            Err(error) => self.restore_with_error(&format!("permanent deletion failed: {error}")),
        }
    }

    pub(super) fn restore(self) -> Result<(), LocatedFailure> {
        self.identity
            .rename_verified_into_parent(&self.claimed, &self.original, self.original_parent)
            .map(|_| ())
            .map_err(|error| LocatedFailure::from_rename(&self.claimed, error))
    }

    fn restore_with_error(self, reason: &str) -> Result<(), LocatedFailure> {
        match self.identity.rename_verified_into_parent(
            &self.claimed,
            &self.original,
            self.original_parent,
        ) {
            Ok(_) => Err(LocatedFailure::new(
                self.original.clone(),
                io::Error::other(format!(
                    "{reason}; the entry was restored to {}",
                    self.original.display()
                )),
            )),
            Err(error) => {
                let failure = LocatedFailure::from_rename(&self.claimed, error);
                let (path, error, location) = failure.into_parts();
                let detail = match location {
                    FailureLocation::Source => "restore did not complete; inspect the claim source",
                    FailureLocation::UnauthenticatedParent => {
                        "restore refused because the destination parent could not be authenticated; \
                         the purge claim was not moved"
                    }
                    FailureLocation::UnverifiedDestination => {
                        "restore could not be verified; inspect the unverified destination"
                    }
                    FailureLocation::Current => "inspect the current entry",
                };
                Err(LocatedFailure::at(
                    path.clone(),
                    io::Error::new(
                        error.kind(),
                        format!("{reason}; {detail} at {}: {error}", path.display()),
                    ),
                    location,
                ))
            }
        }
    }
}

fn validate_before_claim(original: &Path, identity: &EntryIdentity) -> Result<(), ClaimFailure> {
    match identity.matches(original) {
        Ok(true) => {}
        Ok(false) => {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "entry identity changed before mount safety validation: {}",
                    original.display()
                ),
            );
            return Err(ClaimFailure::from_rename(
                original,
                RenameFailure::Source(error),
            ));
        }
        Err(error) => return Err(ClaimFailure::setup(original.to_path_buf(), error)),
    }
    degu_walk::validate_single_mount_tree(original).map_err(|error| {
        ClaimFailure::setup(
            original.to_path_buf(),
            io::Error::new(
                error.kind(),
                format!("mount safety validation failed before purge claim: {error}"),
            ),
        )
    })
}

fn capture_original_parent(original: &Path) -> Result<ObjectIdentity, ClaimFailure> {
    let parent = original
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            ClaimFailure::setup(
                original.to_path_buf(),
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "trash entry has no parent directory: {}",
                        original.display()
                    ),
                ),
            )
        })?;
    capture_parent_following(parent)
        .map_err(|error| ClaimFailure::setup(original.to_path_buf(), error))
}

fn next_claim_path(claims: &Path) -> io::Result<PathBuf> {
    let mut random = [0_u8; CLAIM_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let token = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(claims.join(format!("purge-{token}")))
}

#[cfg(test)]
mod tests {
    use super::{ClaimedTrashEntry, FailureLocation};
    use crate::lifecycle::claims::interrupted_purge_claims;
    use crate::lifecycle::purge::plan::PlannedTrashEntry;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn claimed_entry_replacement_is_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let trash_root = dir.path().join("trash");
        std::fs::create_dir(&trash_root).unwrap();
        let entry = trash_root.join("0001-cache");
        std::fs::write(&entry, "planned").unwrap();
        let planned = PlannedTrashEntry::capture(entry).unwrap();
        let claimed = ClaimedTrashEntry::acquire(planned, &trash_root).unwrap();
        let claim_path = claimed.claimed.clone();
        let planned_path = trash_root.join("planned-moved-by-concurrent-process");
        std::fs::rename(&claim_path, &planned_path).unwrap();
        std::fs::write(&claim_path, "replacement").unwrap();

        let error = claimed.purge().unwrap_err();
        let (actual, error, location) = error.into_parts();

        assert!(error.to_string().contains("identity changed"));
        assert_eq!(actual, claim_path);
        assert_eq!(location, FailureLocation::Source);
        assert_eq!(std::fs::read_to_string(claim_path).unwrap(), "replacement");
        assert_eq!(std::fs::read_to_string(planned_path).unwrap(), "planned");
    }

    #[test]
    fn repeated_crash_leaves_the_new_claim_discoverable() {
        let dir = tempfile::tempdir().unwrap();
        let trash_root = dir.path().join("trash");
        let claims = trash_root.join(".claims");
        std::fs::create_dir_all(&claims).unwrap();
        std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
        let interrupted = claims.join("purge-old");
        std::fs::write(&interrupted, "cache").unwrap();
        let planned = PlannedTrashEntry::capture(interrupted.clone()).unwrap();

        let claimed = ClaimedTrashEntry::acquire(planned, &trash_root).unwrap();
        let moved = claimed.claimed.clone();
        drop(claimed);

        assert!(!interrupted.exists());
        assert_eq!(std::fs::read_to_string(&moved).unwrap(), "cache");
        assert_eq!(interrupted_purge_claims(&trash_root).unwrap(), vec![moved]);
    }
}
