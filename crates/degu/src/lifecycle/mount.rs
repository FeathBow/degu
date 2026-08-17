//! Reopen mount-domain recovery anchors from WAL metadata; pathnames obtain FDs
//! but never replace the core's fresh mount, backend, locator, and identity checks.

use degu_core::seal_wal::StagingTransactionMetadata;
use degu_core::sealed_staging::{ProductionStagingEntry, StartupRecoveryAnchors};
use rustix::fd::OwnedFd;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn metadata_anchors(
    home: &Path,
    metadata: &StagingTransactionMetadata,
) -> io::Result<StartupRecoveryAnchors> {
    open_pair(&anchor_path(home, metadata.recovery_anchor())?)
}

pub(super) fn entry_anchor(home: &Path, entry: &ProductionStagingEntry) -> io::Result<PathBuf> {
    anchor_path(home, entry.recovery_anchor())
}

pub(super) fn open_pair(path: &Path) -> io::Result<StartupRecoveryAnchors> {
    let (source, destination) = open_pair_fds(path)?;
    Ok(StartupRecoveryAnchors::new(source, destination))
}

pub(super) fn open_pair_fds(path: &Path) -> io::Result<(OwnedFd, OwnedFd)> {
    let source = degu_walk::resolve_trusted_directory(path, "sealed-staging recovery anchor")?;
    let destination = rustix::io::dup(&source).map_err(io::Error::from)?;
    Ok((source, destination))
}

fn anchor_path(home: &Path, recorded: Option<&Path>) -> io::Result<PathBuf> {
    match recorded {
        Some(path) => Ok(path.to_path_buf()),
        None => std::fs::canonicalize(home),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_mount_anchor_wins_over_missing_or_changed_home() {
        let recorded = tempfile::tempdir().unwrap();
        let path = recorded.path().canonicalize().unwrap();
        assert_eq!(
            anchor_path(Path::new("/missing/home"), Some(&path)).unwrap(),
            path
        );
    }

    #[test]
    fn legacy_metadata_keeps_the_canonical_home_recovery_arm() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            anchor_path(home.path(), None).unwrap(),
            home.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn trusted_mount_anchor_opens_two_descriptors_for_core_revalidation() {
        let anchor = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            anchor.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let anchor = anchor.path().canonicalize().unwrap();
        let (source, destination) = open_pair_fds(&anchor).unwrap();
        let source = rustix::fs::fstat(&source).unwrap();
        let destination = rustix::fs::fstat(&destination).unwrap();
        assert_eq!(
            (source.st_dev, source.st_ino),
            (destination.st_dev, destination.st_ino)
        );
    }
}
