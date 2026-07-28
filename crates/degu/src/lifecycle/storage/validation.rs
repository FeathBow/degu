use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const SHARED_WRITE_MASK: u32 = 0o022;
const STICKY_BIT: u32 = 0o1000;

/// A validated trash root: the lexical path as configured, kept for display, and
/// the canonicalized path, used to fold lexical aliases of one directory onto a
/// single identity so its entries are never counted twice.
pub(super) struct ValidatedTrashRoot {
    pub(super) lexical: PathBuf,
    pub(super) canonical: PathBuf,
}

pub(super) fn validate_existing_trash_root(
    root: &Path,
    expected_name: &str,
) -> Result<Option<ValidatedTrashRoot>> {
    validate_root_name(root, expected_name)?;
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", root.display()));
        }
    };
    validate_root_metadata(root, &metadata)?;
    let canonical = std::fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize trash root {}", root.display()))?;
    validate_root_name(&canonical, expected_name)?;
    let parent = root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("trash root has no parent: {}", root.display()))?;
    validate_trash_parent(parent)?;
    Ok(Some(ValidatedTrashRoot {
        lexical: root.to_path_buf(),
        canonical,
    }))
}

fn validate_root_name(root: &Path, expected_name: &str) -> Result<()> {
    if root.file_name() != Some(OsStr::new(expected_name)) {
        anyhow::bail!(
            "trash root has an unexpected name (expected {expected_name}): {}",
            root.display()
        );
    }
    Ok(())
}

fn validate_root_metadata(root: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("trash root is not a real directory: {}", root.display());
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        anyhow::bail!(
            "trash root is not owned by the effective user: {}",
            root.display()
        );
    }
    if metadata.mode() & SHARED_WRITE_MASK != 0 {
        anyhow::bail!("trash root is group- or world-writable: {}", root.display());
    }
    Ok(())
}

fn validate_trash_parent(parent: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect trash parent {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("trash parent is not a real directory: {}", parent.display());
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        anyhow::bail!(
            "trash parent is not owned by the effective user: {}",
            parent.display()
        );
    }
    let shared_writable = metadata.mode() & SHARED_WRITE_MASK != 0;
    if shared_writable && metadata.mode() & STICKY_BIT == 0 {
        anyhow::bail!(
            "trash parent is group- or world-writable without the sticky bit: {}",
            parent.display()
        );
    }
    Ok(())
}
