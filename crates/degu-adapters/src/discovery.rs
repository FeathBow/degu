//! Shared scoped-root discovery for build artifacts and checkpoints.
//!
//! One traversal claims whole-directory findings without descending, so byte attribution stays unique.
//! The caller resolves claim paths; scoped roots are canonical and symlinks are never followed.

#[cfg(test)]
mod tests;
mod traversal;

use self::traversal::{RootDiscovery, RootScope};
use degu_core::ecosystem::{DetectCtx, ScanOutcome, ScanPriority};
use degu_core::safety::ProtectionPolicy;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub struct DiscoveryScope<'a> {
    pub claimed_roots: &'a [PathBuf],
    pub dependency_claims: &'a [PathBuf],
    pub sources: ProjectSources,
}

#[derive(Clone, Copy)]
pub struct ProjectSources {
    artifacts: bool,
    checkpoints: bool,
}

impl ProjectSources {
    pub const fn new(artifacts: bool, checkpoints: bool) -> Self {
        Self {
            artifacts,
            checkpoints,
        }
    }

    pub const fn scan_priority(self) -> ScanPriority {
        if self.artifacts {
            ScanPriority::Preferred
        } else {
            ScanPriority::Deferred
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ValidatedProjectRoot(PathBuf);

pub struct ResolvedProjectRoot {
    requested: PathBuf,
    canonical: PathBuf,
}

impl ResolvedProjectRoot {
    pub fn resolve(path: &Path) -> std::io::Result<Self> {
        let canonical = std::fs::canonicalize(path)
            .map_err(|err| path_error("failed to access project root", path, err))?;
        Ok(Self {
            requested: path.to_path_buf(),
            canonical,
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.canonical
    }

    pub fn validate(self) -> std::io::Result<ValidatedProjectRoot> {
        let metadata = std::fs::symlink_metadata(&self.canonical)
            .map_err(|err| path_error("failed to inspect project root", &self.requested, err))?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "project root is not a directory: {}",
                    self.requested.display()
                ),
            ));
        }
        std::fs::read_dir(&self.canonical)
            .map_err(|err| path_error("failed to scan project root", &self.requested, err))?;
        Ok(ValidatedProjectRoot(self.canonical))
    }
}

impl ValidatedProjectRoot {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

pub fn discover(
    roots: &[ValidatedProjectRoot],
    discovery: DiscoveryScope<'_>,
    ctx: &DetectCtx,
) -> std::io::Result<ScanOutcome> {
    if roots.is_empty() {
        return Ok(ScanOutcome::default());
    }
    if ctx.deadline_elapsed() {
        return Ok(ScanOutcome::truncated());
    }
    let protection =
        ProtectionPolicy::for_mixed_state_ai(&ctx.home).map_err(std::io::Error::other)?;
    let mut outcome = ScanOutcome::default();
    let scope = RootScope {
        discovery,
        ctx,
        protection: &protection,
    };
    for root in roots {
        if ctx.deadline_elapsed() {
            outcome.mark_truncated();
            break;
        }
        let root_outcome = RootDiscovery::new(root.as_path(), scope).run();
        let truncated = root_outcome.truncated;
        outcome.merge(root_outcome);
        if truncated {
            break;
        }
    }
    Ok(outcome)
}

fn read_entries(path: &Path) -> std::io::Result<std::fs::ReadDir> {
    std::fs::read_dir(path).map_err(|err| path_error("failed to read directory", path, err))
}

fn path_error(action: &str, path: &Path, source: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        source.kind(),
        format!("{action} {}: {source}", path.display()),
    )
}
