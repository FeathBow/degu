//! degu-core — domain model and safety kernel.
//!
//! Two non-negotiable architectural rules:
//! 1. Adapters (degu-adapters) only produce [`finding::FindingCandidate`] values and
//!    are not given degu's verified deletion interface. Only finalized findings can
//!    enter a clean [`plan::Plan`], and mutation stays inside the private lifecycle.
//! 2. When [`safety::Guard`] hits a protected path it **rejects the whole
//!    plan**, never skips the item — silent skipping hides planner bugs.

pub mod authority;
pub mod config;
pub mod disposition;
pub mod ecosystem;
pub mod finding;
pub mod local_backend;
pub mod oplog;
pub mod plan;
pub mod safety;
pub mod seal_executor;
pub mod seal_store;
pub mod seal_wal;
pub mod sealed_staging;

#[cfg(test)]
pub(crate) fn secure_test_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(temp)
}
