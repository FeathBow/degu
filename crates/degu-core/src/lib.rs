//! degu-core — domain model and safety kernel.
//!
//! Two non-negotiable architectural rules:
//! 1. Adapters (degu-adapters) only produce [`finding::FindingCandidate`] values and
//!    are not given degu's verified deletion interface. Only finalized findings can
//!    enter a clean [`plan::Plan`], and mutation stays inside the private lifecycle.
//! 2. When [`safety::Guard`] hits a protected path it **rejects the whole
//!    plan**, never skips the item — silent skipping hides planner bugs.

pub mod activation;
mod admission;
pub mod authority;
pub mod backend;
pub mod config;
pub mod disposition;
pub mod ecosystem;
pub mod finding;
pub mod oplog;
pub mod plan;
pub mod provision;
pub mod safety;
pub mod seal;
pub mod staging;
/// Bounded invocation of a program the account already trusts, for facts and
/// text no syscall returns. The account database behind Linux's name service
/// switch forced it; the advisory an interactive review can show is the other
/// caller, and that one exists on every platform.
pub mod system_tool;

/// An in-memory WAL writer for fixtures that need a large frame sequence.
/// Driving one through a real store would fsync twice per record, which turns a
/// megabyte-scale fixture into minutes.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryWal {
    pub(crate) bytes: Vec<u8>,
}

#[cfg(test)]
impl std::io::Write for MemoryWal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl crate::seal::wal::DurableWrite for MemoryWal {
    fn sync_record(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn prepare_append(&mut self) -> std::io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
}

/// Overwrites a store's WAL with an exact frame sequence built in memory.
#[cfg(test)]
pub(crate) fn overwrite_test_wal(root: &std::path::Path, bytes: &[u8]) -> u64 {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(root.join(crate::seal::store::WAL_FILE_NAME))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    bytes.len() as u64
}

#[cfg(test)]
pub(crate) fn secure_test_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(temp)
}
