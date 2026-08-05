//! degu-walk — read-only filesystem inspection engine.
//!
//! Hard constraint: be gentle on network filesystems (Lustre/GPFS) — bounded
//! concurrency, minimal metadata requests, because a heavy scan can overload a
//! shared metadata server. When speed and gentleness conflict, gentleness wins.

mod accounting;
mod fstype;
mod metadata;
pub mod mount;
mod mutation_guard;
mod safe_read;
mod walker;

pub use mutation_guard::{
    directory_grants_foreign_mutation, find_named_entry_single_mount,
    reject_protected_in_owned_single_mount_tree, validate_owned_single_mount_tree,
    validate_single_mount_tree, validate_trusted_parent_namespace,
};
pub use safe_read::{
    CappedBytes, open_regular_capped, open_regular_capped_nofollow, read_regular_capped,
    read_regular_capped_nofollow,
};
pub use walker::measure;

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Heartbeat {
    last: Mutex<Instant>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl Heartbeat {
    fn new(now: Instant) -> Self {
        Self {
            last: Mutex::new(now),
        }
    }

    fn due_at(&self, now: Instant) -> bool {
        let mut last = self.last.lock().expect("walk heartbeat lock poisoned");
        if now.duration_since(*last) < HEARTBEAT_INTERVAL {
            return false;
        }
        *last = now;
        true
    }
}

#[derive(Debug, Default)]
pub struct Progress {
    inodes: AtomicU64,
    bytes_allocated: AtomicU64,
    stat_ops: AtomicU64,
    readdir_ops: AtomicU64,
    heartbeat: Heartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressSnapshot {
    pub inodes: u64,
    pub bytes_allocated: u64,
    pub stat_ops: u64,
    pub readdir_ops: u64,
}

impl Progress {
    pub fn add_resources(&self, inodes: u64, bytes_allocated: u64) {
        saturating_atomic_add(&self.inodes, inodes);
        saturating_atomic_add(&self.bytes_allocated, bytes_allocated);
    }

    pub fn add_stat_op(&self) {
        saturating_atomic_add(&self.stat_ops, 1);
    }

    pub fn add_readdir_op(&self) {
        saturating_atomic_add(&self.readdir_ops, 1);
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            inodes: self.inodes.load(Ordering::Relaxed),
            bytes_allocated: self.bytes_allocated.load(Ordering::Relaxed),
            stat_ops: self.stat_ops.load(Ordering::Relaxed),
            readdir_ops: self.readdir_ops.load(Ordering::Relaxed),
        }
    }
}

fn saturating_atomic_add(counter: &AtomicU64, value: u64) {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        })
        .expect("saturating atomic update always succeeds");
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WalkStats {
    pub dirs: u64,
    pub files: u64,
    /// Sum of logical sizes (what `ls -l` shows)
    pub bytes_apparent: u64,
    /// Sum of allocated-block estimates from `st_blocks × 512`.
    pub bytes_allocated: u64,
    /// Sum of allocated bytes for files with more than one hardlink.
    pub bytes_hardlinked: u64,
    /// Newest modification time across files only.
    pub newest_mtime: Option<SystemTime>,
    pub inodes: u64,
    pub stat_ops: u64,
    pub readdir_ops: u64,
    pub skipped_total: u64,
    pub truncated: bool,
    pub unvisited_dirs: u64,
    /// Directories writable by group or other. They remain measured, but a
    /// caller granting cleanup authority must treat the tree as shared.
    pub shared_writable_dirs: u64,
    /// Entries excluded by an explicit name boundary in [`WalkOptions`].
    pub excluded_entries: u64,
    /// Subset of `excluded_entries` whose name is a protected credential
    /// directory, so a demotion can name the honest reason.
    pub excluded_credential_boundaries: u64,
    /// Bounded sample of skipped paths. Use `skipped_total` for counts.
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Upper bound on concurrent directory reads; None selects per-filesystem auto.
    pub max_concurrency: Option<NonZeroUsize>,
    /// Stay on one filesystem, so a $HOME scan never wanders into a mounted
    /// scratch or NFS tree
    pub one_filesystem: bool,
    /// Account only entries owned by this UID. A mismatched entry is recorded
    /// as skipped, and a mismatched directory is never descended into.
    pub required_uid: Option<u32>,
    /// Cross-root progress counters; the heartbeat lives here too, so multi-root
    /// scans must share one instance or fast roots never emit a heartbeat.
    pub progress: Option<std::sync::Arc<Progress>>,
    /// Absolute wall-clock deadline shared by all roots in one CLI scan.
    pub deadline: Option<Instant>,
    /// Exact entry names to record and exclude without descending into them.
    pub excluded_entry_names: &'static [&'static str],
    /// Subset of `excluded_entry_names` that denotes a protected credential
    /// directory, counted separately so a demotion reason stays honest.
    pub credential_entry_names: &'static [&'static str],
    /// Unit-test-only metadata injection: exercises mixed-UID descendant
    /// handling without privileged chown and never enters the public build.
    #[cfg(test)]
    pub(crate) uid_overrides: Option<std::sync::Arc<std::collections::HashMap<PathBuf, u32>>>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_concurrency: None,
            one_filesystem: true,
            required_uid: None,
            progress: None,
            deadline: None,
            excluded_entry_names: &[],
            credential_entry_names: &[],
            #[cfg(test)]
            uid_overrides: None,
        }
    }
}

#[cfg(test)]
mod tests;
