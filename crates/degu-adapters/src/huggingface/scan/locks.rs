use degu_core::ecosystem::DetectCtx;
use rustix::fs::{FlockOperation, flock};
use std::fs::{self, DirEntry};
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) enum LockProbe {
    Clear,
    Busy,
    Failed,
    Deadline,
}

pub(super) fn repo_lock_status(root: &Path, name: &str, ctx: &DetectCtx) -> LockProbe {
    let locks = root.join(".locks").join(name);
    if ctx.deadline_elapsed() {
        return LockProbe::Deadline;
    }
    let mut entries = match fs::read_dir(&locks) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return LockProbe::Clear,
        Err(err) => {
            tracing::warn!(path = %locks.display(), %err, "huggingface lock probe failed");
            return LockProbe::Failed;
        }
    };
    loop {
        if ctx.deadline_elapsed() {
            return LockProbe::Deadline;
        }
        let Some(entry) = entries.next() else {
            return LockProbe::Clear;
        };
        match lock_entry_status(&locks, entry, ctx) {
            LockProbe::Clear => {}
            status => return status,
        }
    }
}

fn lock_entry_status(locks: &Path, entry: std::io::Result<DirEntry>, ctx: &DetectCtx) -> LockProbe {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            tracing::warn!(path = %locks.display(), %err, "huggingface lock entry probe failed");
            return LockProbe::Failed;
        }
    };
    let path = entry.path();
    if path.extension() != Some(std::ffi::OsStr::new("lock")) {
        return LockProbe::Clear;
    }
    lock_file_status(&path, ctx)
}

fn lock_file_status(path: &Path, ctx: &DetectCtx) -> LockProbe {
    if ctx.deadline_elapsed() {
        return LockProbe::Deadline;
    }
    // Safe primitive: a FIFO named *.lock must not block and only the descriptor
    // is needed for flock; a non-regular entry cannot be a real lock -> Failed.
    let file = match degu_walk::open_regular_capped(path) {
        Ok(Some(file)) => file,
        Ok(None) => {
            tracing::warn!(path = %path.display(), "huggingface lock file is not a regular file");
            return LockProbe::Failed;
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "huggingface lock file open failed");
            return LockProbe::Failed;
        }
    };
    if ctx.deadline_elapsed() {
        return LockProbe::Deadline;
    }
    match flock(&file, FlockOperation::NonBlockingLockShared) {
        Ok(()) => LockProbe::Clear,
        Err(rustix::io::Errno::WOULDBLOCK) => {
            tracing::warn!(path = %path.display(), "huggingface repo has an active download lock");
            LockProbe::Busy
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "huggingface lock file probe failed");
            LockProbe::Failed
        }
    }
}
