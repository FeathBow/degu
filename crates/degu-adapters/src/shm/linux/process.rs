#[path = "process/maps.rs"]
mod maps;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HandleProbe {
    Clear,
    Held,
    Failed,
    Deadline,
}

#[derive(Clone, Copy)]
struct ProcessProbe<'a> {
    target: &'a Path,
    uid: u32,
    deadline: Option<Instant>,
}

pub(super) fn probe_same_uid_handles(
    path: &Path,
    uid: u32,
    deadline: Option<Instant>,
) -> HandleProbe {
    if deadline_elapsed(deadline) {
        return HandleProbe::Deadline;
    }
    let mut entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(%err, "proc scan failed during shm handle probe");
            return HandleProbe::Failed;
        }
    };
    let request = ProcessProbe {
        target: path,
        uid,
        deadline,
    };
    loop {
        if deadline_elapsed(deadline) {
            log_deadline(path);
            return HandleProbe::Deadline;
        }
        let Some(entry) = entries.next() else {
            return HandleProbe::Clear;
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(%err, "proc entry scan failed during shm handle probe");
                return HandleProbe::Failed;
            }
        };
        if !is_process_entry(&entry) {
            continue;
        }
        match same_uid_process_probe(&entry.path(), request) {
            HandleProbe::Clear => {}
            result => return result,
        }
    }
}

fn is_process_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| name.as_bytes().iter().all(u8::is_ascii_digit))
}

fn same_uid_process_probe(proc_path: &Path, request: ProcessProbe<'_>) -> HandleProbe {
    if deadline_elapsed(request.deadline) {
        return HandleProbe::Deadline;
    }
    let meta = match fs::symlink_metadata(proc_path) {
        Ok(meta) => meta,
        Err(err) if probe_target_vanished(&err) => return HandleProbe::Clear,
        Err(err) => {
            tracing::debug!(proc = %proc_path.display(), %err, "proc metadata probe failed during shm handle probe");
            return HandleProbe::Failed;
        }
    };
    if meta.uid() != request.uid {
        return HandleProbe::Clear;
    }
    process_holds_path(proc_path, request.target, request.deadline)
}

pub(super) fn process_holds_path(
    proc_path: &Path,
    path: &Path,
    deadline: Option<Instant>,
) -> HandleProbe {
    if deadline_elapsed(deadline) {
        return HandleProbe::Deadline;
    }
    let fd = fd_holds_path(proc_path, path, deadline);
    if matches!(fd, HandleProbe::Held | HandleProbe::Deadline) {
        return fd;
    }
    if deadline_elapsed(deadline) {
        return if fd == HandleProbe::Failed {
            HandleProbe::Failed
        } else {
            HandleProbe::Deadline
        };
    }
    let maps = maps::holds_path(proc_path, path, deadline);
    if maps == HandleProbe::Held {
        return maps;
    }
    if fd == HandleProbe::Failed || maps == HandleProbe::Failed {
        HandleProbe::Failed
    } else {
        maps
    }
}

fn fd_holds_path(proc_path: &Path, path: &Path, deadline: Option<Instant>) -> HandleProbe {
    if deadline_elapsed(deadline) {
        return HandleProbe::Deadline;
    }
    let mut entries = match fs::read_dir(proc_path.join("fd")) {
        Ok(entries) => entries,
        Err(err) => {
            log_probe_error(proc_path, &err, ProbeStep::FdDirectory);
            return failure_for(&err);
        }
    };
    let mut incomplete = false;
    loop {
        // A prior probe failure outranks the deadline; the caller's next
        // iteration still observes the elapsed deadline, so neither flag is lost.
        if deadline_elapsed(deadline) {
            return if incomplete {
                HandleProbe::Failed
            } else {
                HandleProbe::Deadline
            };
        }
        let Some(entry) = entries.next() else {
            break;
        };
        let target = match fd_target(proc_path, entry, deadline) {
            FdTarget::Path(target) => target,
            FdTarget::Missing => continue,
            FdTarget::Failed => {
                incomplete = true;
                continue;
            }
            FdTarget::Deadline => {
                return if incomplete {
                    HandleProbe::Failed
                } else {
                    HandleProbe::Deadline
                };
            }
        };
        if same_fd_target(&target, path) {
            return HandleProbe::Held;
        }
    }
    if incomplete {
        HandleProbe::Failed
    } else {
        HandleProbe::Clear
    }
}

enum FdTarget {
    Path(PathBuf),
    Missing,
    Failed,
    Deadline,
}

fn fd_target(
    proc_path: &Path,
    entry: std::io::Result<fs::DirEntry>,
    deadline: Option<Instant>,
) -> FdTarget {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            log_probe_error(proc_path, &err, ProbeStep::FdEntry);
            return if probe_target_vanished(&err) {
                FdTarget::Missing
            } else {
                FdTarget::Failed
            };
        }
    };
    if deadline_elapsed(deadline) {
        return FdTarget::Deadline;
    }
    match fs::read_link(entry.path()) {
        Ok(target) => FdTarget::Path(target),
        Err(err) => {
            log_probe_error(proc_path, &err, ProbeStep::FdTarget);
            if probe_target_vanished(&err) {
                FdTarget::Missing
            } else {
                FdTarget::Failed
            }
        }
    }
}

fn deadline_elapsed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn log_deadline(path: &Path) {
    tracing::debug!(
        adapter = "shm",
        path = %path.display(),
        "deadline stopped shm handle probe"
    );
}

fn failure_for(err: &std::io::Error) -> HandleProbe {
    if probe_target_vanished(err) {
        HandleProbe::Clear
    } else {
        HandleProbe::Failed
    }
}

fn same_fd_target(target: &Path, path: &Path) -> bool {
    if target == path {
        return true;
    }
    let Some(target) = target.to_str() else {
        return false;
    };
    target
        .strip_suffix(" (deleted)")
        .is_some_and(|target| Path::new(target) == path)
}

fn probe_target_vanished(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::NotFound) || err.raw_os_error() == Some(libc::ESRCH)
}

#[derive(Clone, Copy)]
enum ProbeStep {
    FdDirectory,
    FdEntry,
    FdTarget,
    Maps,
}

fn log_probe_error(proc_path: &Path, err: &std::io::Error, step: ProbeStep) {
    match (step, probe_target_vanished(err)) {
        (ProbeStep::FdDirectory, true) => {
            tracing::debug!(proc = %proc_path.display(), %err, "proc fd scan target vanished during shm handle probe")
        }
        (ProbeStep::FdDirectory, false) => {
            tracing::debug!(proc = %proc_path.display(), %err, "skipping unverifiable proc fd scan during shm handle probe")
        }
        (ProbeStep::FdEntry, true) => {
            tracing::debug!(proc = %proc_path.display(), %err, "proc fd entry scan target vanished during shm handle probe")
        }
        (ProbeStep::FdEntry, false) => {
            tracing::debug!(proc = %proc_path.display(), %err, "skipping unverifiable proc fd entry during shm handle probe")
        }
        (ProbeStep::FdTarget, true) => {
            tracing::debug!(proc = %proc_path.display(), %err, "proc fd target vanished during shm handle probe")
        }
        (ProbeStep::FdTarget, false) => {
            tracing::debug!(proc = %proc_path.display(), %err, "skipping unverifiable proc fd target during shm handle probe")
        }
        (ProbeStep::Maps, true) => {
            tracing::debug!(proc = %proc_path.display(), %err, "proc maps target vanished during shm handle probe")
        }
        (ProbeStep::Maps, false) => {
            tracing::debug!(proc = %proc_path.display(), %err, "skipping unverifiable proc maps scan during shm handle probe")
        }
    }
}
