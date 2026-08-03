use crate::accounting::{
    record_directory, record_file, record_readdir_op, record_skip, record_skip_reason,
    record_stat_op,
};
use crate::metadata::{
    EntryIdentity, Inspection, RootDevice, crosses_filesystem_boundary, inspect_at, lstat,
    normalize_root, open_root, open_verified_directory, root_device,
};
use crate::{Heartbeat, Progress, WalkOptions, WalkStats};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::Dir;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Instant;

/// Deferred child opens + LIFO consumption bound live fds by depth, not width.
enum PendingDir {
    Root {
        fd: Arc<OwnedFd>,
        path: PathBuf,
    },
    Child {
        parent: Arc<OwnedFd>,
        name: CString,
        identity: EntryIdentity,
        meta: crate::metadata::FileMeta,
        path: PathBuf,
    },
}

struct OpenDir {
    fd: Arc<OwnedFd>,
    path: PathBuf,
}

/// Account for one directory tree.
pub fn measure(root: &Path, options: &WalkOptions) -> io::Result<WalkStats> {
    let progress = options.progress.as_deref();
    let lookup = normalize_root(root);
    let (mut stats, inspection) = inspect_root(&lookup, progress)?;
    if let Some(reason) = ownership_mismatch(root, &inspection.meta, options) {
        record_skip_reason(&mut stats, root.to_path_buf(), &reason);
        return Ok(stats);
    }
    if !inspection.meta.is_dir {
        record_file(&inspection.meta, &mut stats, progress);
        return Ok(stats);
    }
    record_directory(&inspection.meta, &mut stats, progress);
    if deadline_elapsed(options.deadline) {
        stats.truncated = true;
        stats.unvisited_dirs = stats.unvisited_dirs.saturating_add(1);
        return Ok(stats);
    }

    let root_device = root_device(&inspection.meta, options.one_filesystem);
    let root_handle = match open_root(&lookup, inspection.identity) {
        Ok(fd) => PendingDir::Root {
            fd: Arc::new(fd),
            path: root.to_path_buf(),
        },
        Err(err) if vanished_before_open(&err) => {
            // Vanished before the verified open: NotFound, not a stale finding.
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Err(err) => {
            // Unreadable, not-a-directory, or swapped root: one skip, Ok scan.
            record_skip(&mut stats, root.to_path_buf(), err);
            return Ok(stats);
        }
    };

    let workers = worker_count(&lookup, options);
    let local_heartbeat;
    let heartbeat = if let Some(progress) = progress {
        &progress.heartbeat
    } else {
        local_heartbeat = Heartbeat::default();
        &local_heartbeat
    };
    let shared = Shared::new(root_handle, stats);
    let context = WorkerContext {
        root,
        root_device,
        options,
        heartbeat,
    };
    run_workers(&shared, &context, workers);
    Ok(shared.state.into_inner().unwrap().stats)
}

fn inspect_root(root: &Path, progress: Option<&Progress>) -> io::Result<(WalkStats, Inspection)> {
    let mut stats = WalkStats::default();
    record_stat_op(&mut stats, progress);
    let inspection = lstat(root)?;
    Ok((stats, inspection))
}

fn worker_count(root: &Path, options: &WalkOptions) -> usize {
    if let Some(max_concurrency) = options.max_concurrency {
        return max_concurrency.get();
    }
    let flavor = crate::fstype::detect(root);
    let workers = crate::fstype::default_concurrency(flavor);
    tracing::debug!(
        root = %root.display(),
        flavor = flavor.label(),
        workers,
        "auto concurrency"
    );
    workers
}

fn run_workers(shared: &Shared, context: &WorkerContext<'_>, workers: usize) {
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| worker(shared, context));
        }
    });
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
}

impl Shared {
    fn new(root: PendingDir, stats: WalkStats) -> Self {
        Self {
            state: Mutex::new(State {
                queue: VecDeque::from([root]),
                active: 0,
                stats,
            }),
            ready: Condvar::new(),
        }
    }
}

struct State {
    queue: VecDeque<PendingDir>,
    active: usize,
    stats: WalkStats,
}

#[derive(Default)]
struct ScanResult {
    stats: WalkStats,
    dirs: Vec<PendingDir>,
}

struct WorkerContext<'a> {
    root: &'a Path,
    root_device: RootDevice,
    options: &'a WalkOptions,
    heartbeat: &'a Heartbeat,
}

fn worker(shared: &Shared, context: &WorkerContext<'_>) {
    while let Some(dir) = next_dir(shared, context) {
        let result = consume_dir(dir, context, || deadline_elapsed(context.options.deadline));
        complete_dir(shared, result);
    }
}

fn consume_dir(
    dir: PendingDir,
    context: &WorkerContext<'_>,
    deadline_expired: impl FnMut() -> bool,
) -> ScanResult {
    let mut result = ScanResult::default();
    let progress = context.options.progress.as_deref();
    let open = match dir {
        // The root was already counted in `measure`; only its enumeration remains.
        PendingDir::Root { fd, path } => OpenDir { fd, path },
        PendingDir::Child {
            parent,
            name,
            identity,
            meta,
            path,
        } => match open_verified_directory(parent.as_fd(), &name, identity) {
            Ok(fd) => {
                // A directory is counted only once its verified open succeeds.
                record_directory(&meta, &mut result.stats, progress);
                OpenDir {
                    fd: Arc::new(fd),
                    path,
                }
            }
            Err(err) if vanished_before_open(&err) => {
                tracing::debug!(path = %path.display(), %err, "directory vanished during walk");
                return result;
            }
            // Identity change or a swapped-in symlink: recorded, never followed.
            Err(err) => {
                tracing::debug!(path = %path.display(), %err, "skipping directory that changed identity");
                record_skip(&mut result.stats, path, err);
                return result;
            }
        },
    };
    scan_dir(&open, context, deadline_expired, &mut result);
    result
}

fn next_dir(shared: &Shared, context: &WorkerContext<'_>) -> Option<PendingDir> {
    let mut state = shared.state.lock().unwrap();
    loop {
        if state.queue.is_empty() && state.active == 0 {
            shared.ready.notify_all();
            return None;
        }
        if state.stats.truncated || deadline_elapsed(context.options.deadline) {
            truncate_pending(shared, &mut state);
            return None;
        }
        if let Some(dir) = state.queue.pop_back() {
            begin_dir(&mut state, context);
            return Some(dir);
        }
        state = shared.ready.wait(state).unwrap();
    }
}

fn deadline_elapsed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn truncate_pending(shared: &Shared, state: &mut MutexGuard<'_, State>) {
    state.stats.truncated = true;
    state.stats.unvisited_dirs = state
        .stats
        .unvisited_dirs
        .saturating_add(state.queue.len() as u64);
    state.queue.clear();
    shared.ready.notify_all();
}

fn begin_dir(state: &mut State, context: &WorkerContext<'_>) {
    state.active += 1;
    if !context.heartbeat.due_at(Instant::now()) {
        return;
    }
    tracing::debug!(
        root = %context.root.display(),
        inodes_so_far = state.stats.inodes,
        "walk in progress"
    );
}

fn complete_dir(shared: &Shared, result: ScanResult) {
    let mut state = shared.state.lock().unwrap();
    state.stats.merge(result.stats);
    if state.stats.truncated {
        state.stats.unvisited_dirs = state
            .stats
            .unvisited_dirs
            .saturating_add(result.dirs.len() as u64);
    } else {
        state.queue.extend(result.dirs);
    }
    state.active -= 1;
    shared.ready.notify_all();
}

fn scan_dir(
    dir: &OpenDir,
    context: &WorkerContext<'_>,
    mut deadline_expired: impl FnMut() -> bool,
    result: &mut ScanResult,
) {
    let progress = context.options.progress.as_deref();
    if deadline_expired() {
        mark_scan_truncated(result);
        return;
    }
    record_readdir_op(&mut result.stats, progress);
    // The fd is already a verified directory, so a read failure here is a real skip.
    let mut entries = match Dir::read_from(&dir.fd) {
        Ok(entries) => entries,
        Err(err) => {
            let err = io::Error::from(err);
            tracing::debug!(dir = %dir.path.display(), %err, "skipping unreadable directory");
            record_skip(&mut result.stats, dir.path.clone(), err);
            return;
        }
    };

    let mut scanner = EntryScanner { context, result };
    // Filter `.`/`..` before the deadline poll so they never spend its budget.
    while let Some(entry) = next_named_entry(&mut entries) {
        if deadline_expired() {
            mark_scan_truncated(scanner.result);
            break;
        }
        scanner.scan_result(entry, dir);
    }
}

fn next_named_entry(entries: &mut Dir) -> Option<Result<rustix::fs::DirEntry, rustix::io::Errno>> {
    loop {
        match entries.next()? {
            Ok(entry) if matches!(entry.file_name().to_bytes(), b"." | b"..") => continue,
            entry => return Some(entry),
        }
    }
}

// Deletion after enumeration is not a failure: completeness is not a snapshot.
fn vanished_after_enumeration(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

// Only ENOENT is a benign vanish; ENOTDIR/ELOOP is a swap and must skip, not drop.
fn vanished_before_open(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
}

fn mark_scan_truncated(result: &mut ScanResult) {
    result.stats.truncated = true;
    result.stats.unvisited_dirs = result.stats.unvisited_dirs.saturating_add(1);
}

struct EntryScanner<'a, 'context> {
    context: &'a WorkerContext<'context>,
    result: &'a mut ScanResult,
}

impl<'a, 'context> EntryScanner<'a, 'context> {
    fn scan_result(
        &mut self,
        entry: Result<rustix::fs::DirEntry, rustix::io::Errno>,
        dir: &OpenDir,
    ) {
        match entry {
            Ok(entry) => self.scan(dir, entry.file_name()),
            Err(err) => {
                let err = io::Error::from(err);
                tracing::debug!(dir = %dir.path.display(), %err, "skipping unreadable directory entry");
                record_skip(&mut self.result.stats, dir.path.clone(), err);
            }
        }
    }

    fn scan(&mut self, dir: &OpenDir, name: &CStr) {
        let raw_name = OsStr::from_bytes(name.to_bytes());
        if excluded_entry(raw_name, self.context.options.excluded_entry_names) {
            self.result.stats.excluded_entries =
                self.result.stats.excluded_entries.saturating_add(1);
            if excluded_entry(raw_name, self.context.options.credential_entry_names) {
                self.result.stats.excluded_credential_boundaries = self
                    .result
                    .stats
                    .excluded_credential_boundaries
                    .saturating_add(1);
            }
            return;
        }
        let path = dir.path.join(raw_name);
        let progress = self.context.options.progress.as_deref();
        record_stat_op(&mut self.result.stats, progress);
        let inspection = match inspect_at(dir.fd.as_fd(), name) {
            Ok(inspection) => inspection,
            Err(err) if vanished_after_enumeration(&err) => {
                tracing::debug!(path = %path.display(), %err, "entry vanished during walk");
                return;
            }
            Err(err) => {
                tracing::debug!(path = %path.display(), %err, "skipping path without metadata");
                record_skip(&mut self.result.stats, path, err);
                return;
            }
        };
        self.record(dir, name, path, inspection);
    }

    fn record(&mut self, dir: &OpenDir, name: &CStr, path: PathBuf, inspection: Inspection) {
        let progress = self.context.options.progress.as_deref();
        if let Some(reason) = ownership_mismatch(&path, &inspection.meta, self.context.options) {
            tracing::debug!(path = %path.display(), %reason, "skipping entry owned by another UID");
            record_skip_reason(&mut self.result.stats, path, &reason);
            return;
        }
        if !inspection.meta.is_dir {
            record_file(&inspection.meta, &mut self.result.stats, progress);
            return;
        }
        if crosses_filesystem_boundary(&inspection.meta, self.context.root_device) {
            tracing::debug!(path = %path.display(), "skipping filesystem boundary");
            record_skip_reason(&mut self.result.stats, path, "filesystem boundary");
            return;
        }
        self.result.dirs.push(PendingDir::Child {
            parent: Arc::clone(&dir.fd),
            name: name.to_owned(),
            identity: inspection.identity,
            meta: inspection.meta,
            path,
        });
    }
}

fn ownership_mismatch(
    path: &Path,
    meta: &crate::metadata::FileMeta,
    options: &WalkOptions,
) -> Option<String> {
    let required = options.required_uid?;
    let actual = effective_uid(path, meta, options);
    (actual != required).then(|| format!("entry UID {actual} differs from required UID {required}"))
}

fn effective_uid(_path: &Path, meta: &crate::metadata::FileMeta, _options: &WalkOptions) -> u32 {
    #[cfg(test)]
    if let Some(uid) = _options
        .uid_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(_path))
    {
        return *uid;
    }
    meta.uid
}

fn excluded_entry(name: &OsStr, excluded_names: &[&str]) -> bool {
    excluded_names
        .iter()
        .any(|excluded| name == OsStr::new(excluded))
}

#[cfg(test)]
mod tests;
