use crate::metadata::FileMeta;
use crate::{Progress, Skipped, WalkStats};
use std::io;
use std::path::PathBuf;

pub(super) const SKIP_SAMPLE_CAP: usize = 32;
const SKIP_REASON_MAX_BYTES: usize = 128;

impl WalkStats {
    /// Merge one walk while retaining a bounded skipped-path sample.
    pub fn merge(&mut self, partial: Self) {
        let Self {
            dirs,
            files,
            bytes_apparent,
            bytes_allocated,
            bytes_hardlinked,
            newest_mtime,
            inodes,
            stat_ops,
            readdir_ops,
            skipped_total,
            truncated,
            unvisited_dirs,
            excluded_entries,
            excluded_credential_boundaries,
            skipped,
        } = partial;
        self.dirs = self.dirs.saturating_add(dirs);
        self.files = self.files.saturating_add(files);
        self.bytes_apparent = self.bytes_apparent.saturating_add(bytes_apparent);
        self.bytes_allocated = self.bytes_allocated.saturating_add(bytes_allocated);
        self.bytes_hardlinked = self.bytes_hardlinked.saturating_add(bytes_hardlinked);
        merge_newest_mtime(self, newest_mtime);
        self.inodes = self.inodes.saturating_add(inodes);
        self.stat_ops = self.stat_ops.saturating_add(stat_ops);
        self.readdir_ops = self.readdir_ops.saturating_add(readdir_ops);
        self.skipped_total = self.skipped_total.saturating_add(skipped_total);
        self.truncated |= truncated;
        self.unvisited_dirs = self.unvisited_dirs.saturating_add(unvisited_dirs);
        self.excluded_entries = self.excluded_entries.saturating_add(excluded_entries);
        self.excluded_credential_boundaries = self
            .excluded_credential_boundaries
            .saturating_add(excluded_credential_boundaries);
        let remaining = SKIP_SAMPLE_CAP.saturating_sub(self.skipped.len());
        self.skipped.extend(skipped.into_iter().take(remaining));
    }
}

fn merge_newest_mtime(stats: &mut WalkStats, candidate: Option<std::time::SystemTime>) {
    match (stats.newest_mtime, candidate) {
        (Some(current), Some(candidate)) if candidate > current => {
            stats.newest_mtime = Some(candidate);
        }
        (None, Some(candidate)) => stats.newest_mtime = Some(candidate),
        _ => {}
    }
}

pub(super) fn record_skip(stats: &mut WalkStats, path: PathBuf, error: io::Error) {
    record_skip_reason(stats, path, &error.to_string());
}

pub(super) fn record_skip_reason(stats: &mut WalkStats, path: PathBuf, reason: &str) {
    stats.skipped_total = stats.skipped_total.saturating_add(1);
    if stats.skipped.len() >= SKIP_SAMPLE_CAP {
        return;
    }

    stats.skipped.push(Skipped {
        path,
        reason: truncate_reason(reason),
    });
}

fn truncate_reason(reason: &str) -> String {
    if reason.len() <= SKIP_REASON_MAX_BYTES {
        return reason.to_owned();
    }

    let mut end = 0;
    for (index, character) in reason.char_indices() {
        let next = index + character.len_utf8();
        if next > SKIP_REASON_MAX_BYTES {
            break;
        }
        end = next;
    }
    reason[..end].to_owned()
}

pub(super) fn record_file(meta: &FileMeta, stats: &mut WalkStats, progress: Option<&Progress>) {
    stats.files = stats.files.saturating_add(1);
    stats.inodes = stats.inodes.saturating_add(1);
    stats.bytes_apparent = stats.bytes_apparent.saturating_add(meta.len);
    let allocated = meta.bytes_allocated;
    stats.bytes_allocated = stats.bytes_allocated.saturating_add(allocated);
    record_progress(progress, 1, allocated);
    if meta.nlink > 1 {
        stats.bytes_hardlinked = stats.bytes_hardlinked.saturating_add(allocated);
    }
    if let Some(mtime) = meta.mtime {
        match stats.newest_mtime {
            Some(current) if mtime <= current => {}
            _ => stats.newest_mtime = Some(mtime),
        }
    }
}

pub(super) fn record_directory(stats: &mut WalkStats, progress: Option<&Progress>) {
    stats.dirs = stats.dirs.saturating_add(1);
    stats.inodes = stats.inodes.saturating_add(1);
    record_progress(progress, 1, 0);
}

pub(super) fn record_progress(progress: Option<&Progress>, inodes: u64, bytes_allocated: u64) {
    if let Some(progress) = progress {
        progress.add_resources(inodes, bytes_allocated);
    }
}

pub(super) fn record_stat_op(stats: &mut WalkStats, progress: Option<&Progress>) {
    stats.stat_ops = stats.stat_ops.saturating_add(1);
    if let Some(progress) = progress {
        progress.add_stat_op();
    }
}

pub(super) fn record_readdir_op(stats: &mut WalkStats, progress: Option<&Progress>) {
    stats.readdir_ops = stats.readdir_ops.saturating_add(1);
    if let Some(progress) = progress {
        progress.add_readdir_op();
    }
}

#[cfg(test)]
mod tests;
