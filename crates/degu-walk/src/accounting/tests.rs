use super::*;
use std::sync::atomic::Ordering;

#[test]
fn truncates_stored_skip_reason_on_utf8_boundary() {
    let mut stats = WalkStats::default();
    let reason = format!("{}é{}", "a".repeat(127), "b".repeat(16));

    record_skip_reason(&mut stats, PathBuf::from("sample"), &reason);

    assert_eq!(stats.skipped_total, 1);
    assert_eq!(stats.skipped.len(), 1);
    assert!(stats.skipped[0].reason.len() <= SKIP_REASON_MAX_BYTES);
    assert!(
        stats.skipped[0]
            .reason
            .is_char_boundary(stats.skipped[0].reason.len())
    );
    assert_eq!(stats.skipped[0].reason, "a".repeat(127));
}

#[test]
fn merge_preserves_bounded_diagnostics_and_scan_state() {
    let mut stats = WalkStats {
        skipped_total: u64::MAX - 10,
        unvisited_dirs: u64::MAX - 2,
        excluded_entries: u64::MAX - 3,
        ..Default::default()
    };
    let mut first = stats_with_skips(SkipStatsSpec {
        prefix: "first",
        count: 20,
        measurement_base: 1,
        stat_ops: 7,
        readdir_ops: 3,
    });
    let mut second = stats_with_skips(SkipStatsSpec {
        prefix: "second",
        count: 20,
        measurement_base: 10,
        stat_ops: 11,
        readdir_ops: 5,
    });
    first.newest_mtime = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(2));
    first.truncated = true;
    first.unvisited_dirs = 1;
    first.excluded_entries = 1;
    second.newest_mtime = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
    second.unvisited_dirs = 2;
    second.excluded_entries = 3;
    let expected_newest = first.newest_mtime;

    stats.merge(first);
    stats.merge(second);

    assert_merged_stats(&stats, expected_newest);
}

#[test]
fn merge_saturates_all_numeric_totals() {
    let mut stats = stats_at_numeric_max();
    let partial = WalkStats {
        dirs: 1,
        files: 1,
        bytes_apparent: 1,
        bytes_allocated: 1,
        bytes_hardlinked: 1,
        inodes: 1,
        stat_ops: 1,
        readdir_ops: 1,
        skipped_total: 1,
        unvisited_dirs: 1,
        excluded_entries: 1,
        ..Default::default()
    };

    stats.merge(partial);

    assert_numeric_totals_are_max(&stats);
}

#[test]
fn recording_saturates_numeric_totals() {
    let mut stats = stats_at_numeric_max();
    let progress = progress_at_numeric_max();
    let meta = FileMeta {
        is_dir: false,
        len: 1,
        bytes_allocated: 1,
        nlink: 2,
        mtime: None,
        dev: 0,
    };

    record_file(&meta, &mut stats, Some(&progress));
    record_directory(&mut stats, Some(&progress));
    record_stat_op(&mut stats, Some(&progress));
    record_readdir_op(&mut stats, Some(&progress));

    assert_numeric_totals_are_max(&stats);
    assert_eq!(
        progress.snapshot(),
        crate::ProgressSnapshot {
            inodes: u64::MAX,
            bytes_allocated: u64::MAX,
            stat_ops: u64::MAX,
            readdir_ops: u64::MAX,
        }
    );
}

fn progress_at_numeric_max() -> Progress {
    let progress = Progress::default();
    progress.inodes.store(u64::MAX, Ordering::Relaxed);
    progress.bytes_allocated.store(u64::MAX, Ordering::Relaxed);
    progress.stat_ops.store(u64::MAX, Ordering::Relaxed);
    progress.readdir_ops.store(u64::MAX, Ordering::Relaxed);
    progress
}

fn assert_merged_stats(stats: &WalkStats, expected_newest: Option<std::time::SystemTime>) {
    assert_eq!(stats.dirs, 11);
    assert_eq!(stats.files, 13);
    assert_eq!(stats.bytes_apparent, 15);
    assert_eq!(stats.bytes_allocated, 17);
    assert_eq!(stats.bytes_hardlinked, 19);
    assert_eq!(stats.inodes, 21);
    assert_eq!(stats.skipped_total, u64::MAX);
    assert_eq!(stats.stat_ops, 18);
    assert_eq!(stats.readdir_ops, 8);
    assert_eq!(stats.newest_mtime, expected_newest);
    assert!(stats.truncated);
    assert_eq!(stats.unvisited_dirs, u64::MAX);
    assert_eq!(stats.excluded_entries, u64::MAX);
    assert_eq!(stats.skipped.len(), SKIP_SAMPLE_CAP);
    assert_eq!(stats.skipped[19].path, PathBuf::from("first-19"));
    assert_eq!(stats.skipped[20].path, PathBuf::from("second-0"));
    assert_eq!(stats.skipped[31].path, PathBuf::from("second-11"));
}

fn stats_at_numeric_max() -> WalkStats {
    WalkStats {
        dirs: u64::MAX,
        files: u64::MAX,
        bytes_apparent: u64::MAX,
        bytes_allocated: u64::MAX,
        bytes_hardlinked: u64::MAX,
        inodes: u64::MAX,
        stat_ops: u64::MAX,
        readdir_ops: u64::MAX,
        skipped_total: u64::MAX,
        unvisited_dirs: u64::MAX,
        excluded_entries: u64::MAX,
        ..Default::default()
    }
}

fn assert_numeric_totals_are_max(stats: &WalkStats) {
    assert_eq!(
        [
            stats.dirs,
            stats.files,
            stats.bytes_apparent,
            stats.bytes_allocated,
            stats.bytes_hardlinked,
            stats.inodes,
            stats.stat_ops,
            stats.readdir_ops,
            stats.skipped_total,
            stats.unvisited_dirs,
            stats.excluded_entries,
        ],
        [u64::MAX; 11]
    );
}

struct SkipStatsSpec<'a> {
    prefix: &'a str,
    count: usize,
    measurement_base: u64,
    stat_ops: u64,
    readdir_ops: u64,
}

fn stats_with_skips(spec: SkipStatsSpec<'_>) -> WalkStats {
    let mut stats = WalkStats {
        dirs: spec.measurement_base,
        files: spec.measurement_base + 1,
        bytes_apparent: spec.measurement_base + 2,
        bytes_allocated: spec.measurement_base + 3,
        bytes_hardlinked: spec.measurement_base + 4,
        inodes: spec.measurement_base + 5,
        stat_ops: spec.stat_ops,
        readdir_ops: spec.readdir_ops,
        ..Default::default()
    };
    for index in 0..spec.count {
        record_skip_reason(
            &mut stats,
            PathBuf::from(format!("{}-{index}", spec.prefix)),
            spec.prefix,
        );
    }
    stats
}
