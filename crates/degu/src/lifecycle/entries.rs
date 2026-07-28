use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::lifecycle::trash::Trash;
use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;

use super::claims::interrupted_purge_claims;
use super::expiry::{SECONDS_PER_DAY, fallback_age};
use super::operation_log::OperationLog;
use super::reconcile::{TrashOplogInfo, reconciled_trash_info};
use super::storage::trash_roots;

pub(crate) struct TrashEntry {
    pub(crate) entry: PathBuf,
    pub(crate) original: Option<PathBuf>,
    pub(crate) bytes_allocated: u64,
    pub(crate) bytes_hardlinked: u64,
    pub(crate) age_days: u64,
    pub(crate) ambiguous: bool,
    pub(crate) interrupted_purge: bool,
    /// The size is a lower bound: the measure was truncated, skipped paths, or
    /// left directories unvisited.
    pub(crate) lower_bound: bool,
}

struct EntryInspection<'a> {
    entry: PathBuf,
    info: Option<&'a TrashOplogInfo>,
    now: jiff::Timestamp,
    interrupted_purge: bool,
}

pub(crate) fn trash_entries(ctx: &DetectCtx) -> Result<Vec<TrashEntry>> {
    let records = OperationLog::new(ctx).read()?;
    let recorded = reconciled_trash_info(&records);
    let now = jiff::Timestamp::now();
    let mut entries = Vec::new();

    for root in trash_roots(ctx)? {
        entries.extend(root_entries(&root, &recorded, now)?);
    }
    entries.sort_by(|left, right| {
        right
            .bytes_allocated
            .cmp(&left.bytes_allocated)
            .then_with(|| left.entry.cmp(&right.entry))
    });
    Ok(entries)
}

fn root_entries(
    root: &Path,
    recorded: &HashMap<PathBuf, TrashOplogInfo>,
    now: jiff::Timestamp,
) -> Result<Vec<TrashEntry>> {
    let trash = Trash::new(root.to_path_buf());
    let entries = trash
        .entries_matching(|_, _| true)
        .with_context(|| format!("failed to select trash in {}", root.display()))?;
    let mut rows = Vec::new();
    for entry in entries {
        let info = recorded.get(&entry);
        rows.push(inspect_entry(EntryInspection {
            entry,
            info,
            now,
            interrupted_purge: false,
        })?);
    }
    for claim in interrupted_purge_claims(root)? {
        rows.push(inspect_entry(EntryInspection {
            entry: claim,
            info: None,
            now,
            interrupted_purge: true,
        })?);
    }
    Ok(rows)
}

fn inspect_entry(request: EntryInspection<'_>) -> Result<TrashEntry> {
    let meta = std::fs::symlink_metadata(&request.entry)
        .with_context(|| format!("failed to inspect {}", request.entry.display()))?;
    let stats = degu_walk::measure(&request.entry, &degu_walk::WalkOptions::default())
        .with_context(|| format!("failed to measure {}", request.entry.display()))?;
    Ok(TrashEntry {
        original: request.info.map(|value| value.original.clone()),
        bytes_allocated: stats.bytes_allocated,
        bytes_hardlinked: stats.bytes_hardlinked,
        age_days: entry_age_days(request.info, &meta, request.now),
        ambiguous: request.info.is_some_and(|value| value.ambiguous),
        interrupted_purge: request.interrupted_purge,
        lower_bound: stats.truncated || stats.skipped_total > 0 || stats.unvisited_dirs > 0,
        entry: request.entry,
    })
}

fn entry_age_days(
    info: Option<&TrashOplogInfo>,
    meta: &std::fs::Metadata,
    now: jiff::Timestamp,
) -> u64 {
    let age = match info.and_then(|value| value.staged_at) {
        Some(staged_at) => non_negative_age(staged_at, now),
        None => fallback_age(meta, now),
    };
    age.as_secs() / SECONDS_PER_DAY
}

fn non_negative_age(staged_at: jiff::Timestamp, now: jiff::Timestamp) -> Duration {
    let age = now.duration_since(staged_at);
    if age.is_negative() {
        Duration::ZERO
    } else {
        age.unsigned_abs()
    }
}
