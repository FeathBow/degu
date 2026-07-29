use super::reconcile::TrashOplogInfo;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const TRASH_RETENTION_DAYS: u64 = 7;
pub(super) const SECONDS_PER_DAY: u64 = 86_400;
pub(super) const TRASH_TTL: Duration = Duration::from_secs(TRASH_RETENTION_DAYS * SECONDS_PER_DAY);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrashEntryExpiry {
    Never,
    StagedAt(jiff::Timestamp),
    Fallback,
}

#[derive(Clone, Copy)]
pub(crate) struct ExpiryContext<'a> {
    recorded: &'a HashMap<PathBuf, TrashOplogInfo>,
    now: jiff::Timestamp,
}

impl<'a> ExpiryContext<'a> {
    pub(crate) fn new(
        recorded: &'a HashMap<PathBuf, TrashOplogInfo>,
        now: jiff::Timestamp,
    ) -> Self {
        Self { recorded, now }
    }
}

pub(crate) fn trash_entry_expiry(
    entry: &Path,
    recorded: &HashMap<PathBuf, TrashOplogInfo>,
) -> TrashEntryExpiry {
    match recorded.get(entry) {
        Some(info) if info.ambiguous => TrashEntryExpiry::Never,
        Some(info) => info
            .staged_at
            .map_or(TrashEntryExpiry::Fallback, TrashEntryExpiry::StagedAt),
        None => TrashEntryExpiry::Fallback,
    }
}

pub(crate) fn should_purge_expired_entry(
    entry: &Path,
    meta: &std::fs::Metadata,
    expiry: ExpiryContext<'_>,
) -> bool {
    match trash_entry_expiry(entry, expiry.recorded) {
        TrashEntryExpiry::Never => false,
        TrashEntryExpiry::StagedAt(ts) => {
            timestamp_age(ts, expiry.now).is_some_and(|age| age >= TRASH_TTL)
        }
        TrashEntryExpiry::Fallback => {
            fallback_age(meta, expiry.now) >= TRASH_TTL
                && fallback_mtime_age(meta, expiry.now) >= TRASH_TTL
        }
    }
}

fn timestamp_age(ts: jiff::Timestamp, now: jiff::Timestamp) -> Option<Duration> {
    let age = now.duration_since(ts);
    (!age.is_negative()).then(|| age.unsigned_abs())
}

pub(crate) fn fallback_age(meta: &std::fs::Metadata, now: jiff::Timestamp) -> Duration {
    let ts = jiff::Timestamp::from_second(meta.ctime().max(0)).unwrap_or(jiff::Timestamp::MIN);
    timestamp_age(ts, now).unwrap_or(Duration::ZERO)
}

pub(crate) fn fallback_mtime_age(meta: &std::fs::Metadata, now: jiff::Timestamp) -> Duration {
    let modified = match meta.modified() {
        Ok(modified) => modified,
        Err(_) => return Duration::ZERO,
    };
    let ts = match jiff::Timestamp::try_from(modified) {
        Ok(ts) => ts,
        Err(_) => return Duration::ZERO,
    };
    timestamp_age(ts, now).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests;
