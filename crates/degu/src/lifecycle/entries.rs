use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::lifecycle::trash::Trash;
use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;

use super::claims::interrupted_purge_claims;
use super::expiry::{ExpiryContext, SECONDS_PER_DAY, fallback_age, should_purge_expired_entry};
use super::journal::OperationLog;
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
    /// The next confirmed clean purges this entry whether or not anyone asks,
    /// because degu runs no background timer. This is the expiry planner's own
    /// predicate, not an age comparison: an ambiguous entry never expires, an
    /// interrupted claim never expires, and an entry without a recorded
    /// staging time must be old by both ctime and mtime.
    pub(crate) expiring: bool,
    /// The size is a lower bound: the measure was truncated, skipped paths, or
    /// left directories unvisited.
    pub(crate) lower_bound: bool,
}

struct EntryInspection<'a> {
    entry: PathBuf,
    info: Option<&'a TrashOplogInfo>,
    recorded: &'a HashMap<PathBuf, TrashOplogInfo>,
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
            recorded,
            now,
            interrupted_purge: false,
        })?);
    }
    for claim in interrupted_purge_claims(root)? {
        rows.push(inspect_entry(EntryInspection {
            entry: claim,
            info: None,
            recorded,
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
        // The expiry walk skips the whole claims directory, so a claim never
        // expires however old it is. Asking the age predicate anyway would
        // promise a removal that no clean performs.
        expiring: !request.interrupted_purge
            && should_purge_expired_entry(
                &request.entry,
                &meta,
                ExpiryContext::new(request.recorded, request.now),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const EIGHT_DAYS: u64 = 8 * SECONDS_PER_DAY;

    fn aged_dir(parent: &Path, name: &str) -> PathBuf {
        let path = parent.join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(path.join("payload.bin"), b"staged").unwrap();
        path
    }

    /// The same conclusion through the enumeration production uses: a claim
    /// reaches the list from `.claims`, not from a flag a caller set.
    #[test]
    fn a_claim_found_by_the_real_enumeration_does_not_expire() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let claims = root.path().join(".claims");
        std::fs::create_dir_all(&claims).unwrap();
        std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
        aged_dir(&claims, "purge-interrupted");
        let staged = aged_dir(root.path(), "0001-cache");

        let recorded = HashMap::new();
        let now = jiff::Timestamp::now() + std::time::Duration::from_secs(EIGHT_DAYS);
        let rows = root_entries(root.path(), &recorded, now).unwrap();

        let claim = rows
            .iter()
            .find(|row| row.interrupted_purge)
            .expect("the claims directory was not enumerated");
        assert!(
            !claim.expiring,
            "an enumerated claim was reported as expiring"
        );

        let ordinary = rows
            .iter()
            .find(|row| row.entry == staged)
            .expect("the staged entry was not enumerated");
        assert!(
            ordinary.expiring,
            "the fixture is too young for the claim assertion to mean anything"
        );
    }
}
