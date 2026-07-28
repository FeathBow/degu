use super::claims::interrupted_purge_claims_until;
use super::storage::trash_roots;
use anyhow::{Context, Result};
use degu_core::ecosystem::DetectCtx;
use std::ffi::OsStr;

pub(crate) struct TrashSummary {
    pub(crate) entries: usize,
    pub(crate) bytes_allocated: u64,
    pub(crate) bytes_hardlinked: u64,
    /// A scan budget cut entry or claim enumeration short, so the count is a
    /// floor: more entries may exist than were tallied.
    pub(crate) entries_lower_bound: bool,
    /// A measure was truncated, skipped paths, or left directories unvisited, so
    /// the byte totals are a floor. Tracked apart from the count because an
    /// enumeration can finish while its measure is cut short, and vice versa.
    pub(crate) bytes_lower_bound: bool,
}

pub(crate) fn trash_summary(ctx: &DetectCtx) -> Result<Option<TrashSummary>> {
    let mut summary = TrashSummary {
        entries: 0,
        bytes_allocated: 0,
        bytes_hardlinked: 0,
        entries_lower_bound: false,
        bytes_lower_bound: false,
    };
    let options = degu_walk::WalkOptions {
        deadline: ctx.deadline,
        max_concurrency: ctx.max_concurrency,
        ..Default::default()
    };
    for dir in trash_roots(ctx)? {
        if ctx.deadline_elapsed() {
            // A root left entirely uncounted and unmeasured floors both totals.
            summary.entries_lower_bound = true;
            summary.bytes_lower_bound = true;
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", dir.display()));
            }
        };
        let interrupted = interrupted_purge_claims_until(&dir, ctx.deadline)
            .with_context(|| format!("failed to select interrupted purges in {}", dir.display()))?;
        summary.entries_lower_bound |= interrupted.truncated;
        let counted = count_entries(entries, &dir, ctx)?;
        summary.entries_lower_bound |= counted.truncated;
        let entry_count = counted.count.saturating_add(interrupted.claims.len());
        if entry_count == 0 {
            continue;
        }
        let stats = degu_walk::measure(&dir, &options)
            .with_context(|| format!("failed to measure {}", dir.display()))?;
        summary.bytes_lower_bound |=
            stats.truncated || stats.skipped_total > 0 || stats.unvisited_dirs > 0;
        summary.entries = summary.entries.saturating_add(entry_count);
        summary.bytes_allocated = summary
            .bytes_allocated
            .saturating_add(stats.bytes_allocated);
        summary.bytes_hardlinked = summary
            .bytes_hardlinked
            .saturating_add(stats.bytes_hardlinked);
    }
    if summary.entries == 0 && !summary.entries_lower_bound && !summary.bytes_lower_bound {
        return Ok(None);
    }
    Ok(Some(summary))
}

struct CountedEntries {
    count: usize,
    truncated: bool,
}

fn count_entries(
    entries: std::fs::ReadDir,
    dir: &std::path::Path,
    ctx: &DetectCtx,
) -> Result<CountedEntries> {
    let mut count = 0usize;
    for entry in entries {
        if ctx.deadline_elapsed() {
            return Ok(CountedEntries {
                count,
                truncated: true,
            });
        }
        let entry = entry.with_context(|| format!("failed to read {}", dir.display()))?;
        if entry.file_name() != OsStr::new(".claims") {
            count = count.saturating_add(1);
        }
    }
    Ok(CountedEntries {
        count,
        truncated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::{count_entries, trash_summary};
    use degu_core::ecosystem::DetectCtx;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    fn seeded_state() -> tempfile::TempDir {
        let state = tempfile::tempdir().unwrap();
        let trash = state.path().join("degu/trash");
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            trash.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let entry = trash.join("0001-entry");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("data"), [0u8; 4096]).unwrap();
        state
    }

    fn ctx(home: &tempfile::TempDir, state: &tempfile::TempDir) -> DetectCtx {
        DetectCtx::for_test(
            home.path().to_path_buf(),
            [(
                "XDG_STATE_HOME".to_owned(),
                state.path().as_os_str().to_owned(),
            )],
        )
    }

    #[test]
    fn summary_without_a_deadline_is_complete() {
        let home = tempfile::tempdir().unwrap();
        let state = seeded_state();
        let summary = trash_summary(&ctx(&home, &state)).unwrap().unwrap();

        assert!(!summary.entries_lower_bound);
        assert!(!summary.bytes_lower_bound);
        assert_eq!(summary.entries, 1);
        assert!(summary.bytes_allocated >= 4096);
    }

    #[test]
    fn an_elapsed_deadline_marks_the_summary_incomplete_without_measuring() {
        let home = tempfile::tempdir().unwrap();
        let state = seeded_state();
        let ctx = ctx(&home, &state).with_deadline(Some(Instant::now()));

        let summary = trash_summary(&ctx).unwrap().unwrap();

        assert!(summary.entries_lower_bound);
        assert!(summary.bytes_lower_bound);
        assert_eq!(summary.entries, 0);
        assert_eq!(summary.bytes_allocated, 0);
    }

    #[test]
    fn count_entries_stops_and_flags_a_floor_when_the_budget_is_spent() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["0001-a", "0002-b", "0003-c"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let ctx = ctx(&home, &state).with_deadline(Some(Instant::now()));
        let entries = std::fs::read_dir(dir.path()).unwrap();

        let counted = count_entries(entries, dir.path(), &ctx).unwrap();

        // A spent budget abandons the walk rather than tallying every entry, and
        // reports the truncation so the count reads as a floor, not an exact total.
        assert!(counted.truncated);
        assert!(counted.count < 3);
    }

    #[test]
    fn a_spent_budget_stops_the_claims_walk_and_flags_a_floor() {
        use super::super::claims::interrupted_purge_claims_until;

        let trash = tempfile::tempdir().unwrap();
        let claims = trash.path().join(".claims");
        std::fs::create_dir(&claims).unwrap();
        std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(claims.join("0002"), b"cache-a").unwrap();
        std::fs::write(claims.join("0003"), b"cache-b").unwrap();

        let bounded = interrupted_purge_claims_until(trash.path(), Some(Instant::now())).unwrap();

        // The scan already spent its budget, so the claims walk stops rather than
        // draining a possibly huge directory, and flags the count as a floor.
        assert!(bounded.truncated);
        assert!(bounded.claims.len() < 2);
    }
}
