use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, RootProvenance, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MIN_AGE_DAYS: u64 = 10;
const ECOSYSTEM_ID: &str = "tmp";
const FACTS: FindingFacts = (Recovery::UserAsset, Ownership::Standalone, None);
const RATIONALE: &str =
    "aged temp file owned by you; site policies purge these -- review and remove manually";
const PARTIAL_RATIONALE: &str =
    "temp entry was only partially measured; size is a lower bound and no age claim is made";

pub struct Tmp;

impl Ecosystem for Tmp {
    fn id(&self) -> &'static str {
        ECOSYSTEM_ID
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        if ctx.env("SLURM_JOB_ID").is_some() {
            return RootOutcome::default();
        }

        let mut outcome = RootOutcome::default();
        let mut seen = HashSet::new();
        for root in [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")] {
            if ctx.deadline_elapsed() {
                outcome.mark_truncated();
                return outcome;
            }
            push_root(Root::well_known(root), &mut seen, &mut outcome);
        }
        if let Some(tmpdir) = ctx.env("TMPDIR").map(PathBuf::from) {
            if ctx.deadline_elapsed() {
                outcome.mark_truncated();
                return outcome;
            }
            let root = Root::redirect("TMPDIR", tmpdir);
            if crate::validate_root_path(ctx, ECOSYSTEM_ID, &root) {
                push_root(root, &mut seen, &mut outcome);
            } else {
                outcome.mark_incomplete();
            }
        }
        outcome
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        FACTS
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        if ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let root: &Path = &root.path;
        let mut entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::warn!(root = %root.display(), %err, "tmp scan failed");
                return ScanOutcome::failed();
            }
        };

        let uid = rustix::process::geteuid().as_raw();
        let mut outcome = ScanOutcome::default();
        let mut entries_seen = 0_u64;
        loop {
            if ctx.deadline_elapsed() {
                tracing::debug!(
                    adapter = self.id(),
                    root = %root.display(),
                    entries_seen,
                    "deadline stopped tmp enumeration"
                );
                outcome.mark_truncated();
                break;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            entries_seen = entries_seen.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::warn!(root = %root.display(), %err, "tmp entry scan failed");
                    outcome.mark_incomplete();
                    continue;
                }
            };
            outcome.merge(finding_for_path(&entry.path(), uid, ctx));
        }
        outcome
    }
}

fn finding_for_path(path: &Path, uid: u32, ctx: &DetectCtx) -> ScanOutcome {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if crate::is_missing_path_error(&err) => {
            tracing::debug!(path = %path.display(), %err, "tmp entry vanished during scan");
            return ScanOutcome::default();
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "tmp metadata probe failed");
            return ScanOutcome::failed();
        }
    };
    if meta.uid() != uid || is_degu_state_path(path, ctx) {
        return ScanOutcome::default();
    }
    let modified = match meta.modified() {
        Ok(modified) => modified,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "tmp modified-time probe failed");
            return ScanOutcome::failed();
        }
    };
    let entry_age_days = crate::age_days(Some(modified));
    if entry_age_days.is_none_or(|age| age < MIN_AGE_DAYS) {
        return ScanOutcome::default();
    }
    let outcome = crate::measure_finding(
        path,
        ctx,
        crate::FindingSpec {
            ecosystem: ECOSYSTEM_ID,
            kind: FindingKind::Other,
            facts: FACTS,
            rationale: RATIONALE,
        },
    );
    apply_tmp_age_policy(outcome, entry_age_days)
}

fn apply_tmp_age_policy(mut outcome: ScanOutcome, entry_age_days: Option<u64>) -> ScanOutcome {
    let partial = outcome.incomplete
        || outcome
            .candidates
            .iter()
            .any(|finding| finding.truncated || finding.unvisited_dirs > 0);
    if partial {
        outcome.mark_incomplete();
        for finding in &mut outcome.candidates {
            finding.age_days = None;
            finding.rationale = PARTIAL_RATIONALE.to_string();
        }
        return outcome;
    }
    for finding in &mut outcome.candidates {
        finding.age_days = finding.age_days.into_iter().chain(entry_age_days).min();
    }
    outcome
        .candidates
        .retain(|finding| finding.age_days.is_some_and(|age| age >= MIN_AGE_DAYS));
    outcome
}

fn push_root(root: Root, seen: &mut HashSet<PathBuf>, outcome: &mut RootOutcome) {
    let path = match fs::canonicalize(&root.path) {
        Ok(path) => path,
        Err(error) if crate::is_missing_path_error(&error) => return,
        Err(error) => {
            tracing::warn!(path = %root.path.display(), %error, "tmp root resolution failed");
            outcome.mark_incomplete();
            return;
        }
    };
    if !path_is_directory(&path, outcome) {
        return;
    }
    if seen.insert(path.clone()) {
        outcome.roots.push(Root {
            path,
            provenance: root.provenance,
            origin: root.origin,
            role: None,
        });
    } else if root.provenance == RootProvenance::Redirect
        && let Some(existing) = outcome
            .roots
            .iter_mut()
            .find(|existing| existing.path == path)
    {
        existing.provenance = RootProvenance::Redirect;
        existing.origin = root.origin;
    }
}

fn path_is_directory(path: &Path, outcome: &mut RootOutcome) -> bool {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => {
            tracing::warn!(path = %path.display(), "tmp root is not a directory");
            outcome.mark_incomplete();
            false
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "tmp root metadata probe failed");
            outcome.mark_incomplete();
            false
        }
    }
}

fn is_degu_state_path(path: &Path, ctx: &DetectCtx) -> bool {
    let state = ctx.xdg_state();
    path.components()
        .any(|component| component.as_os_str() == ".degu-trash")
        || path == state
        || path.starts_with(state.join("degu"))
        || path == state.join("trashroots")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn vanished_entries_are_clean_drops() {
        let ctx = DetectCtx::from_process().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone");
        std::fs::write(&path, [0_u8]).unwrap();
        std::fs::remove_file(&path).unwrap();

        let outcome = finding_for_path(&path, rustix::process::geteuid().as_raw(), &ctx);

        assert!(!outcome.incomplete);
        assert!(outcome.candidates.is_empty());
    }

    #[test]
    fn unreadable_entries_stay_incomplete() {
        let ctx = DetectCtx::from_process().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let inner = locked.join("inner");
        std::fs::write(&inner, [0_u8]).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o0)).unwrap();

        let outcome = finding_for_path(&inner, rustix::process::geteuid().as_raw(), &ctx);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(outcome.incomplete);
        assert!(outcome.candidates.is_empty());
    }
}
