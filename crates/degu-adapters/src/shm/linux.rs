#[path = "linux/process.rs"]
mod process;

use degu_core::ecosystem::{DetectCtx, Ecosystem, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const MIN_AGE: Duration = Duration::from_secs(60 * 60);
const RATIONALE: &str = "likely leaked shared-memory segment from a crashed job; other users' handles are not visible, verify before manual removal";
const PSM_RATIONALE: &str = "likely leaked shared-memory segment from a crashed job; other users' handles are not visible, verify before manual removal; psm_* may be Python shared_memory or Omni-Path PSM2";

pub struct Shm;

impl Ecosystem for Shm {
    fn id(&self) -> &'static str {
        "shm"
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        crate::resolve_existing_roots(
            ctx,
            self.id(),
            vec![Root::well_known(PathBuf::from("/dev/shm"))],
        )
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        super::FACTS
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        if ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let root = root.path.as_path();
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::warn!(root = %root.display(), %err, "shm scan failed");
                return ScanOutcome::failed();
            }
        };
        Scanner::new(root, ctx, self.id()).run(entries)
    }
}

struct Scanner<'a> {
    root: &'a Path,
    ctx: &'a DetectCtx,
    ecosystem: &'static str,
    uid: u32,
    outcome: ScanOutcome,
    entries_seen: u64,
}

impl<'a> Scanner<'a> {
    fn new(root: &'a Path, ctx: &'a DetectCtx, ecosystem: &'static str) -> Self {
        Self {
            root,
            ctx,
            ecosystem,
            uid: rustix::process::geteuid().as_raw(),
            outcome: ScanOutcome::default(),
            entries_seen: 0,
        }
    }

    fn run(mut self, mut entries: fs::ReadDir) -> ScanOutcome {
        loop {
            if self.ctx.deadline_elapsed() {
                self.mark_truncated();
                break;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            self.entries_seen = self.entries_seen.saturating_add(1);
            let Some(entry) = self.read_entry(entry) else {
                continue;
            };
            let finding = self.finding_for(entry);
            self.outcome.merge(finding);
            if self.outcome.truncated {
                break;
            }
        }
        self.outcome
    }

    fn read_entry(&mut self, entry: std::io::Result<fs::DirEntry>) -> Option<fs::DirEntry> {
        match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                tracing::warn!(root = %self.root.display(), %err, "shm entry scan failed");
                self.outcome.mark_incomplete();
                None
            }
        }
    }

    fn finding_for(&self, entry: fs::DirEntry) -> ScanOutcome {
        if self.ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "shm metadata probe failed");
                return ScanOutcome::failed();
            }
        };
        if !candidate_entry(&entry, &meta, self.uid) {
            return ScanOutcome::default();
        }
        let modified = match meta.modified() {
            Ok(modified) => modified,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "shm modified-time probe failed");
                return ScanOutcome::failed();
            }
        };
        if !old_enough(modified) {
            return ScanOutcome::default();
        }
        if let Some(outcome) = self.handle_exclusion(&path) {
            return outcome;
        }
        let mut outcome = crate::measure_finding(
            &path,
            self.ctx,
            crate::FindingSpec {
                ecosystem: self.ecosystem,
                kind: FindingKind::Other,
                facts: super::FACTS,
                rationale: rationale_for(&entry.file_name()),
            },
        );
        if let Some(finding) = outcome.candidates.first_mut() {
            finding.age_days = crate::age_days(Some(modified));
        }
        outcome
    }

    fn handle_exclusion(&self, path: &Path) -> Option<ScanOutcome> {
        match process::probe_same_uid_handles(path, self.uid, self.ctx.deadline) {
            process::HandleProbe::Clear => None,
            process::HandleProbe::Failed => Some(ScanOutcome::failed()),
            process::HandleProbe::Held => Some(ScanOutcome::default()),
            process::HandleProbe::Deadline => Some(ScanOutcome::truncated()),
        }
    }

    fn mark_truncated(&mut self) {
        tracing::debug!(
            adapter = self.ecosystem,
            root = %self.root.display(),
            entries_seen = self.entries_seen,
            "deadline stopped shm enumeration"
        );
        self.outcome.mark_truncated();
    }
}

fn candidate_entry(entry: &fs::DirEntry, meta: &fs::Metadata, uid: u32) -> bool {
    meta.uid() == uid && is_leak_name(&entry.file_name())
}

fn is_leak_name(name: &std::ffi::OsStr) -> bool {
    let name = name.as_bytes();
    name.starts_with(b"torch_")
        || name.starts_with(b"nccl-")
        || name.starts_with(b"sem.mp-")
        || name.starts_with(b"psm_")
        || name.starts_with(b"vader_segment.")
        || name.starts_with(b"sm_segment.")
}

fn rationale_for(name: &std::ffi::OsStr) -> &'static str {
    if name.as_bytes().starts_with(b"psm_") {
        PSM_RATIONALE
    } else {
        RATIONALE
    }
}

fn old_enough(modified: SystemTime) -> bool {
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .is_some_and(|age| age >= MIN_AGE)
}

#[cfg(test)]
#[path = "linux/tests.rs"]
mod tests;
