mod locks;

use self::locks::{LockProbe, repo_lock_status};
use degu_core::ecosystem::{DetectCtx, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::fs::{self, DirEntry};
use std::path::Path;

pub(super) fn hub(root: &Path, ctx: &DetectCtx, ecosystem: &str) -> ScanOutcome {
    let scanner = Scanner::new(root, ctx, ecosystem);
    if ctx.deadline_elapsed() {
        return ScanOutcome::truncated();
    }
    let mut entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(root = %root.display(), %err, "huggingface hub scan failed");
            return ScanOutcome::failed();
        }
    };
    let mut outcome = ScanOutcome::default();
    loop {
        if ctx.deadline_elapsed() {
            outcome.mark_truncated();
            return outcome;
        }
        let Some(entry) = entries.next() else {
            break;
        };
        outcome.merge(scanner.repo_finding(entry));
        if outcome.truncated {
            return outcome;
        }
    }
    outcome.merge(scanner.orphan_locks());
    outcome
}

pub(super) fn whole_root(root: &Path, ctx: &DetectCtx, ecosystem: &str) -> ScanOutcome {
    // datasets have concurrent writers and the xet cache holds shared chunks, so
    // degu reports the root instead of deleting it -- reclaim with the tool.
    Scanner::new(root, ctx, ecosystem)
        .measure(MeasureRequest {
            path: root,
            kind: FindingKind::ModelCache,
            facts: coordinated_facts(),
            rationale: "HuggingFace datasets/xet cache; regenerable, but downloads coordinate through locks and xet chunks are shared, so degu reports it rather than deleting the whole root -- reclaim with huggingface-cli",
        })
}

struct Scanner<'a> {
    root: &'a Path,
    ctx: &'a DetectCtx,
    ecosystem: &'a str,
}

impl<'a> Scanner<'a> {
    fn new(root: &'a Path, ctx: &'a DetectCtx, ecosystem: &'a str) -> Self {
        Self {
            root,
            ctx,
            ecosystem,
        }
    }

    fn repo_finding(&self, entry: std::io::Result<DirEntry>) -> ScanOutcome {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(root = %self.root.display(), %err, "huggingface hub entry scan failed");
                return ScanOutcome::failed();
            }
        };
        let name = entry.file_name();
        let path = entry.path();
        let Some(name) = name.to_str() else {
            tracing::warn!(path = %path.display(), "huggingface hub entry name is not valid UTF-8");
            return ScanOutcome::failed();
        };
        if self.ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "huggingface hub entry type probe failed");
                return ScanOutcome::failed();
            }
        };
        if !is_repo_dir_name(name) || !file_type.is_dir() {
            return ScanOutcome::default();
        }
        self.repo_directory_finding(&path, name)
    }

    fn repo_directory_finding(&self, path: &Path, name: &str) -> ScanOutcome {
        match repo_lock_status(self.root, name, self.ctx) {
            LockProbe::Clear => {}
            LockProbe::Busy => return ScanOutcome::default(),
            LockProbe::Failed => return ScanOutcome::failed(),
            LockProbe::Deadline => return ScanOutcome::truncated(),
        }
        self.measure(MeasureRequest {
            path,
            kind: FindingKind::ModelCache,
            facts: costly_facts(),
            rationale: "HuggingFace hub repo; regenerable, but re-download costs real transfer and shared xet chunks are not released by deleting one repo",
        })
    }

    fn orphan_locks(&self) -> ScanOutcome {
        let locks = self.root.join(".locks");
        if self.ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let mut entries = match fs::read_dir(&locks) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return ScanOutcome::default();
            }
            Err(err) => {
                tracing::warn!(path = %locks.display(), %err, "huggingface lock scan failed");
                return ScanOutcome::failed();
            }
        };
        let mut outcome = ScanOutcome::default();
        loop {
            if self.ctx.deadline_elapsed() {
                outcome.mark_truncated();
                return outcome;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            outcome.merge(self.orphan_lock_finding(&locks, entry));
            if outcome.truncated {
                return outcome;
            }
        }
        outcome
    }

    fn orphan_lock_finding(&self, locks: &Path, entry: std::io::Result<DirEntry>) -> ScanOutcome {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(path = %locks.display(), %err, "huggingface lock entry scan failed");
                return ScanOutcome::failed();
            }
        };
        let path = entry.path();
        if self.ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "huggingface lock entry type probe failed");
                return ScanOutcome::failed();
            }
        };
        if !file_type.is_dir() {
            return ScanOutcome::default();
        }
        if self.ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        match self.root.join(entry.file_name()).try_exists() {
            Ok(true) => return ScanOutcome::default(),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "huggingface repo presence probe failed");
                return ScanOutcome::failed();
            }
        }
        // The repo dir can be absent transiently (concurrent delete/migrate/download
        // init) while another process still holds the lock; only a lock nobody holds
        // is a true orphan.
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            tracing::warn!(path = %path.display(), "huggingface lock dir name is not valid UTF-8");
            return ScanOutcome::failed();
        };
        match repo_lock_status(self.root, &name, self.ctx) {
            LockProbe::Clear => {}
            LockProbe::Busy => return ScanOutcome::default(),
            LockProbe::Failed => return ScanOutcome::failed(),
            LockProbe::Deadline => return ScanOutcome::truncated(),
        }
        self.measure(MeasureRequest {
            path: &path,
            kind: FindingKind::Other,
            facts: cheap_facts(),
            rationale: "HuggingFace leftover lock directory of a removed repo",
        })
    }

    fn measure(&self, request: MeasureRequest<'_>) -> ScanOutcome {
        crate::measure_finding(
            request.path,
            self.ctx,
            crate::FindingSpec {
                ecosystem: self.ecosystem,
                kind: request.kind,
                facts: request.facts,
                rationale: request.rationale,
            },
        )
    }
}

struct MeasureRequest<'a> {
    path: &'a Path,
    kind: FindingKind,
    facts: FindingFacts,
    rationale: &'a str,
}

fn is_repo_dir_name(name: &str) -> bool {
    super::HUB_REPO_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub(super) fn costly_facts() -> FindingFacts {
    (
        Recovery::Regenerable {
            cost: RegenCost::Costly,
        },
        Ownership::Standalone,
        None,
    )
}

pub(super) fn coordinated_facts() -> FindingFacts {
    (
        Recovery::Regenerable {
            cost: RegenCost::Costly,
        },
        Ownership::ToolCoordinated,
        None,
    )
}

fn cheap_facts() -> FindingFacts {
    (
        Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        Ownership::Standalone,
        None,
    )
}

#[cfg(test)]
mod tests;
