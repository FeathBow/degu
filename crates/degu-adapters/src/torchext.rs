use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{FindingFacts, FindingKind, Ownership, Recovery, RegenCost};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const ECOSYSTEM_ID: &str = "torchext";
const FACTS: FindingFacts = (
    Recovery::Regenerable {
        cost: RegenCost::Costly,
    },
    Ownership::Standalone,
    None,
);
const RATIONALE: &str = "PyTorch extension cache for a specific Python/CUDA build; stale torch/CUDA combos are rebuilt by the next extension build";

pub struct Torchext;

impl Ecosystem for Torchext {
    fn id(&self) -> &'static str {
        ECOSYSTEM_ID
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        let candidates = vec![
            ctx.env("TORCH_EXTENSIONS_DIR")
                .map(|dir| Root::redirect("TORCH_EXTENSIONS_DIR", PathBuf::from(dir)))
                .unwrap_or_else(|| crate::platform_cache_root(ctx, "torch_extensions")),
        ];
        crate::resolve_existing_roots(ctx, self.id(), candidates)
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "TORCH_EXTENSIONS_DIR",
            subdir: "torch_extensions",
            role: None,
        }]
    }

    fn stated_facts(&self, _root: &Root) -> FindingFacts {
        FACTS
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        let root: &Path = &root.path;
        if ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let mut entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::warn!(root = %root.display(), %err, "torchext version scan failed");
                return ScanOutcome::failed();
            }
        };

        let mut outcome = ScanOutcome::default();
        loop {
            if ctx.deadline_elapsed() {
                outcome.mark_truncated();
                break;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            outcome.merge(scan_version_entry(entry, root, ctx));
            if outcome.truncated {
                break;
            }
        }
        outcome
    }
}

fn scan_version_entry(
    entry: io::Result<fs::DirEntry>,
    root: &Path,
    ctx: &DetectCtx,
) -> ScanOutcome {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            tracing::warn!(root = %root.display(), %err, "torchext version entry scan failed");
            return ScanOutcome::failed();
        }
    };
    let path = entry.path();
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "torchext version type probe failed");
            return ScanOutcome::failed();
        }
    };
    if !file_type.is_dir() {
        return ScanOutcome::default();
    }
    match version_lock_status(&path, ctx) {
        LockProbe::Clear if !ctx.deadline_elapsed() => measure_version(&path, ctx),
        LockProbe::Deadline | LockProbe::Clear => ScanOutcome::truncated(),
        LockProbe::Busy => {
            tracing::warn!(path = %path.display(), "torchext version skipped because an extension lock file is present");
            ScanOutcome::default()
        }
        LockProbe::Failed => ScanOutcome::failed(),
    }
}

fn measure_version(path: &Path, ctx: &DetectCtx) -> ScanOutcome {
    crate::measure_finding(
        path,
        ctx,
        crate::FindingSpec {
            ecosystem: ECOSYSTEM_ID,
            kind: FindingKind::BuildArtifact,
            facts: FACTS,
            rationale: RATIONALE,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockProbe {
    Clear,
    Busy,
    Failed,
    Deadline,
}

fn version_lock_status(version: &Path, ctx: &DetectCtx) -> LockProbe {
    if ctx.deadline_elapsed() {
        return LockProbe::Deadline;
    }
    let mut entries = match fs::read_dir(version) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(path = %version.display(), %err, "torchext version lock probe failed");
            return LockProbe::Failed;
        }
    };

    loop {
        if ctx.deadline_elapsed() {
            return LockProbe::Deadline;
        }
        let Some(entry) = entries.next() else {
            break;
        };
        match version_entry_lock_status(version, entry, ctx) {
            LockProbe::Clear => {}
            status => return status,
        }
    }

    LockProbe::Clear
}

fn version_entry_lock_status(
    version: &Path,
    entry: io::Result<fs::DirEntry>,
    ctx: &DetectCtx,
) -> LockProbe {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            tracing::warn!(path = %version.display(), %err, "torchext extension entry lock probe failed");
            return LockProbe::Failed;
        }
    };
    let path = entry.path();
    match entry.file_type() {
        Ok(file_type) if file_type.is_dir() => extension_lock_status(&path, ctx),
        Ok(_) => LockProbe::Clear,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "torchext extension type lock probe failed");
            LockProbe::Failed
        }
    }
}

fn extension_lock_status(extension: &Path, ctx: &DetectCtx) -> LockProbe {
    let mut pending = vec![extension.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if ctx.deadline_elapsed() {
            return LockProbe::Deadline;
        }
        let mut entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::warn!(path = %dir.display(), %err, "torchext extension lock probe failed");
                return LockProbe::Failed;
            }
        };
        loop {
            if ctx.deadline_elapsed() {
                return LockProbe::Deadline;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            match extension_entry_lock_status(entry, &dir, &mut pending) {
                LockProbe::Clear => {}
                status => return status,
            }
        }
    }
    LockProbe::Clear
}

fn extension_entry_lock_status(
    entry: std::io::Result<std::fs::DirEntry>,
    dir: &Path,
    pending: &mut Vec<PathBuf>,
) -> LockProbe {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            tracing::warn!(path = %dir.display(), %err, "torchext extension lock entry probe failed");
            return LockProbe::Failed;
        }
    };
    let path = entry.path();
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "torchext extension lock type probe failed");
            return LockProbe::Failed;
        }
    };
    if entry.file_name() == "lock" && file_type.is_file() {
        return LockProbe::Busy;
    }
    if file_type.is_dir() {
        pending.push(path);
    }
    LockProbe::Clear
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn expired_deadline_stops_lock_enumeration_and_propagates() {
        let root = tempfile::tempdir().unwrap();
        let version = root.path().join("py311_cu121");
        std::fs::create_dir(&version).unwrap();
        let entry = std::fs::read_dir(root.path()).unwrap().next().unwrap();
        let ctx = DetectCtx::from_process()
            .unwrap()
            .with_deadline(Some(Instant::now()));

        assert_eq!(extension_lock_status(&version, &ctx), LockProbe::Deadline);
        assert!(scan_version_entry(entry, root.path(), &ctx).truncated);
    }
}
