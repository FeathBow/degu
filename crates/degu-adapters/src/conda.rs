use degu_core::ecosystem::{DetectCtx, Ecosystem, Relocation, Root, RootOutcome, ScanOutcome};
use degu_core::finding::{
    FindingCandidate, FindingFacts, FindingKind, Hazard, Ownership, Recovery, RegenCost,
};
use std::path::Path;
use std::time::SystemTime;

mod roots;

const ECOSYSTEM_ID: &str = "conda";
const ROLE_ENVIRONMENT: &str = "environment";
const PACKAGE_RATIONALE: &str = "hardlink installs survive, but softlink installs (cross-filesystem, common on clusters) do not, so review with --include-review is required";

pub struct Conda;

#[derive(Default)]
struct MetadataScan {
    newest: Option<SystemTime>,
    incomplete: bool,
    truncated: bool,
}

impl MetadataScan {
    fn truncated(incomplete: bool) -> Self {
        Self {
            incomplete,
            truncated: true,
            ..Self::default()
        }
    }
}

fn newest_conda_meta_json_mtime(env: &Path, ctx: &DetectCtx) -> MetadataScan {
    if ctx.deadline_elapsed() {
        return MetadataScan::truncated(false);
    }
    let conda_meta = env.join("conda-meta");
    let entries = match std::fs::read_dir(&conda_meta) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::debug!(path = %conda_meta.display(), %err, "conda-meta scan failed");
            return fallback_environment_mtime(env, ctx, true);
        }
    };
    scan_conda_meta_entries(env, entries, ctx)
}

fn scan_conda_meta_entries(
    env: &Path,
    mut entries: std::fs::ReadDir,
    ctx: &DetectCtx,
) -> MetadataScan {
    let conda_meta = env.join("conda-meta");
    let mut scan = MetadataScan::default();
    loop {
        if ctx.deadline_elapsed() {
            return MetadataScan::truncated(scan.incomplete);
        }
        let Some(entry) = entries.next() else {
            break;
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::debug!(path = %conda_meta.display(), %err, "conda-meta entry scan failed");
                scan.incomplete = true;
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if ctx.deadline_elapsed() {
            return MetadataScan::truncated(scan.incomplete);
        }
        let mtime = match entry.metadata().and_then(|meta| meta.modified()) {
            Ok(mtime) => mtime,
            Err(err) => {
                tracing::debug!(path = %path.display(), %err, "conda-meta metadata probe failed");
                scan.incomplete = true;
                continue;
            }
        };
        scan.newest = scan.newest.max(Some(mtime));
    }
    if scan.newest.is_some() {
        return scan;
    }
    fallback_environment_mtime(env, ctx, scan.incomplete)
}

fn fallback_environment_mtime(env: &Path, ctx: &DetectCtx, incomplete: bool) -> MetadataScan {
    if ctx.deadline_elapsed() {
        return MetadataScan::truncated(incomplete);
    }
    let newest = env.metadata().and_then(|meta| meta.modified()).ok();
    MetadataScan {
        newest,
        incomplete: incomplete || newest.is_none(),
        truncated: false,
    }
}

fn environment_rationale(age_days: Option<u64>) -> String {
    let age = age_days
        .map(|days| format!("{days} days ago"))
        .unwrap_or_else(|| "at an unknown time".to_string());
    format!(
        "conda environment; last package operation {age}; hardlink sharing with the package cache means deleting it may not free the full reported size, and degu never cleans environments"
    )
}

fn environment_candidate(
    root: &Path,
    stats: &degu_walk::WalkStats,
    ctx: &DetectCtx,
    facts: FindingFacts,
) -> (FindingCandidate, MetadataScan) {
    let metadata = if stats.truncated {
        MetadataScan::truncated(false)
    } else {
        newest_conda_meta_json_mtime(root, ctx)
    };
    let age_days = crate::age_days(metadata.newest);
    let (recovery, ownership, hazard) = facts;
    let candidate = FindingCandidate {
        ecosystem: ECOSYSTEM_ID.to_string(),
        path: root.to_path_buf(),
        kind: FindingKind::Environment,
        bytes_apparent: stats.bytes_apparent,
        bytes_allocated: stats.bytes_allocated,
        age_days,
        bytes_hardlinked: stats.bytes_hardlinked,
        inodes: stats.inodes,
        skipped: stats.skipped_total,
        truncated: stats.truncated,
        unvisited_dirs: stats.unvisited_dirs,
        protected_boundaries: stats.excluded_entries,
        protected_credential_boundaries: stats.excluded_credential_boundaries,
        recovery,
        ownership,
        hazard,
        rationale: environment_rationale(age_days),
    };
    (candidate, metadata)
}

fn package_candidate(
    root: &Path,
    stats: &degu_walk::WalkStats,
    facts: FindingFacts,
) -> FindingCandidate {
    let (recovery, ownership, hazard) = facts;
    FindingCandidate {
        ecosystem: ECOSYSTEM_ID.to_string(),
        path: root.to_path_buf(),
        kind: FindingKind::PackageCache,
        bytes_apparent: stats.bytes_apparent,
        bytes_allocated: stats.bytes_allocated,
        age_days: crate::age_days(stats.newest_mtime),
        bytes_hardlinked: stats.bytes_hardlinked,
        inodes: stats.inodes,
        skipped: stats.skipped_total,
        truncated: stats.truncated,
        unvisited_dirs: stats.unvisited_dirs,
        protected_boundaries: stats.excluded_entries,
        protected_credential_boundaries: stats.excluded_credential_boundaries,
        recovery,
        ownership,
        hazard,
        rationale: PACKAGE_RATIONALE.to_string(),
    }
}

impl Ecosystem for Conda {
    fn id(&self) -> &'static str {
        ECOSYSTEM_ID
    }

    fn roots(&self, ctx: &DetectCtx) -> RootOutcome {
        roots::discover(ctx)
    }

    fn stated_facts(&self, root: &Root) -> FindingFacts {
        if root.role == Some(ROLE_ENVIRONMENT) {
            (Recovery::UserAsset, Ownership::Standalone, None)
        } else {
            (
                Recovery::Regenerable {
                    cost: RegenCost::Cheap,
                },
                Ownership::Standalone,
                Some(Hazard::BreaksConsumers),
            )
        }
    }

    fn relocations(&self) -> Vec<Relocation> {
        vec![Relocation {
            var: "CONDA_PKGS_DIRS",
            subdir: "conda-pkgs",
            role: None,
        }]
    }

    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome {
        let path: &Path = &root.path;
        if ctx.deadline_elapsed() {
            return ScanOutcome::truncated();
        }
        let opts = crate::walk_options(ctx);
        let stats = match degu_walk::measure(path, &opts) {
            Ok(s) => s,
            Err(err) if crate::is_missing_path_error(&err) => {
                tracing::debug!(root = %path.display(), %err, "conda root vanished during scan");
                return ScanOutcome::default();
            }
            Err(err) => {
                tracing::warn!(root = %path.display(), %err, "conda package cache scan failed");
                return ScanOutcome::failed();
            }
        };
        crate::log_skipped_samples(self.id(), &stats);
        let facts = self.stated_facts(root);
        if root.role == Some(ROLE_ENVIRONMENT) {
            let (candidate, metadata) = environment_candidate(path, &stats, ctx, facts);
            let mut outcome = ScanOutcome::from_candidates(vec![candidate]);
            if metadata.incomplete {
                outcome.mark_incomplete_at(path);
            }
            outcome.truncated |= metadata.truncated;
            outcome
        } else {
            ScanOutcome::from_candidates(vec![package_candidate(path, &stats, facts)])
        }
    }
}

#[cfg(test)]
mod tests;
