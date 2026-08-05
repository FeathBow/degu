use super::{DiscoveryScope, path_error, read_entries};
use degu_core::ecosystem::{DetectCtx, ScanOutcome};
use degu_core::safety::ProtectionPolicy;
use std::path::{Path, PathBuf};

const MIN_LOOSE_CHECKPOINT_FILES: usize = 2;

#[derive(Clone, Copy)]
pub(super) struct RootScope<'a> {
    pub(super) discovery: DiscoveryScope<'a>,
    pub(super) ctx: &'a DetectCtx,
    pub(super) protection: &'a ProtectionPolicy,
}

pub(super) struct RootDiscovery<'a> {
    root: &'a Path,
    scope: RootScope<'a>,
    pending: Vec<PathBuf>,
    outcome: ScanOutcome,
}

impl<'a> RootDiscovery<'a> {
    pub(super) fn new(root: &'a Path, scope: RootScope<'a>) -> Self {
        Self {
            root,
            scope,
            pending: vec![root.to_path_buf()],
            outcome: ScanOutcome::default(),
        }
    }

    pub(super) fn run(mut self) -> ScanOutcome {
        loop {
            if self.deadline_reached() {
                break;
            }
            let Some(dir) = self.pending.pop() else { break };
            self.visit_dir(&dir);
            if self.outcome.truncated {
                break;
            }
        }
        self.outcome
    }

    fn visit_dir(&mut self, dir: &Path) {
        if self.deadline_reached() {
            return;
        }
        if self.scope.protection.contains_resolved(&[dir]).is_some() {
            tracing::debug!(path = %dir.display(), "skipping mixed-state AI tool directory");
            return;
        }
        match is_owned_by_effective_uid(dir) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(path = %dir.display(), "foreign-owned project directory refused");
                self.outcome.mark_incomplete_at(dir);
                return;
            }
            Err(error) => {
                tracing::warn!(path = %dir.display(), %error, "project directory ownership probe failed");
                self.outcome.mark_incomplete_at(dir);
                return;
            }
        }
        if is_claimed(dir, self.scope.discovery.claimed_roots) {
            tracing::debug!(path = %dir.display(), "skipping subtree claimed by an adapter root");
            return;
        }
        match classify_directory(dir, self.scope.ctx) {
            DirectoryClassification::Unclassified => self.visit_unclassified(dir),
            DirectoryClassification::Incomplete => {
                // Descend to keep reporting useful, but record this dir: its complete-world
                // claim could have vetoed every descendant, and the clean gate needs the path.
                self.outcome.mark_incomplete_at(dir);
                self.visit_unclassified(dir)
            }
            DirectoryClassification::Truncated { incomplete } => {
                if incomplete {
                    self.outcome.mark_incomplete_at(dir);
                }
                self.outcome.mark_truncated();
            }
            DirectoryClassification::Checkpoint => {
                self.visit_claimed(dir, DirectoryClassification::Checkpoint)
            }
            DirectoryClassification::Artifact(evidence) => {
                self.visit_claimed(dir, DirectoryClassification::Artifact(evidence))
            }
        }
    }

    fn visit_claimed(&mut self, dir: &Path, classification: DirectoryClassification) {
        if !self.claim_selected(classification) {
            tracing::debug!(path = %dir.display(), "skipping subtree claimed by an unselected project source");
            return;
        }
        if contains_claimed_descendant(dir, self.scope.discovery) {
            return;
        }
        if self.deadline_reached() {
            return;
        }
        let entries = match read_entries(dir) {
            Ok(entries) => entries,
            Err(error) => {
                // Degrading drops this claim's finding entirely (the cache-adapter side keeps
                // one with skipped > 0) -- the fail-closed direction: only the region record
                // survives, and the clean gate refuses anything touching it.
                tracing::warn!(path = %dir.display(), %error, "claimed directory read failed; degrading to an incomplete region");
                self.outcome.mark_incomplete_at(dir);
                return;
            }
        };
        if self.deadline_reached() {
            return;
        }
        let mut outcome = self.measure_claim(dir, classification);
        // A pathless measurement failure happened inside this claim.
        outcome.incomplete_regions.resolve_unlocated(dir);
        self.visit_classified(entries, DirectoryClaim { dir, outcome })
    }

    fn visit_unclassified(&mut self, dir: &Path) {
        if dir != self.root && is_dot_dir(dir) {
            return;
        }
        if self.deadline_reached() {
            return;
        }
        let entries = match read_entries(dir) {
            Ok(entries) => entries,
            Err(error) => {
                // A nested unreadable directory must not abort the root's scan: record the
                // region and continue. An unreadable ROOT stays a hard error in validate().
                tracing::warn!(path = %dir.display(), %error, "directory read failed; degrading to an incomplete region");
                self.outcome.mark_incomplete_at(dir);
                return;
            }
        };
        self.visit_entries(entries, dir)
    }

    fn visit_classified(&mut self, entries: std::fs::ReadDir, claim: DirectoryClaim<'_>) {
        if claim.outcome.truncated {
            self.outcome.merge(claim.outcome);
            return;
        }
        if claim
            .outcome
            .candidates
            .first()
            .is_some_and(|finding| finding.protected_boundaries > 0)
        {
            // The claim's candidates are discarded, but its incompleteness
            // and region provenance must survive.
            self.outcome.incomplete |= claim.outcome.incomplete;
            self.outcome
                .incomplete_regions
                .merge(claim.outcome.incomplete_regions);
            return self.visit_entries(entries, claim.dir);
        }
        let mut outcome = claim.outcome;
        match validate_entries(entries, claim.dir, self.scope.ctx) {
            Ok(true) => {}
            Ok(false) => outcome.mark_truncated(),
            Err(error) => {
                // The claim's measurement already merged; a failing
                // enumeration only demotes the claim to an incomplete region.
                tracing::warn!(path = %claim.dir.display(), %error, "claimed directory enumeration failed; degrading to an incomplete region");
                outcome.mark_incomplete_at(claim.dir);
            }
        }
        self.outcome.merge(outcome);
    }

    fn claim_selected(&self, classification: DirectoryClassification) -> bool {
        match classification {
            DirectoryClassification::Checkpoint => self.scope.discovery.sources.checkpoints,
            DirectoryClassification::Artifact(_) => self.scope.discovery.sources.artifacts,
            _ => unreachable!("only claimed classifications reach visit_claimed"),
        }
    }

    fn measure_claim(&self, dir: &Path, classification: DirectoryClassification) -> ScanOutcome {
        match classification {
            DirectoryClassification::Checkpoint => {
                crate::checkpoints::named_checkpoint_finding(dir, self.scope.ctx)
            }
            DirectoryClassification::Artifact(evidence) => {
                crate::artifacts::finding_for(dir, self.scope.ctx, evidence)
            }
            _ => unreachable!("only claimed classifications reach measure_claim"),
        }
    }

    fn visit_entries(&mut self, mut entries: std::fs::ReadDir, dir: &Path) {
        let mut checkpoint_files = Vec::new();
        loop {
            if self.deadline_reached() {
                return;
            }
            let Some(entry) = entries.next() else {
                break;
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    // Mid-enumeration failure (EIO, network FS): keep the entries already seen,
                    // record the region, stop this directory. The partial list may under-count
                    // the loose-checkpoint aggregation -- accepted: checkpoints are UserAsset and
                    // always report-only, so an under-count never grants clean authority.
                    tracing::warn!(path = %dir.display(), %error, "directory entry read failed; degrading to an incomplete region");
                    self.outcome.mark_incomplete_at(dir);
                    break;
                }
            };
            self.visit_entry(entry, &mut checkpoint_files);
        }
        if self.scope.discovery.sources.checkpoints
            && checkpoint_files.len() >= MIN_LOOSE_CHECKPOINT_FILES
        {
            if self.deadline_reached() {
                return;
            }
            let mut outcome = crate::checkpoints::loose_checkpoint_finding(
                dir,
                &checkpoint_files,
                self.scope.ctx,
            );
            outcome.incomplete_regions.resolve_unlocated(dir);
            self.outcome.merge(outcome);
        }
    }

    fn visit_entry(&mut self, entry: std::fs::DirEntry, checkpoint_files: &mut Vec<PathBuf>) {
        if self.deadline_reached() {
            return;
        }
        if let Some(progress) = &self.scope.ctx.progress {
            progress.add_resources(1, 0);
        }
        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                // The entry itself is the region that could not be inspected; siblings keep scanning.
                tracing::warn!(path = %path.display(), %error, "entry metadata probe failed; degrading to an incomplete region");
                self.outcome.mark_incomplete_at(&path);
                return;
            }
        };
        if metadata_uid(&metadata) != rustix::process::geteuid().as_raw() {
            tracing::warn!(path = %path.display(), "foreign-owned project entry refused");
            self.outcome.mark_incomplete_at(&path);
            return;
        }
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            self.pending.push(path);
        } else if self.scope.discovery.sources.checkpoints
            && file_type.is_file()
            && crate::checkpoints::is_checkpoint_file(&path)
        {
            checkpoint_files.push(path);
        }
    }

    fn deadline_reached(&mut self) -> bool {
        if !self.scope.ctx.deadline_elapsed() {
            return false;
        }
        self.outcome.mark_truncated();
        true
    }
}

#[derive(Clone, Copy)]
enum DirectoryClassification {
    Unclassified,
    Checkpoint,
    Artifact(crate::artifacts::ArtifactEvidence),
    Incomplete,
    Truncated { incomplete: bool },
}

struct DirectoryClaim<'a> {
    dir: &'a Path,
    outcome: ScanOutcome,
}

fn classify_directory(dir: &Path, ctx: &DetectCtx) -> DirectoryClassification {
    if crate::checkpoints::is_named_checkpoint_dir(dir) {
        return DirectoryClassification::Checkpoint;
    }
    match crate::artifacts::classify(dir, ctx) {
        crate::artifacts::ArtifactClassification::Match(evidence) => {
            DirectoryClassification::Artifact(evidence)
        }
        crate::artifacts::ArtifactClassification::Miss => DirectoryClassification::Unclassified,
        crate::artifacts::ArtifactClassification::Incomplete => DirectoryClassification::Incomplete,
        crate::artifacts::ArtifactClassification::Truncated { incomplete } => {
            DirectoryClassification::Truncated { incomplete }
        }
    }
}

fn validate_entries(
    mut entries: std::fs::ReadDir,
    dir: &Path,
    ctx: &DetectCtx,
) -> std::io::Result<bool> {
    loop {
        if ctx.deadline_elapsed() {
            return Ok(false);
        }
        let Some(entry) = entries.next() else {
            return Ok(true);
        };
        let entry = entry.map_err(|err| path_error("failed to read an entry in", dir, err))?;
        if ctx.deadline_elapsed() {
            return Ok(false);
        }
        let path = entry.path();
        entry
            .file_type()
            .map_err(|err| path_error("failed to inspect", &path, err))?;
    }
}

fn is_claimed(path: &Path, claimed: &[PathBuf]) -> bool {
    claimed.iter().any(|root| path.starts_with(root))
}

fn contains_claimed_descendant(path: &Path, scope: DiscoveryScope<'_>) -> bool {
    scope
        .claimed_roots
        .iter()
        .any(|root| root.as_path() != path && root.starts_with(path))
        || scope
            .dependency_claims
            .iter()
            .any(|dependency| dependency.starts_with(path))
}

fn is_owned_by_effective_uid(path: &Path) -> std::io::Result<bool> {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata_uid(&metadata) == rustix::process::geteuid().as_raw())
}

fn metadata_uid(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;

    metadata.uid()
}

fn is_dot_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}
