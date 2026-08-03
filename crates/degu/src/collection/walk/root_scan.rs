use super::{AdapterRootScan, Collector, DiscoveryScope};
use crate::collection::adapters::exclude_claimed_candidates;
use crate::collection::metrics::elapsed_ms;
use crate::collection::protection::{
    apply_candidate_constraints, apply_mixed_state_constraints, finalize_candidates, finding_source,
};
use crate::collection::section::SectionObservation;
use anyhow::{Context, Result};
use degu_adapters::{AdapterScope, discovery::ValidatedProjectRoot};
use degu_core::ecosystem::{IncompleteRegions, RegionCause, ScanOutcome};
use degu_core::finding::{Finding, FindingKind, FindingSource, finalize_findings};
use std::path::Path;
use std::time::Instant;

impl Collector<'_> {
    pub(super) fn scan_adapter_root(&self, request: AdapterRootScan<'_>) -> Result<RootScan> {
        let ecosystem = request.registration.ecosystem();
        let span = tracing::info_span!(
            target: "degu",
            "scan",
            ecosystem = ecosystem.id(),
            root = %request.root.path.display()
        );
        let _guard = span.enter();
        let started = Instant::now();
        let outcome = match std::fs::symlink_metadata(&request.root.path) {
            Ok(metadata) if !metadata.file_type().is_symlink() => {
                ecosystem.scan(request.root, self.ctx)
            }
            Ok(_) => {
                tracing::warn!(root = %request.root.path.display(), "symlink adapter root refused");
                ScanOutcome::failed()
            }
            Err(error) => {
                tracing::warn!(root = %request.root.path.display(), %error, "adapter root metadata probe failed");
                ScanOutcome::failed()
            }
        };
        let result = self.finalize_adapter_root(request, outcome)?;
        log_adapter_scan(&result, started);
        Ok(result)
    }

    fn finalize_adapter_root(
        &self,
        request: AdapterRootScan<'_>,
        outcome: ScanOutcome,
    ) -> Result<RootScan> {
        let ScanOutcome {
            mut candidates,
            incomplete,
            truncated,
            mut incomplete_regions,
        } = outcome;
        let scope = request.registration.scope();
        let mut observation =
            SectionObservation::from_candidates(&candidates, incomplete, truncated);
        // Claim exclusion drops a candidate this scan measured, so the
        // region is a measurement gap, not a deliberate prune.
        for dropped in exclude_claimed_candidates(&mut candidates, request.claims)? {
            observation.mark_incomplete();
            incomplete_regions.record(&dropped, RegionCause::Measurement);
        }
        if candidates.is_empty() {
            return Ok(RootScan::new(
                Vec::new(),
                observation,
                scope,
                incomplete_regions,
                &request.root.path,
            ));
        }
        let source = finding_source(request.registration.id(), request.root, candidates.len());
        let constraint = apply_mixed_state_constraints(
            request.root,
            &mut candidates,
            self.ctx,
            &mut incomplete_regions,
        )?;
        let findings = finalize_candidates(candidates, source, constraint);
        Ok(RootScan::new(
            findings,
            observation,
            scope,
            incomplete_regions,
            &request.root.path,
        ))
    }

    pub(super) fn scan_artifact_root(
        &self,
        root: &ValidatedProjectRoot,
        scope: DiscoveryScope<'_>,
    ) -> Result<RootScan> {
        let root_path = root.as_path();
        let span = tracing::info_span!(
            target: "degu",
            "scan",
            ecosystem = "project_roots",
            root = %root_path.display()
        );
        let _guard = span.enter();
        let started = Instant::now();
        let discovery = degu_adapters::discovery::DiscoveryScope {
            claimed_roots: scope.claimed_roots,
            dependency_claims: &scope.exclusion_claims.dependencies,
            sources: scope.sources,
        };
        let outcome =
            degu_adapters::discovery::discover(std::slice::from_ref(root), discovery, self.ctx)
                .with_context(|| format!("failed to scan project root {}", root_path.display()))?;
        let result = self.finalize_artifact_root(scope, root_path, outcome)?;
        log_artifact_scan(&result, started);
        Ok(result)
    }

    fn finalize_artifact_root(
        &self,
        scope: DiscoveryScope<'_>,
        root: &Path,
        outcome: ScanOutcome,
    ) -> Result<RootScan> {
        let ScanOutcome {
            mut candidates,
            incomplete,
            truncated,
            mut incomplete_regions,
        } = outcome;
        let mut observation =
            SectionObservation::from_candidates(&candidates, incomplete, truncated);
        // Same claim-exclusion measurement gap as the adapter-root path.
        for dropped in exclude_claimed_candidates(&mut candidates, scope.exclusion_claims)? {
            observation.mark_incomplete();
            incomplete_regions.record(&dropped, RegionCause::Measurement);
        }
        if candidates.is_empty() {
            return Ok(RootScan::new(
                Vec::new(),
                observation,
                AdapterScope::Cache,
                incomplete_regions,
                root,
            ));
        }
        apply_candidate_constraints(&mut candidates, self.ctx, &mut incomplete_regions)?;
        let findings = finalize_findings(candidates, FindingSource::ProjectRoot);
        Ok(RootScan::new(
            findings,
            observation,
            AdapterScope::Cache,
            incomplete_regions,
            root,
        ))
    }
}

pub(super) struct RootScan {
    pub(super) findings: Vec<Finding>,
    pub(super) scan: SectionObservation,
    pub(super) scope: AdapterScope,
    pub(super) incomplete_regions: IncompleteRegions,
}

impl RootScan {
    pub(super) fn new(
        findings: Vec<Finding>,
        mut observation: SectionObservation,
        scope: AdapterScope,
        mut incomplete_regions: IncompleteRegions,
        root: &Path,
    ) -> Self {
        observation.observe_findings(&findings);
        // A scan is confined to the root it was given, so pathless
        // incompleteness events are attributed to that root; an incomplete
        // observation that recorded no region at all gets the same root
        // fallback so provenance is never silently lost. Both default to
        // Measurement: the cause of a lost event is unknown and fails closed.
        incomplete_regions.resolve_unlocated(root);
        if observation.is_incomplete() && incomplete_regions.is_empty() {
            incomplete_regions.record(root, RegionCause::Measurement);
        }
        Self {
            findings,
            scan: observation,
            scope,
            incomplete_regions,
        }
    }

    pub(super) fn bytes_allocated(&self) -> u64 {
        self.findings.iter().fold(0_u64, |total, finding| {
            total.saturating_add(finding.bytes_allocated())
        })
    }

    pub(super) fn inodes(&self) -> u64 {
        self.findings.iter().fold(0_u64, |total, finding| {
            total.saturating_add(finding.inodes())
        })
    }

    pub(super) fn skipped(&self) -> u64 {
        self.findings.iter().fold(0_u64, |total, finding| {
            total.saturating_add(finding.skipped())
        })
    }
}

pub(super) fn log_adapter_scan(result: &RootScan, started: Instant) {
    tracing::info!(
        target: "degu",
        findings = result.findings.len(),
        bytes_allocated = result.bytes_allocated(),
        inodes = result.inodes(),
        skipped = result.skipped(),
        incomplete = result.scan.is_incomplete(),
        truncated = result.scan.is_truncated(),
        unvisited_dirs = result.scan.unvisited_dirs(),
        elapsed_ms = elapsed_ms(started.elapsed()),
        "scan complete"
    );
}

pub(super) fn log_artifact_scan(result: &RootScan, started: Instant) {
    tracing::info!(
        target: "degu",
        artifacts_found = count_kind(&result.findings, FindingKind::BuildArtifact),
        checkpoints_found = count_kind(&result.findings, FindingKind::Checkpoint),
        bytes_allocated = result.bytes_allocated(),
        inodes = result.inodes(),
        skipped = result.skipped(),
        incomplete = result.scan.is_incomplete(),
        truncated = result.scan.is_truncated(),
        unvisited_dirs = result.scan.unvisited_dirs(),
        elapsed_ms = elapsed_ms(started.elapsed()),
        "scan complete"
    );
}

fn count_kind(findings: &[Finding], kind: FindingKind) -> usize {
    findings
        .iter()
        .filter(|finding| finding.kind() == kind)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::adapters::ExclusionClaims;
    use crate::collection::progress::ScanRootProgress;
    use degu_adapters::discovery::ProjectSources;
    use degu_core::config::Config;
    use degu_core::ecosystem::DetectCtx;
    use degu_core::finding::{FindingCandidate, FindingKind, Ownership, Recovery};
    use std::path::PathBuf;

    #[test]
    fn truncated_artifact_batch_is_still_finalized() {
        let root = tempfile::tempdir().unwrap();
        let ctx = DetectCtx::from_process().unwrap();
        let config = Config::default();
        let progress = ScanRootProgress::new();
        let collector = Collector::new(&ctx, &config, &progress);
        let claims = ExclusionClaims::default();
        let scope = DiscoveryScope {
            claimed_roots: &[],
            exclusion_claims: &claims,
            sources: ProjectSources::new(true, false),
        };
        let outcome = ScanOutcome {
            candidates: vec![candidate(root.path().to_path_buf())],
            incomplete: false,
            truncated: true,
            incomplete_regions: IncompleteRegions::default(),
        };

        let result = collector
            .finalize_artifact_root(scope, root.path(), outcome)
            .unwrap();

        assert_eq!(result.findings.len(), 1);
        assert!(result.scan.is_truncated());
    }

    fn candidate(path: PathBuf) -> FindingCandidate {
        FindingCandidate {
            ecosystem: "artifacts".to_string(),
            path,
            kind: FindingKind::BuildArtifact,
            bytes_apparent: 1,
            bytes_allocated: 1,
            age_days: None,
            bytes_hardlinked: 0,
            inodes: 1,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            shared_writable_dirs: 0,
            protected_boundaries: 0,
            protected_credential_boundaries: 0,
            recovery: Recovery::Unknown,
            ownership: Ownership::Unknown,
            hazard: None,
            rationale: "test fixture".to_string(),
        }
    }
}
