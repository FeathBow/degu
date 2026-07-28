use anyhow::Result;
use degu_core::ecosystem::IncompleteRegions;
use degu_core::finding::{Finding, FindingCandidate, consolidate_findings};

pub(crate) struct CollectionSection {
    findings: Vec<Finding>,
    status: ScanStatus,
    incomplete_regions: IncompleteRegions,
}

#[derive(Clone, Copy)]
pub(crate) struct ScanStatus {
    requested: bool,
    observation: SectionObservation,
}

#[derive(Clone, Copy, Default)]
pub(super) struct SectionObservation {
    truncated: bool,
    incomplete: bool,
    unvisited_dirs: u64,
}

pub(super) struct SectionProfile {
    pub(super) findings: usize,
    pub(super) total_inodes: u64,
    pub(super) status: ScanStatus,
}

impl CollectionSection {
    pub(super) fn new(requested: bool) -> Self {
        Self {
            findings: Vec::new(),
            status: ScanStatus {
                requested,
                observation: SectionObservation::default(),
            },
            incomplete_regions: IncompleteRegions::default(),
        }
    }

    /// Adapter root resolution failed or partially resolved: there is no
    /// reliable path for what was missed, so the provenance stays unlocated
    /// and mutation gates relying on it must fail closed.
    pub(super) fn mark_incomplete(&mut self) -> Result<()> {
        self.ensure_requested()?;
        self.status.observation.mark_incomplete();
        self.incomplete_regions.record_unlocated();
        Ok(())
    }

    pub(super) fn mark_truncated_if_requested(&mut self) {
        if self.status.requested {
            self.status.observation.mark_truncated();
        }
    }

    pub(super) fn record(
        &mut self,
        findings: Vec<Finding>,
        observation: SectionObservation,
        incomplete_regions: IncompleteRegions,
    ) -> Result<()> {
        self.ensure_requested()?;
        self.status.observation.merge(observation);
        self.incomplete_regions.merge(incomplete_regions);
        self.findings.extend(findings);
        Ok(())
    }

    pub(super) fn finish(mut self) -> Self {
        self.findings = consolidate_findings(self.findings);
        self
    }

    pub(crate) fn into_parts(self) -> (Vec<Finding>, ScanStatus, IncompleteRegions) {
        // Consumers gate on the provenance only after seeing `incomplete`,
        // so an incomplete section must carry at least one recorded event.
        // The reverse cannot be asserted (nor the flag derived from region
        // emptiness): regions also carry truncation provenance — a
        // deadline-truncated walk records its unvisited region without
        // marking the scan incomplete.
        debug_assert!(
            !self.status.is_incomplete() || !self.incomplete_regions.is_empty(),
            "incomplete scan section without recorded incompleteness provenance"
        );
        (self.findings, self.status, self.incomplete_regions)
    }

    pub(super) fn profile(&self) -> SectionProfile {
        SectionProfile {
            findings: self.findings.len(),
            total_inodes: self.findings.iter().fold(0_u64, |total, finding| {
                total.saturating_add(finding.inodes())
            }),
            status: self.status,
        }
    }

    fn ensure_requested(&self) -> Result<()> {
        if !self.status.requested {
            anyhow::bail!("attempted to collect an unrequested scan section");
        }
        Ok(())
    }
}

impl ScanStatus {
    pub(crate) fn as_str(self) -> &'static str {
        if !self.requested {
            "not_requested"
        } else if self.observation.truncated {
            "truncated"
        } else if self.observation.incomplete {
            "incomplete"
        } else {
            "complete"
        }
    }

    pub(crate) fn is_truncated(self) -> bool {
        self.observation.truncated
    }

    pub(crate) fn is_incomplete(self) -> bool {
        self.observation.incomplete
    }
}

impl SectionObservation {
    pub(super) fn from_candidates(
        candidates: &[FindingCandidate],
        incomplete: bool,
        truncated: bool,
    ) -> Self {
        let unvisited_dirs = candidates.iter().fold(0_u64, |total, finding| {
            total.saturating_add(finding.unvisited_dirs)
        });
        Self {
            truncated: truncated || candidates.iter().any(|finding| finding.truncated),
            incomplete: incomplete || unvisited_dirs > 0,
            unvisited_dirs,
        }
    }

    pub(super) fn observe_findings(&mut self, findings: &[Finding]) {
        self.incomplete |= findings.iter().any(|finding| finding.skipped() > 0);
    }

    pub(super) fn mark_incomplete(&mut self) {
        self.incomplete = true;
    }

    pub(super) fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    pub(super) fn is_truncated(self) -> bool {
        self.truncated
    }

    pub(super) fn is_incomplete(self) -> bool {
        self.incomplete
    }

    pub(super) fn unvisited_dirs(self) -> u64 {
        self.unvisited_dirs
    }

    fn merge(&mut self, other: Self) {
        self.truncated |= other.truncated;
        self.incomplete |= other.incomplete;
        self.unvisited_dirs = self.unvisited_dirs.saturating_add(other.unvisited_dirs);
    }
}
