//! The ecosystem adapter contract and its discovery/scan outcome types.

use super::environment::DetectCtx;
use super::incompleteness::{IncompleteRegions, RegionCause};
use crate::finding::{FindingCandidate, FindingFacts};
use std::io;
use std::path::{Path, PathBuf};

/// An ecosystem adapter: discovers, never deletes.
pub trait Ecosystem: Send + Sync {
    /// Stable id used for config switches, JSON output, and log fields
    fn id(&self) -> &'static str;

    /// Locate cache roots. Must honor redirect env vars (HF_HOME,
    /// PIP_CACHE_DIR, …): HPC users relocate caches to scratch, and a
    /// defaults-only tool misses or double-counts them. Stop before a new
    /// enumeration unit once `ctx.deadline_elapsed()`; discovery failures set
    /// `RootOutcome::incomplete` — a missing candidate is a complete empty
    /// result.
    fn roots(&self, ctx: &DetectCtx) -> RootOutcome;

    /// Scan one cache root read-only, honoring the shared deadline between
    /// enumeration units.
    fn scan(&self, root: &Root, ctx: &DetectCtx) -> ScanOutcome;

    /// Static disposition facts for findings under `root`, varying only by
    /// source or root role. `scan` must state the same class; a mixed root
    /// states its primary's.
    fn stated_facts(&self, root: &Root) -> FindingFacts;

    /// Scheduling hint only, derived from [`Ecosystem::stated_facts`]:
    /// report-only facts defer the root. Overriding requires a stated reason;
    /// disposition derivation remains the sole cleanup authority.
    fn scan_priority(&self, root: &Root) -> ScanPriority {
        crate::disposition::scan_priority(self.stated_facts(root))
    }

    /// The platform this source requires, or `None` when universal. Default
    /// scans silently skip impossible sources; explicit selection must fail
    /// loudly instead of reporting complete-and-empty.
    fn platform_requirement(&self) -> Option<&'static str> {
        None
    }

    fn relocations(&self) -> Vec<Relocation> {
        Vec::new()
    }

    fn relocation_refusals(&self) -> Vec<RelocationRefusal> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanPriority {
    Preferred,
    Deferred,
}

#[derive(Default)]
pub struct RootOutcome {
    pub roots: Vec<Root>,
    pub incomplete: bool,
    pub truncated: bool,
    /// Bounded provenance for `incomplete` (first failed probes), so refusing
    /// callers can name a path, OS error, and remedy — not just the adapter
    /// id. [`RootOutcome::mark_incomplete`] records no detail.
    pub failures: Vec<RootFailure>,
}

#[derive(Debug)]
pub struct RootFailure {
    pub path: PathBuf,
    pub error: io::Error,
}

impl RootOutcome {
    pub(crate) const FAILURE_SAMPLE_CAP: usize = 8;

    pub fn failed() -> Self {
        Self {
            incomplete: true,
            ..Self::default()
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.roots.extend(other.roots);
        self.incomplete |= other.incomplete;
        self.truncated |= other.truncated;
        for failure in other.failures {
            self.push_failure(failure);
        }
    }

    pub fn mark_incomplete(&mut self) {
        self.incomplete = true;
    }

    /// [`RootOutcome::mark_incomplete`] with provenance: records which root
    /// probe failed and why, keeping a bounded sample.
    pub fn record_failure(&mut self, path: PathBuf, error: io::Error) {
        self.incomplete = true;
        self.push_failure(RootFailure { path, error });
    }

    fn push_failure(&mut self, failure: RootFailure) {
        if self.failures.len() < Self::FAILURE_SAMPLE_CAP {
            self.failures.push(failure);
        }
    }

    pub fn mark_truncated(&mut self) {
        self.truncated = true;
    }
}
#[derive(Default)]
pub struct ScanOutcome {
    pub candidates: Vec<FindingCandidate>,
    pub incomplete: bool,
    pub truncated: bool,
    /// Provenance for `incomplete`: where this scan lost sight of the tree.
    pub incomplete_regions: IncompleteRegions,
}

impl ScanOutcome {
    /// The only source of [`RegionCause::Protected`] records: candidates
    /// whose sole incompleteness evidence is deliberate walker-boundary
    /// prunes. Any measurement counter wins [`RegionCause::Measurement`], the
    /// strictest tier.
    pub fn from_candidates(candidates: Vec<FindingCandidate>) -> Self {
        let mut incomplete_regions = IncompleteRegions::default();
        for candidate in &candidates {
            if let Some(cause) = candidate_region_cause(candidate) {
                incomplete_regions.record(&candidate.path, cause);
            }
        }
        // The ledger is the single source: unvisited-only and truncated
        // candidates now correctly mark the whole scan incomplete.
        let incomplete = !incomplete_regions.is_empty();
        let truncated = candidates.iter().any(|candidate| candidate.truncated);
        Self {
            candidates,
            incomplete,
            truncated,
            incomplete_regions,
        }
    }

    pub fn failed() -> Self {
        let mut outcome = Self {
            candidates: Vec::new(),
            incomplete: true,
            truncated: false,
            incomplete_regions: IncompleteRegions::default(),
        };
        outcome.incomplete_regions.record_unlocated();
        outcome
    }

    pub fn truncated() -> Self {
        Self {
            truncated: true,
            ..Self::default()
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.candidates.extend(other.candidates);
        self.incomplete |= other.incomplete;
        self.truncated |= other.truncated;
        self.incomplete_regions.merge(other.incomplete_regions);
    }

    pub fn mark_incomplete(&mut self) {
        self.incomplete = true;
        self.incomplete_regions.record_unlocated();
    }

    /// A probe, read, or enumeration failure at `region`: always a
    /// measurement event. Deliberate prunes only enter through
    /// [`ScanOutcome::from_candidates`].
    pub fn mark_incomplete_at(&mut self, region: &Path) {
        self.incomplete = true;
        self.incomplete_regions
            .record(region, RegionCause::Measurement);
    }

    pub fn mark_truncated(&mut self) {
        self.truncated = true;
    }
}

/// A candidate's incompleteness cause: any measurement counter (skips,
/// unvisited dirs, truncation) is [`RegionCause::Measurement`]; a pure
/// deliberate prune is [`RegionCause::Protected`]; otherwise fully measured.
fn candidate_region_cause(candidate: &FindingCandidate) -> Option<RegionCause> {
    if candidate.skipped > 0 || candidate.unvisited_dirs > 0 || candidate.truncated {
        Some(RegionCause::Measurement)
    } else if candidate.protected_boundaries > 0 {
        Some(RegionCause::Protected)
    } else {
        None
    }
}

/// Cleanup confidence in a cache root: a `Redirect` root is selected outside
/// fixed defaults, so the collector requires corroborating evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootProvenance {
    WellKnown,
    Redirect,
}

/// Where a root path came from, independent of its cleanup confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOrigin {
    Fixed,
    Environment(&'static str),
}

/// A candidate cache root plus how it was resolved.
#[derive(Debug, Clone)]
pub struct Root {
    pub path: PathBuf,
    pub provenance: RootProvenance,
    pub origin: RootOrigin,
    /// Adapter-private tag telling an ecosystem's scan() which of its sibling roots this is (e.g. the HF hub vs datasets root). Core never interprets it.
    pub role: Option<&'static str>,
}

impl Root {
    pub fn well_known(path: PathBuf) -> Self {
        Self {
            path,
            provenance: RootProvenance::WellKnown,
            origin: RootOrigin::Fixed,
            role: None,
        }
    }

    pub fn redirect(variable: &'static str, path: PathBuf) -> Self {
        Self {
            path,
            provenance: RootProvenance::Redirect,
            origin: RootOrigin::Environment(variable),
            role: None,
        }
    }

    pub(super) fn well_known_environment(variable: &'static str, path: PathBuf) -> Self {
        Self {
            path,
            provenance: RootProvenance::WellKnown,
            origin: RootOrigin::Environment(variable),
            role: None,
        }
    }

    pub fn join(mut self, path: impl AsRef<Path>) -> Self {
        self.path.push(path.as_ref());
        self
    }

    pub fn with_role(mut self, role: &'static str) -> Self {
        self.role = Some(role);
        self
    }
}

pub struct Relocation {
    pub var: &'static str,
    pub subdir: &'static str,
    /// Binds this relocation to the same-named root role, so an adapter with
    /// several roots reports each current location only under its own export.
    pub role: Option<&'static str>,
}

pub struct RelocationRefusal {
    pub var: &'static str,
    pub reason: &'static str,
}
