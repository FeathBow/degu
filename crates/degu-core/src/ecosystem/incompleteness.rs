//! Bounded provenance for scan incompleteness: the region ledger and its
//! measurement-vs-protected cause taxonomy.

use std::path::{Path, PathBuf};

/// Why a region was recorded incomplete. Gates cleaning mutations, so
/// fail-closed: anything not provably a deliberate guard prune is a
/// measurement problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionCause {
    /// Could not be fully measured or classified (probe error, deadline,
    /// overflow, unknown provenance). Mutation gates must treat these as
    /// blocking.
    Measurement,
    /// A deliberate, name-based guard prune at the walker boundary (AI-tool
    /// and credential names). Pre-descent, deterministic, one-directional —
    /// hidden content can never grant eligibility or change plan membership —
    /// so mutation gates may skip these regions. A discovery-time pre-descent
    /// skip records nothing: no candidate was measured there.
    Protected,
}

/// One recorded incomplete region: where the scan lost sight of the tree and
/// why.
#[derive(Debug, Clone)]
pub struct IncompleteRegion {
    path: PathBuf,
    cause: RegionCause,
}

impl IncompleteRegion {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cause(&self) -> RegionCause {
        self.cause
    }
}

/// Bounded provenance for scan incompleteness, following degu-walk's bounded
/// sample idiom. Events beyond the bound (`overflowed`) or without a usable
/// path (`unlocated`) have unknown provenance and fail closed as
/// [`RegionCause::Measurement`]. Never serialized: the JSON schema is frozen.
///
/// ```compile_fail,E0277
/// fn assert_serializable<T: serde::Serialize>() {}
/// assert_serializable::<degu_core::ecosystem::IncompleteRegions>();
/// ```
#[derive(Debug, Default, Clone)]
pub struct IncompleteRegions {
    sample: Vec<IncompleteRegion>,
    overflowed: u64,
    unlocated: u64,
}

impl IncompleteRegions {
    pub const SAMPLE_CAP: usize = 32;

    pub fn record(&mut self, path: &Path, cause: RegionCause) {
        if let Some(seen) = self.sample.iter_mut().find(|seen| seen.path == path) {
            // Dedup keeps the strictest cause: one measurement failure outweighs
            // any number of deliberate prunes.
            if cause == RegionCause::Measurement {
                seen.cause = RegionCause::Measurement;
            }
            return;
        }
        if self.sample.len() >= Self::SAMPLE_CAP {
            // The cause is dropped with the path; unknown provenance fails
            // closed, so overflow always counts as a measurement event.
            self.overflowed = self.overflowed.saturating_add(1);
            return;
        }
        self.sample.push(IncompleteRegion {
            path: path.to_path_buf(),
            cause,
        });
    }

    pub fn record_unlocated(&mut self) {
        self.unlocated = self.unlocated.saturating_add(1);
    }

    /// Attribute every unlocated event to `root`; valid only when the caller
    /// knows all merged events happened at or under `root`. Unlocated events
    /// carry no cause, so they resolve to [`RegionCause::Measurement`].
    pub fn resolve_unlocated(&mut self, root: &Path) {
        if self.unlocated == 0 {
            return;
        }
        self.unlocated = 0;
        self.record(root, RegionCause::Measurement);
    }

    pub fn merge(&mut self, other: Self) {
        self.overflowed = self.overflowed.saturating_add(other.overflowed);
        self.unlocated = self.unlocated.saturating_add(other.unlocated);
        for region in other.sample {
            self.record(&region.path, region.cause);
        }
    }

    pub fn sample(&self) -> &[IncompleteRegion] {
        &self.sample
    }

    /// Events whose location is not in the sample; every one fails closed as
    /// [`RegionCause::Measurement`].
    pub fn unsampled(&self) -> u64 {
        self.overflowed.saturating_add(self.unlocated)
    }

    /// Sampled measurement regions plus every unsampled event; a ledger
    /// holding only deliberate protected prunes returns false.
    pub fn has_measurement_events(&self) -> bool {
        self.unsampled() > 0
            || self
                .sample
                .iter()
                .any(|region| region.cause == RegionCause::Measurement)
    }

    /// Whether every recorded event is a deliberate protected prune. An
    /// incomplete scan whose ledger is empty broke the event<->record
    /// conservation invariant, so an empty ledger does not count as
    /// protected-only and callers fall through to their fail-closed paths.
    pub fn protected_prunes_only(&self) -> bool {
        !self.is_empty() && !self.has_measurement_events()
    }

    /// Sampled regions recorded as deliberate protected prunes.
    pub fn protected_regions(&self) -> usize {
        self.sample
            .iter()
            .filter(|region| region.cause == RegionCause::Protected)
            .count()
    }

    /// Path-bearing events dropped only because the sample bound was reached.
    pub fn overflowed(&self) -> u64 {
        self.overflowed
    }

    /// Events recorded without any usable path.
    pub fn unlocated(&self) -> u64 {
        self.unlocated
    }

    pub fn is_empty(&self) -> bool {
        self.sample.is_empty() && self.unsampled() == 0
    }
}
