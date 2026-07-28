use crate::finding::{FindingCandidate, FindingFacts};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;

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
    const FAILURE_SAMPLE_CAP: usize = 8;

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

    fn well_known_environment(variable: &'static str, path: PathBuf) -> Self {
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
}

pub struct RelocationRefusal {
    pub var: &'static str,
    pub reason: &'static str,
}

/// Detection context with a read-only snapshot of the process environment.
#[derive(Clone)]
pub struct DetectCtx {
    pub home: PathBuf,
    pub max_concurrency: Option<NonZeroUsize>,
    pub progress: Option<Arc<degu_walk::Progress>>,
    pub deadline: Option<Instant>,
    env: HashMap<OsString, OsString>,
    reported_invalid_roots: Arc<Mutex<HashSet<&'static str>>>,
}

#[derive(Debug, Error)]
pub enum DetectCtxError {
    #[error("HOME is not set; degu works strictly in user space")]
    MissingHome,
    #[error("failed to canonicalize HOME {path}")]
    HomeCanonicalize {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl DetectCtx {
    /// Missing $HOME is unrecoverable: degu works strictly in user space;
    /// home-less scratch containers are not a target environment.
    pub fn from_process() -> Result<Self, DetectCtxError> {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .ok_or(DetectCtxError::MissingHome)?;
        let home = std::fs::canonicalize(&home)
            .map_err(|source| DetectCtxError::HomeCanonicalize { path: home, source })?;
        Ok(Self {
            home,
            max_concurrency: None,
            progress: None,
            deadline: None,
            env: std::env::vars_os().collect(),
            reported_invalid_roots: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Test-support constructor: a context over an explicit home and env map,
    /// so a test can point discovery at a temp tree without mutating the shared
    /// process environment.
    #[doc(hidden)]
    pub fn for_test<K, V>(home: PathBuf, env: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            home,
            max_concurrency: None,
            progress: None,
            deadline: None,
            env: env
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            reported_invalid_roots: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn with_max_concurrency(mut self, max_concurrency: Option<NonZeroUsize>) -> Self {
        self.max_concurrency = max_concurrency;
        self
    }

    pub fn with_progress(mut self, progress: Option<Arc<degu_walk::Progress>>) -> Self {
        self.progress = progress;
        self
    }

    pub fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    pub fn deadline_elapsed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Empty strings count as unset (the usual `export FOO=` shell residue).
    pub fn env(&self, key: &str) -> Option<&OsStr> {
        self.env
            .get(OsStr::new(key))
            .map(OsString::as_os_str)
            .filter(|v| !v.is_empty())
    }

    pub fn claim_invalid_root_diagnostic(&self, source: &'static str) -> bool {
        self.reported_invalid_roots
            .lock()
            .expect("invalid-root diagnostic state poisoned")
            .insert(source)
    }

    pub fn xdg_cache(&self) -> Root {
        self.xdg_root("XDG_CACHE_HOME", ".cache")
    }

    pub fn xdg_data(&self) -> Root {
        self.xdg_root("XDG_DATA_HOME", ".local/share")
    }

    pub fn xdg_config(&self) -> PathBuf {
        self.env("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home.join(".config"))
    }

    pub fn xdg_state(&self) -> PathBuf {
        self.env("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home.join(".local/state"))
    }

    fn xdg_root(&self, variable: &'static str, fallback: &str) -> Root {
        self.env(variable)
            .map(|path| Root::well_known_environment(variable, PathBuf::from(path)))
            .unwrap_or_else(|| Root::well_known(self.home.join(fallback)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Renderers that walk the source chain print the io error themselves, so
    // repeating it in the display string would double it.
    #[test]
    fn home_canonicalize_display_does_not_repeat_its_source() {
        let error = DetectCtxError::HomeCanonicalize {
            path: PathBuf::from("/degu-test-home"),
            source: io::Error::from_raw_os_error(2),
        };
        let source = std::error::Error::source(&error)
            .expect("HomeCanonicalize must keep its source chain")
            .to_string();
        assert!(
            !error.to_string().contains(&source),
            "display repeats its source: {error}"
        );
    }

    #[test]
    fn recorded_root_failures_mark_incompleteness_and_survive_merges() {
        let mut outcome = RootOutcome::default();
        outcome.record_failure(
            PathBuf::from("/degu-test/.cache/pip"),
            io::Error::from_raw_os_error(2),
        );
        assert!(outcome.incomplete);

        let mut merged = RootOutcome::default();
        merged.merge(outcome);

        assert!(merged.incomplete);
        let failure = merged.failures.first().expect("failure sample survives");
        assert_eq!(failure.path, PathBuf::from("/degu-test/.cache/pip"));
        assert_eq!(
            failure.error.raw_os_error(),
            Some(2),
            "the OS error travels with the path"
        );
    }

    #[test]
    fn root_failure_sample_is_bounded() {
        let mut outcome = RootOutcome::default();
        for index in 0..=RootOutcome::FAILURE_SAMPLE_CAP {
            outcome.record_failure(
                PathBuf::from(format!("/degu-test-{index}")),
                io::Error::from_raw_os_error(2),
            );
        }
        assert_eq!(outcome.failures.len(), RootOutcome::FAILURE_SAMPLE_CAP);
    }

    fn sole_cause(regions: &IncompleteRegions) -> RegionCause {
        assert_eq!(regions.sample().len(), 1, "expected exactly one region");
        regions.sample()[0].cause()
    }

    #[test]
    fn dedup_collision_upgrades_protected_to_measurement() {
        let path = Path::new("/degu-test-region");
        let mut regions = IncompleteRegions::default();
        regions.record(path, RegionCause::Protected);
        regions.record(path, RegionCause::Measurement);
        assert_eq!(sole_cause(&regions), RegionCause::Measurement);
        assert!(regions.has_measurement_events());
    }

    #[test]
    fn dedup_collision_never_downgrades_measurement_to_protected() {
        let path = Path::new("/degu-test-region");
        let mut regions = IncompleteRegions::default();
        regions.record(path, RegionCause::Measurement);
        regions.record(path, RegionCause::Protected);
        assert_eq!(sole_cause(&regions), RegionCause::Measurement);
        assert!(regions.has_measurement_events());
    }

    #[test]
    fn merge_collision_upgrades_to_the_strictest_cause_in_both_orders() {
        let path = Path::new("/degu-test-region");
        let mut protected = IncompleteRegions::default();
        protected.record(path, RegionCause::Protected);
        let mut measurement = IncompleteRegions::default();
        measurement.record(path, RegionCause::Measurement);

        let mut protected_first = protected.clone();
        protected_first.merge(measurement.clone());
        assert_eq!(sole_cause(&protected_first), RegionCause::Measurement);

        let mut measurement_first = measurement;
        measurement_first.merge(protected);
        assert_eq!(sole_cause(&measurement_first), RegionCause::Measurement);
    }

    #[test]
    fn only_protected_samples_report_no_measurement_events() {
        let mut regions = IncompleteRegions::default();
        regions.record(Path::new("/degu-test-region"), RegionCause::Protected);
        assert!(!regions.has_measurement_events());
        assert_eq!(regions.protected_regions(), 1);

        regions.record_unlocated();
        assert!(
            regions.has_measurement_events(),
            "unsampled events must fail closed as measurement events"
        );
    }

    fn boundary_candidate() -> FindingCandidate {
        FindingCandidate {
            ecosystem: "test".to_string(),
            path: PathBuf::from("/degu-test-cache"),
            kind: crate::finding::FindingKind::PackageCache,
            bytes_apparent: 1,
            bytes_allocated: 1,
            age_days: None,
            bytes_hardlinked: 0,
            inodes: 1,
            skipped: 0,
            truncated: false,
            unvisited_dirs: 0,
            protected_boundaries: 1,
            protected_credential_boundaries: 0,
            recovery: crate::finding::Recovery::Unknown,
            ownership: crate::finding::Ownership::Unknown,
            hazard: None,
            rationale: "test fixture".to_string(),
        }
    }

    #[test]
    fn a_pure_protected_prune_records_a_protected_region() {
        let outcome = ScanOutcome::from_candidates(vec![boundary_candidate()]);
        assert!(outcome.incomplete, "the scan-level flag stays as today");
        assert_eq!(
            sole_cause(&outcome.incomplete_regions),
            RegionCause::Protected
        );
    }

    #[test]
    fn protected_boundaries_with_unvisited_dirs_fail_closed_as_measurement() {
        let mut candidate = boundary_candidate();
        candidate.unvisited_dirs = 1;
        let outcome = ScanOutcome::from_candidates(vec![candidate]);
        assert_eq!(
            sole_cause(&outcome.incomplete_regions),
            RegionCause::Measurement
        );
    }

    #[test]
    fn protected_boundaries_with_skips_or_truncation_fail_closed_as_measurement() {
        let mut skipped = boundary_candidate();
        skipped.skipped = 1;
        let outcome = ScanOutcome::from_candidates(vec![skipped]);
        assert_eq!(
            sole_cause(&outcome.incomplete_regions),
            RegionCause::Measurement
        );

        let mut truncated = boundary_candidate();
        truncated.truncated = true;
        let outcome = ScanOutcome::from_candidates(vec![truncated]);
        assert_eq!(
            sole_cause(&outcome.incomplete_regions),
            RegionCause::Measurement
        );
    }

    #[test]
    fn unvisited_only_and_truncated_only_candidates_mark_the_scan_incomplete() {
        for mutate in [
            (|c: &mut FindingCandidate| c.unvisited_dirs = 1) as fn(&mut FindingCandidate),
            |c: &mut FindingCandidate| c.truncated = true,
        ] {
            let mut candidate = boundary_candidate();
            candidate.protected_boundaries = 0;
            mutate(&mut candidate);
            let outcome = ScanOutcome::from_candidates(vec![candidate]);
            assert!(
                outcome.incomplete,
                "measurement counter must mark incomplete"
            );
            assert_eq!(
                sole_cause(&outcome.incomplete_regions),
                RegionCause::Measurement
            );
        }
    }
}
