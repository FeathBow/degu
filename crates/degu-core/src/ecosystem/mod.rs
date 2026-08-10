//! Ecosystem discovery contract, scan-incompleteness ledger, and detection
//! context, split across submodules. The public API is re-exported here so
//! `degu_core::ecosystem::X` paths stay unchanged.

mod discovery;
mod environment;
mod incompleteness;

pub use discovery::*;
pub use environment::*;
pub use incompleteness::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::FindingCandidate;
    use std::io;
    use std::path::{Path, PathBuf};

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
            shared_writable_dirs: 0,
            parent_grants_foreign_mutation: false,
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

    #[test]
    fn relative_xdg_config_and_state_paths_use_home_fallbacks() {
        let home = PathBuf::from("/home/degu-test");
        let ctx = DetectCtx::for_test(
            home.clone(),
            [
                ("XDG_CACHE_HOME", "relative-cache"),
                ("XDG_DATA_HOME", "relative-data"),
                ("XDG_CONFIG_HOME", "relative-config"),
                ("XDG_STATE_HOME", "relative-state"),
            ],
        );

        assert_eq!(ctx.xdg_cache().path, PathBuf::from("relative-cache"));
        assert_eq!(ctx.xdg_data().path, PathBuf::from("relative-data"));
        assert_eq!(ctx.xdg_config(), home.join(".config"));
        assert_eq!(ctx.xdg_state(), home.join(".local/state"));
    }
}
