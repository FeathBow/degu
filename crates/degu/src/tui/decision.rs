use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use degu_core::finding::Finding;

use crate::cli::{CleanArgs, JsonArgs, ScanLimitArgs};
use crate::findings::Filters;
use crate::tui::report::{Class, Section};

pub struct Decisions {
    chosen: BTreeSet<PathBuf>,
    default: BTreeSet<PathBuf>,
    sizes: BTreeMap<PathBuf, (u64, bool)>,
}

/// What a plan would move, carrying the same honesty the rest of the report
/// carries: a size measured from a truncated walk is a floor, and a sum that
/// overflowed is a floor too.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    pub locations: usize,
    pub bytes: u64,
    /// At least one member's size was a lower bound, or the sum saturated.
    pub lower_bound: bool,
}

impl Plan {
    pub fn add(&mut self, bytes: u64, lower_bound: bool) {
        self.locations += 1;
        self.lower_bound |= lower_bound;
        match self.bytes.checked_add(bytes) {
            Some(sum) => self.bytes = sum,
            None => {
                self.bytes = u64::MAX;
                self.lower_bound = true;
            }
        }
    }
}

impl Decisions {
    pub fn new(cache: &[Finding]) -> Self {
        let default: BTreeSet<PathBuf> = cache
            .iter()
            .filter(|finding| Class::of(finding, Section::Cache) == Class::Ready)
            .map(|finding| finding.path().to_path_buf())
            .collect();
        let sizes = cache
            .iter()
            .map(|finding| {
                (
                    finding.path().to_path_buf(),
                    (finding.bytes_allocated(), finding.measurement_incomplete()),
                )
            })
            .collect();
        Self {
            chosen: default.clone(),
            default,
            sizes,
        }
    }

    pub fn plan(&self) -> Plan {
        let mut plan = Plan::default();
        for path in &self.chosen {
            let (bytes, lower_bound) = self.sizes.get(path).copied().unwrap_or_default();
            plan.add(bytes, lower_bound);
        }
        plan
    }

    pub fn toggle(&mut self, finding: &Finding, section: Section) {
        if Class::of(finding, section) == Class::NotManaged {
            return;
        }
        let path = finding.path().to_path_buf();
        if !self.chosen.remove(&path) {
            self.chosen.insert(path);
        }
    }

    pub fn is_chosen(&self, finding: &Finding) -> bool {
        self.chosen.contains(finding.path())
    }

    pub fn is_empty(&self) -> bool {
        self.chosen.is_empty()
    }

    /// Every selectable finding outside the default set needs --include-review.
    fn includes_review(&self) -> bool {
        self.chosen.difference(&self.default).next().is_some()
    }

    pub fn clean_args(
        &self,
        filters: &Filters,
        limits: ScanLimitArgs,
        dry_run: bool,
    ) -> Option<CleanArgs> {
        if self.is_empty() {
            return None;
        }
        Some(CleanArgs {
            output: JsonArgs { json: false },
            limits,
            details: false,
            roots: filters.roots.clone(),
            include_review: self.includes_review(),
            review: None,
            yes: false,
            dry_run,
            purge: false,
            older_than: filters.older_than,
            only: filters.only.clone(),
            min_size: filters.min_size,
            top: filters.top,
            path: self.chosen.iter().cloned().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use degu_core::finding::{
        DispositionMode, FindingCandidate, FindingKind, FindingSource, Ownership, Recovery,
        RegenCost, finalize_findings,
    };

    fn finding(path: &str, recovery: Recovery) -> Finding {
        finalize_findings(
            vec![FindingCandidate {
                ecosystem: "test".to_owned(),
                path: PathBuf::from(path),
                kind: FindingKind::PackageCache,
                bytes_apparent: 4096,
                bytes_allocated: 4096,
                age_days: Some(30),
                bytes_hardlinked: 0,
                inodes: 1,
                skipped: 0,
                truncated: false,
                unvisited_dirs: 0,
                shared_writable_dirs: 0,
                parent_grants_foreign_mutation: false,
                protected_boundaries: 0,
                protected_credential_boundaries: 0,
                recovery,
                ownership: Ownership::Standalone,
                hazard: None,
                rationale: "fixture".to_owned(),
            }],
            FindingSource::WellKnownRoot,
        )
        .pop()
        .expect("one finalized finding")
    }

    fn ready(path: &str) -> Finding {
        finding(
            path,
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
        )
    }

    fn review(path: &str) -> Finding {
        finding(
            path,
            Recovery::Regenerable {
                cost: RegenCost::Costly,
            },
        )
    }

    fn unmanaged(path: &str) -> Finding {
        finding(path, Recovery::UserAsset)
    }

    fn filters() -> Filters {
        Filters {
            roots: vec![PathBuf::from("/authorized")],
            only: vec!["test".to_owned()],
            older_than: Some(30),
            min_size: Some(1024),
            top: Some(5),
        }
    }

    /// A floor anywhere in the plan makes the whole plan a floor, and a sum
    /// that overflows is one too. Reporting either as exact would overstate
    /// what a clean recovers.
    #[test]
    fn a_bounded_member_makes_the_whole_plan_a_lower_bound() {
        let mut plan = Plan::default();
        plan.add(10, false);
        assert!(!plan.lower_bound);
        plan.add(20, true);
        assert!(plan.lower_bound);
        assert_eq!(plan.bytes, 30);
        assert_eq!(plan.locations, 2);
    }

    #[test]
    fn a_saturating_sum_is_reported_as_a_lower_bound() {
        let mut plan = Plan::default();
        plan.add(u64::MAX, false);
        plan.add(1, false);
        assert_eq!(plan.bytes, u64::MAX);
        assert!(plan.lower_bound);
    }

    #[test]
    fn the_plan_starts_as_the_one_degu_would_build_alone() {
        let decisions = Decisions::new(&[ready("/y"), review("/r"), unmanaged("/n")]);
        assert!(decisions.is_chosen(&ready("/y")));
        assert!(!decisions.is_chosen(&review("/r")));
        assert!(!decisions.is_chosen(&unmanaged("/n")));
    }

    #[test]
    fn a_not_managed_finding_cannot_be_put_in_the_plan() {
        assert_eq!(
            unmanaged("/n").disposition().mode,
            DispositionMode::ReportOnly
        );
        let mut decisions = Decisions::new(&[unmanaged("/n")]);
        decisions.toggle(&unmanaged("/n"), Section::Cache);
        assert!(decisions.is_empty(), "a keystroke reached a withheld tier");
    }

    #[test]
    fn a_runtime_finding_cannot_be_put_in_the_plan() {
        let finding = review("/r");
        let mut decisions = Decisions::new(std::slice::from_ref(&finding));
        decisions.toggle(&finding, Section::Runtime);
        assert!(decisions.is_empty());
    }

    #[test]
    fn deciding_twice_returns_to_where_it_started() {
        let mut decisions = Decisions::new(&[ready("/y"), review("/r")]);
        for finding in [review("/r"), ready("/y")] {
            decisions.toggle(&finding, Section::Cache);
            decisions.toggle(&finding, Section::Cache);
        }
        assert!(decisions.is_chosen(&ready("/y")));
        assert!(!decisions.is_chosen(&review("/r")));
    }

    #[test]
    fn dropping_everything_leaves_nothing_to_run() {
        let mut decisions = Decisions::new(&[ready("/y")]);
        decisions.toggle(&ready("/y"), Section::Cache);
        assert!(decisions.is_empty());
        assert!(
            decisions
                .clean_args(&filters(), ScanLimitArgs::default(), false)
                .is_none()
        );
    }

    #[test]
    fn choosing_a_review_finding_asks_for_review_and_keeps_the_rest() {
        let mut decisions = Decisions::new(&[ready("/y"), review("/r"), review("/other")]);
        decisions.toggle(&review("/r"), Section::Cache);

        let args = decisions
            .clean_args(&filters(), ScanLimitArgs::default(), false)
            .expect("a non-empty plan produces arguments");
        assert!(args.include_review);
        assert_eq!(args.path, vec![PathBuf::from("/r"), PathBuf::from("/y")]);
    }

    #[test]
    fn a_plan_of_only_ready_findings_asks_for_no_review() {
        let decisions = Decisions::new(&[ready("/a"), ready("/b")]);
        let args = decisions
            .clean_args(&filters(), ScanLimitArgs::default(), false)
            .expect("arguments");
        assert!(!args.include_review);
    }

    /// The arguments carry the scan's own filters and nothing the reader did
    /// not decide. `roots` in particular is a cleanup authority: it must be
    /// the set the scope carried, never one the interface widened.
    #[test]
    fn the_arguments_carry_the_scope_and_no_decision_of_their_own() {
        let filters = filters();
        let args = Decisions::new(&[ready("/y")])
            .clean_args(&filters, ScanLimitArgs::default(), true)
            .expect("arguments");
        assert_eq!(args.roots, filters.roots);
        assert_eq!(args.only, filters.only);
        assert_eq!(args.older_than, filters.older_than);
        assert_eq!(args.min_size, filters.min_size);
        assert_eq!(args.top, filters.top);
        assert!(args.dry_run);
        assert!(!args.purge, "the review never plans permanent removal here");
        assert!(!args.yes, "the command's own confirmation still runs");
        assert!(
            args.review.is_none(),
            "--review takes one path; these are many"
        );
        assert!(!args.output.json);
        assert!(!args.details);
    }
}
