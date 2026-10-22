use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use degu_core::finding::Finding;
use degu_core::seal::wal::WalRoom;

use crate::cli::{CleanArgs, JsonArgs, ScanLimitArgs};
use crate::commands::clean::{PlanAssessment, WalCost, room_refusals};
use crate::findings::Filters;
use crate::tui::report::{Class, Section};

pub struct Decisions {
    chosen: BTreeSet<PathBuf>,
    default: BTreeSet<PathBuf>,
    sizes: BTreeMap<PathBuf, (u64, bool)>,
    /// Why sealed staging would refuse a tree the scan found eligible, whatever else
    /// the plan holds, by path.
    ///
    /// Scan eligibility says a cache is cheap to regenerate; it says nothing about
    /// whether this tree can be staged. Asked once, for the findings that would start
    /// in the plan, so a screen offering to run that plan is not the last place to
    /// learn the plan cannot run.
    refusals: BTreeMap<PathBuf, String>,
    /// The eligible trees staging's policy admits, in the order a clean runs them,
    /// with what each can leave in the seal WAL, or `None` for one that could not be
    /// sized. Kept so the plan's room can be measured again without walking them.
    costs: Vec<(PathBuf, Option<WalCost>)>,
    /// The seal WAL's room when the review opened, if it could be read.
    room: Option<WalRoom>,
    /// Why the seal WAL would have no room for a tree beside the trees planned
    /// before it. It depends on the plan, so it is measured again whenever the plan
    /// changes.
    full: BTreeMap<PathBuf, String>,
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
    /// `assess` says whether sealed staging would refuse a tree, and sizes one it
    /// would not. Passed in rather than called here: it walks the tree's metadata,
    /// which is work for the caller that already waits on a scan, and only the
    /// findings that would start in the plan are worth asking about. They are kept in
    /// the order the scan reported them, which is the order a clean runs them,
    /// because whether a tree fits in the seal WAL's `room` depends on the trees
    /// planned before it.
    pub fn new(
        cache: &[Finding],
        room: Option<WalRoom>,
        mut assess: impl FnMut(&Finding) -> PlanAssessment,
    ) -> Self {
        let mut refusals = BTreeMap::new();
        let mut costs = Vec::new();
        for finding in cache
            .iter()
            .filter(|finding| Class::of(finding, Section::Cache) == Class::Ready)
        {
            let path = finding.path().to_path_buf();
            match assess(finding) {
                PlanAssessment::Refused(reason) => {
                    refusals.insert(path, reason);
                }
                PlanAssessment::Admitted(cost) => costs.push((path, cost)),
            }
        }
        // A tree staging would refuse does not start in the plan: leaving it checked
        // offers a run that the same keystroke's preview and execution both reject.
        // Nor does one the seal WAL would have no room for beside the trees that
        // start before it.
        let full = measure_room(room, &costs, |_, fits| fits);
        let default: BTreeSet<PathBuf> = costs
            .iter()
            .map(|(path, _)| path)
            .filter(|path| !full.contains_key(*path))
            .cloned()
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
            refusals,
            costs,
            room,
            full,
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
        // The trees after this one now find a different room left. What this one
        // finds is unchanged, so its own panel stays right.
        let chosen = &self.chosen;
        self.full = measure_room(self.room, &self.costs, |path, _| chosen.contains(path));
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

    /// Why sealed staging would refuse this tree, for a finding the scan found
    /// eligible, with the plan as it stands. `None` for a tree it would admit, and
    /// for one never asked about.
    pub fn refusal(&self, path: &Path) -> Option<&str> {
        self.refusals
            .get(path)
            .or_else(|| self.full.get(path))
            .map(String::as_str)
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

/// Why the seal WAL would have no room for each sized tree, in plan order, with
/// `planned` saying which trees the plan holds. Nothing is refused for room that
/// could not be read.
fn measure_room(
    room: Option<WalRoom>,
    costs: &[(PathBuf, Option<WalCost>)],
    planned: impl FnMut(&Path, bool) -> bool,
) -> BTreeMap<PathBuf, String> {
    room.map(|room| {
        room_refusals(
            room,
            costs.iter().map(|(path, cost)| (path.as_path(), *cost)),
            planned,
        )
    })
    .unwrap_or_default()
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

    /// A tree staging's policy admits, not sized.
    fn admitted(_: &Finding) -> PlanAssessment {
        PlanAssessment::Admitted(None)
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

    /// Scan eligibility and staging readiness are two different answers. A tree the
    /// scan found cheap to regenerate but staging would refuse cannot start in a plan
    /// the reader is one keystroke from running.
    #[test]
    fn a_refused_tree_stays_out_of_the_plan_and_says_why() {
        let findings = [ready("/y"), ready("/refused")];
        let decisions = Decisions::new(&findings, None, |finding| {
            if finding.path() == Path::new("/refused") {
                PlanAssessment::Refused("external or unenumerated hard link encountered".to_owned())
            } else {
                PlanAssessment::Admitted(None)
            }
        });

        assert_eq!(decisions.plan().locations, 1);
        assert!(decisions.is_chosen(&findings[0]));
        assert!(!decisions.is_chosen(&findings[1]));
        assert_eq!(decisions.refusal(std::path::Path::new("/y")), None);
        assert!(
            decisions
                .refusal(std::path::Path::new("/refused"))
                .is_some_and(|reason| reason.contains("hard link"))
        );
    }

    /// Whether the seal WAL has room for a tree depends on the trees planned before
    /// it, so it is measured again whenever the plan changes. `/a` and `/b` each fit
    /// alone but not together, so `/b` starts out and says why; once `/a` is taken
    /// out, `/b` fits. A tree kept in the plan that does not fit still leaves what
    /// its refusal does, so `/c`, which fits after `/a` alone, no longer fits once
    /// `/b` is in the plan too. With no room read, nothing is refused for room.
    #[test]
    fn room_follows_plan() {
        let findings = [ready("/a"), ready("/b"), ready("/c")];
        let tree = WalCost::exact(100, 60, 10);
        let small = WalCost::exact(85, 5, 1);
        let assess = |finding: &Finding| {
            PlanAssessment::Admitted(Some(if finding.path() == Path::new("/c") {
                small
            } else {
                tree
            }))
        };
        let room = WalRoom {
            limit: 150,
            committed: 0,
            reserved: 0,
        };
        let refused = |decisions: &Decisions, path: &str| {
            decisions.refusal(Path::new(path)).map(|reason| {
                assert!(reason.contains("the seal WAL needs"), "{reason}");
                reason.rsplit_once(" but has ").unwrap().1.to_owned()
            })
        };

        let mut decisions = Decisions::new(&findings, Some(room), assess);
        assert!(decisions.is_chosen(&findings[0]));
        assert!(!decisions.is_chosen(&findings[1]));
        assert!(decisions.is_chosen(&findings[2]));
        assert_eq!(refused(&decisions, "/b").as_deref(), Some("90 to give"));

        decisions.toggle(&findings[0], Section::Cache);
        assert_eq!(refused(&decisions, "/b"), None);
        decisions.toggle(&findings[1], Section::Cache);
        assert_eq!(refused(&decisions, "/a"), None);
        assert_eq!(refused(&decisions, "/c"), None);
        decisions.toggle(&findings[0], Section::Cache);
        assert_eq!(refused(&decisions, "/b").as_deref(), Some("90 to give"));
        assert_eq!(refused(&decisions, "/c").as_deref(), Some("80 to give"));

        let unread = Decisions::new(&findings, None, assess);
        for finding in &findings {
            assert!(unread.is_chosen(finding));
            assert_eq!(unread.refusal(finding.path()), None);
        }
    }

    #[test]
    fn the_plan_starts_as_the_one_degu_would_build_alone() {
        let decisions = Decisions::new(
            &[ready("/y"), review("/r"), unmanaged("/n")],
            None,
            admitted,
        );
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
        let mut decisions = Decisions::new(&[unmanaged("/n")], None, admitted);
        decisions.toggle(&unmanaged("/n"), Section::Cache);
        assert!(decisions.is_empty(), "a keystroke reached a withheld tier");
    }

    #[test]
    fn a_runtime_finding_cannot_be_put_in_the_plan() {
        let finding = review("/r");
        let mut decisions = Decisions::new(std::slice::from_ref(&finding), None, admitted);
        decisions.toggle(&finding, Section::Runtime);
        assert!(decisions.is_empty());
    }

    #[test]
    fn dropping_everything_leaves_nothing_to_run() {
        let mut decisions = Decisions::new(&[ready("/y")], None, admitted);
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
        let mut decisions = Decisions::new(
            &[ready("/y"), review("/r"), review("/other")],
            None,
            admitted,
        );
        decisions.toggle(&review("/other"), Section::Cache);
        decisions.toggle(&review("/other"), Section::Cache);
        decisions.toggle(&review("/r"), Section::Cache);

        let args = decisions
            .clean_args(&filters(), ScanLimitArgs::default(), false)
            .expect("a non-empty plan produces arguments");
        assert!(args.include_review);
        assert_eq!(args.path, vec![PathBuf::from("/r"), PathBuf::from("/y")]);
    }

    #[test]
    fn a_plan_of_only_ready_findings_asks_for_no_review() {
        let decisions = Decisions::new(&[ready("/a"), ready("/b")], None, admitted);
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
        let args = Decisions::new(&[ready("/y")], None, admitted)
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
