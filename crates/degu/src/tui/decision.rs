use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use degu_core::finding::{DispositionMode, Finding};

use crate::cli::{CleanArgs, JsonArgs, ScanLimitArgs};
use crate::tui::report::Section;

/// Whether a finding can be put in or out of the plan, and where it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Offered {
        taken: bool,
    },
    /// Outside any plan degu will build, from any surface.
    Withheld,
}

impl Choice {
    pub fn of(finding: &Finding, section: Section, taken: bool) -> Self {
        if section == Section::Runtime {
            return Self::Withheld;
        }
        match finding.disposition().mode {
            DispositionMode::Eligible | DispositionMode::OptIn => Self::Offered { taken },
            DispositionMode::ReportOnly => Self::Withheld,
        }
    }

    pub fn is_offered(self) -> bool {
        matches!(self, Self::Offered { .. })
    }
}

/// What the reader has decided to clean.
///
/// Starts as the plan `degu clean` would build on its own — every Eligible
/// finding — because that is what degu already decided. From there the reader
/// adds the Needs review findings they judge safe and drops the Eligible ones
/// they want kept. `ReportOnly` admits no decision from any surface, so no
/// keystroke can put one in.
pub struct Decisions {
    chosen: BTreeSet<PathBuf>,
    default: BTreeSet<PathBuf>,
    sizes: BTreeMap<PathBuf, u64>,
}

/// What a clean would move right now.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    pub locations: usize,
    pub bytes: u64,
}

impl Decisions {
    /// Takes the cache section only: the runtime section is reported, never
    /// cleaned, so nothing in it can ever be decided.
    pub fn new(cache: &[Finding]) -> Self {
        let default: BTreeSet<PathBuf> = cache
            .iter()
            .filter(|finding| finding.disposition().mode == DispositionMode::Eligible)
            .map(|finding| finding.path().to_path_buf())
            .collect();
        let sizes = cache
            .iter()
            .map(|finding| (finding.path().to_path_buf(), finding.bytes_allocated()))
            .collect();
        Self {
            chosen: default.clone(),
            default,
            sizes,
        }
    }

    /// The size of the plan, so a decision shows its effect on the row the
    /// reader is already looking at.
    pub fn plan(&self) -> Plan {
        let mut plan = Plan {
            locations: self.chosen.len(),
            bytes: 0,
        };
        for path in &self.chosen {
            plan.bytes = plan
                .bytes
                .saturating_add(self.sizes.get(path).copied().unwrap_or_default());
        }
        plan
    }

    /// Put a finding in the plan, or take it out. Anything degu will not act on
    /// is ignored rather than refused: a keystroke on such a row is a no-op.
    pub fn toggle(&mut self, finding: &Finding, section: Section) {
        if !Choice::of(finding, section, false).is_offered() {
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

    /// Whether the reader changed anything. Until they do, the plan is the one
    /// `degu clean` builds by itself, and saying so is more use than listing
    /// every path it would have found.
    fn is_default(&self) -> bool {
        self.chosen == self.default
    }

    /// True once something outside the default plan is in it, which is the only
    /// case where degu needs telling to admit Needs review findings.
    fn includes_review(&self) -> bool {
        self.chosen.difference(&self.default).next().is_some()
    }

    /// The clean these decisions describe, as the arguments a person could have
    /// typed. Nothing else executes: the interface builds this and the ordinary
    /// command implementation runs it.
    pub fn clean_args(&self, limits: ScanLimitArgs, dry_run: bool) -> CleanArgs {
        CleanArgs {
            output: JsonArgs { json: false },
            limits,
            details: false,
            roots: Vec::new(),
            include_review: self.includes_review(),
            review: None,
            yes: false,
            dry_run,
            purge: false,
            older_than: None,
            only: Vec::new(),
            min_size: None,
            top: None,
            // `--path` keeps only what it names, so naming the choices is what
            // makes the plan match them. Leaving it empty when nothing was
            // changed keeps the default plan whole.
            path: if self.is_default() {
                Vec::new()
            } else {
                self.chosen.iter().cloned().collect()
            },
        }
    }

    /// How the same clean would be written on a command line, so a reader who
    /// wants the rule rather than the judgement next time can see it.
    pub fn command_line(&self, dry_run: bool) -> String {
        let mut words = vec!["degu".to_owned(), "clean".to_owned()];
        if dry_run {
            words.push("--dry-run".to_owned());
        }
        if self.includes_review() {
            words.push("--include-review".to_owned());
        }
        if !self.is_default() {
            for path in &self.chosen {
                words.push("--path".to_owned());
                words.push(path.display().to_string());
            }
        }
        words.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use degu_core::finding::{
        FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
        finalize_findings,
    };

    fn finding(path: &str, recovery: Recovery) -> Finding {
        let candidate = FindingCandidate {
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
        };
        finalize_findings(vec![candidate], FindingSource::WellKnownRoot)
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

    fn withheld(path: &str) -> Finding {
        finding(path, Recovery::UserAsset)
    }

    fn decisions(findings: Vec<Finding>) -> Decisions {
        Decisions::new(&findings)
    }

    fn limits() -> ScanLimitArgs {
        ScanLimitArgs {
            max_concurrency: None,
            budget: None,
        }
    }

    #[test]
    fn the_plan_starts_as_the_one_degu_would_build_alone() {
        let decisions = decisions(vec![ready("/y"), review("/r"), withheld("/n")]);
        assert!(decisions.is_chosen(&ready("/y")));
        assert!(!decisions.is_chosen(&review("/r")));
        assert!(!decisions.is_chosen(&withheld("/n")));

        let args = decisions.clean_args(limits(), false);
        assert!(!args.include_review);
        assert!(
            args.path.is_empty(),
            "an unchanged plan is the default plan, not a filter that happens to match it"
        );
        assert_eq!(decisions.command_line(false), "degu clean");
    }

    #[test]
    fn the_plan_size_follows_the_decisions() {
        let mut decisions = decisions(vec![ready("/y"), review("/r")]);
        assert_eq!(
            decisions.plan(),
            Plan {
                locations: 1,
                bytes: 4096
            }
        );
        decisions.toggle(&review("/r"), Section::Cache);
        assert_eq!(
            decisions.plan(),
            Plan {
                locations: 2,
                bytes: 8192
            }
        );
        decisions.toggle(&ready("/y"), Section::Cache);
        assert_eq!(
            decisions.plan(),
            Plan {
                locations: 1,
                bytes: 4096
            }
        );
    }

    #[test]
    fn a_withheld_finding_cannot_be_put_in_the_plan() {
        let mut decisions = decisions(vec![withheld("/n")]);
        decisions.toggle(&withheld("/n"), Section::Cache);
        assert!(decisions.is_empty());
    }

    #[test]
    fn a_runtime_finding_is_never_offered() {
        let finding = review("/r");
        let mut decisions = decisions(vec![finding.clone()]);
        decisions.toggle(&finding, Section::Runtime);
        assert!(decisions.is_empty());
        assert_eq!(
            Choice::of(&finding, Section::Runtime, false),
            Choice::Withheld
        );
    }

    #[test]
    fn choosing_a_review_finding_keeps_the_rest_of_the_plan() {
        let mut decisions = decisions(vec![ready("/y"), review("/r"), review("/other")]);
        decisions.toggle(&review("/r"), Section::Cache);

        let args = decisions.clean_args(limits(), false);
        assert!(args.include_review);
        assert_eq!(
            args.path,
            vec![PathBuf::from("/r"), PathBuf::from("/y")],
            "the chosen review finding joins the default plan rather than replacing it"
        );
        assert_eq!(
            decisions.command_line(false),
            "degu clean --include-review --path /r --path /y"
        );
        assert_eq!(
            decisions.command_line(true),
            "degu clean --dry-run --include-review --path /r --path /y"
        );
    }

    #[test]
    fn dropping_a_ready_finding_leaves_it_out_and_asks_for_no_review() {
        let mut decisions = decisions(vec![ready("/a"), ready("/b")]);
        decisions.toggle(&ready("/b"), Section::Cache);

        let args = decisions.clean_args(limits(), false);
        assert!(!args.include_review);
        assert_eq!(args.path, vec![PathBuf::from("/a")]);
    }

    #[test]
    fn deciding_twice_returns_to_where_it_started() {
        let mut decisions = decisions(vec![ready("/y"), review("/r")]);
        for finding in [review("/r"), ready("/y")] {
            decisions.toggle(&finding, Section::Cache);
            decisions.toggle(&finding, Section::Cache);
        }
        assert!(decisions.is_default());
        assert_eq!(decisions.command_line(false), "degu clean");
    }

    #[test]
    fn dropping_everything_leaves_nothing_to_run() {
        let mut decisions = decisions(vec![ready("/y")]);
        decisions.toggle(&ready("/y"), Section::Cache);
        assert!(decisions.is_empty());
    }

    #[test]
    fn the_arguments_carry_no_decision_the_interface_did_not_make() {
        let args = decisions(vec![ready("/y")]).clean_args(limits(), true);
        assert!(args.dry_run);
        assert!(!args.purge, "the interface never plans permanent removal");
        assert!(!args.yes, "the command's own confirmation still runs");
        assert!(
            args.review.is_none(),
            "--review takes one path; these are many"
        );
        assert!(args.only.is_empty() && args.top.is_none() && args.min_size.is_none());
    }
}
