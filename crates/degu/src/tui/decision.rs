use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use degu_core::finding::Finding;

use crate::cli::{CleanArgs, JsonArgs, ScanLimitArgs};
use crate::findings::Filters;
use crate::tui::report::{Class, Section};

pub struct Decisions {
    chosen: BTreeSet<PathBuf>,
    default: BTreeSet<PathBuf>,
    sizes: BTreeMap<PathBuf, u64>,
}

#[derive(Default, Clone, Copy)]
pub struct Plan {
    pub locations: usize,
    pub bytes: u64,
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
            .map(|finding| (finding.path().to_path_buf(), finding.bytes_allocated()))
            .collect();
        Self {
            chosen: default.clone(),
            default,
            sizes,
        }
    }

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
