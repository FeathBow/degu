use degu_core::finding::DispositionMode;
pub use degu_core::finding::Finding;

use crate::collection::ScanCompleteness;

pub(crate) use crate::collection::ScanStatus as Coverage;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Cache,
    Runtime,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Runtime => "node-runtime (Not managed)",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Cache => Self::Runtime,
            Self::Runtime => Self::Cache,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Total {
    pub value: u64,
    pub saturated: bool,
}

impl Total {
    pub fn of(values: impl Iterator<Item = u64>) -> Self {
        let mut value: u64 = 0;
        let mut saturated = false;
        for item in values {
            match value.checked_add(item) {
                Some(sum) => value = sum,
                None => {
                    value = u64::MAX;
                    saturated = true;
                }
            }
        }
        Self { value, saturated }
    }
}

/// The findings of one scan, split the way the printed report splits them.
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub runtime: Vec<Finding>,
    completeness: ScanCompleteness,
}

impl ScanReport {
    pub fn new(
        findings: Vec<Finding>,
        runtime: Vec<Finding>,
        completeness: ScanCompleteness,
    ) -> Self {
        Self {
            findings,
            runtime,
            completeness,
        }
    }

    pub fn section(&self, section: Section) -> &[Finding] {
        match section {
            Section::Cache => &self.findings,
            Section::Runtime => &self.runtime,
        }
    }

    pub fn coverage(&self, section: Section) -> Coverage {
        match section {
            Section::Cache => self.completeness.findings,
            Section::Runtime => self.completeness.runtime,
        }
    }

    pub fn total_allocated(&self, section: Section) -> Total {
        Total::of(
            self.section(section)
                .iter()
                .map(degu_core::finding::Finding::bytes_allocated),
        )
    }

    pub fn total_inodes(&self, section: Section) -> Total {
        Total::of(
            self.section(section)
                .iter()
                .map(degu_core::finding::Finding::inodes),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Ready,
    NeedsReview,
    NotManaged,
}

impl Class {
    pub fn of(finding: &Finding, section: Section) -> Self {
        if section == Section::Runtime {
            return Self::NotManaged;
        }
        match finding.disposition().mode {
            DispositionMode::Eligible => Self::Ready,
            DispositionMode::OptIn => Self::NeedsReview,
            DispositionMode::ReportOnly => Self::NotManaged,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready to clean",
            Self::NeedsReview => "Needs review",
            Self::NotManaged => "Not managed",
        }
    }
}
