use serde::Deserialize;

#[derive(Deserialize)]
pub struct Finding {
    pub path: String,
    pub ecosystem: String,
    pub kind: String,
    pub bytes_allocated: u64,
    pub bytes_apparent: u64,
    #[serde(default)]
    pub bytes_hardlinked: u64,
    #[serde(default)]
    pub inodes: u64,
    // An unknown age must remain distinct from zero days.
    #[serde(default)]
    pub age_days: Option<u64>,
    #[serde(default)]
    pub skipped: u64,
    pub confidence: String,
    pub ownership: String,
    pub disposition: Disposition,
    #[serde(default)]
    pub recovery: Option<Recovery>,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Deserialize)]
pub struct Disposition {
    pub mode: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Deserialize)]
pub struct Recovery {
    pub kind: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    NotRequested,
    Truncated,
    Incomplete,
    Unknown,
}

impl Coverage {
    pub fn was_requested(self) -> bool {
        self != Self::NotRequested
    }

    pub fn is_floor(self) -> bool {
        matches!(self, Self::Truncated | Self::Incomplete | Self::Unknown)
    }
}

#[derive(Default, Deserialize)]
pub struct Completeness {
    #[serde(default)]
    findings: String,
    #[serde(default)]
    runtime: String,
}

impl Completeness {
    pub fn section(&self, section: Section) -> Coverage {
        let state = match section {
            Section::Cache => &self.findings,
            Section::Runtime => &self.runtime,
        };
        match state.as_str() {
            "complete" => Coverage::Complete,
            "not_requested" => Coverage::NotRequested,
            "truncated" => Coverage::Truncated,
            "incomplete" => Coverage::Incomplete,
            _ => Coverage::Unknown,
        }
    }
}

#[derive(Deserialize)]
pub struct ScanReport {
    #[serde(default)]
    pub completeness: Completeness,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub runtime: Vec<Finding>,
}

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

impl ScanReport {
    pub fn section(&self, section: Section) -> &[Finding] {
        match section {
            Section::Cache => &self.findings,
            Section::Runtime => &self.runtime,
        }
    }

    pub fn total_allocated(&self, section: Section) -> Total {
        Total::of(self.section(section).iter().map(|f| f.bytes_allocated))
    }

    pub fn total_inodes(&self, section: Section) -> Total {
        Total::of(self.section(section).iter().map(|f| f.inodes))
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
        match finding.disposition.mode.as_str() {
            "eligible" => Self::Ready,
            "opt_in" => Self::NeedsReview,
            _ => Self::NotManaged,
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
