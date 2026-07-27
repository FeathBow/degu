use serde::Serialize;
use std::path::{Path, PathBuf};

mod consolidate;
mod finalize;

pub use consolidate::consolidate_findings;
pub use finalize::{AuthorityConstraint, finalize_findings, finalize_findings_with_constraint};

/// A storage observation emitted by an adapter and awaiting policy finalization.
///
/// ```compile_fail,E0277
/// use degu_core::finding::FindingCandidate;
/// fn assert_serializable<T: serde::Serialize>() {}
/// assert_serializable::<FindingCandidate>();
/// ```
/// ```compile_fail,E0308
/// use degu_core::finding::FindingCandidate;
/// use degu_core::plan::Plan;
/// let candidates: Vec<FindingCandidate> = Vec::new();
/// let _ = Plan::new(candidates, false);
/// ```
#[derive(Debug, Clone)]
pub struct FindingCandidate {
    /// Adapter id, e.g. "pip", "huggingface"
    pub ecosystem: String,
    pub path: PathBuf,
    pub kind: FindingKind,
    /// Logical size (what `ls -l` shows)
    pub bytes_apparent: u64,
    /// Allocated-block estimate from `st_blocks × 512`. Sparse or compressed files can differ from logical size; authoritative quota is queried separately.
    pub bytes_allocated: u64,
    /// Whole days since the newest file mtime in this finding.
    pub age_days: Option<u64>,
    /// Allocated bytes belonging to files with more than one hardlink.
    pub bytes_hardlinked: u64,
    /// HPC homes often carry a separate inode quota, as binding as the byte one.
    pub inodes: u64,
    /// Paths under this root that could not be accounted for during walking.
    pub skipped: u64,
    /// True when the reported size is a lower bound due to a time budget.
    pub truncated: bool,
    pub unvisited_dirs: u64,
    /// Mixed-state directory boundaries excluded while measuring this candidate.
    pub protected_boundaries: u64,
    /// Subset of `protected_boundaries` that are protected credential
    /// directories, so the demotion reason names credentials, not AI state.
    pub protected_credential_boundaries: u64,
    pub recovery: Recovery,
    pub ownership: Ownership,
    pub hazard: Option<Hazard>,
    /// Why this storage was reported and its operational implications; shown verbatim.
    pub rationale: String,
}

/// An immutable, policy-finalized storage observation safe to render, serialize, or plan.
///
/// ```compile_fail,E0277
/// use degu_core::finding::Finding;
/// fn assert_deserializable<T: serde::de::DeserializeOwned>() {}
/// assert_deserializable::<Finding>();
/// ```
/// ```compile_fail,E0616
/// use degu_core::finding::{Confidence, Finding};
/// fn rewrite_confidence(finding: &mut Finding) {
///     finding.confidence = Confidence::Unverified;
/// }
/// ```
/// ```compile_fail,E0616
/// use degu_core::finding::Finding;
/// use std::path::PathBuf;
/// fn rewrite_path(finding: &mut Finding) {
///     finding.path = PathBuf::from("/different/root");
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    ecosystem: String,
    path: PathBuf,
    kind: FindingKind,
    bytes_apparent: u64,
    bytes_allocated: u64,
    age_days: Option<u64>,
    bytes_hardlinked: u64,
    inodes: u64,
    skipped: u64,
    truncated: bool,
    #[serde(skip)]
    unvisited_dirs: u64,
    recovery: Recovery,
    ownership: Ownership,
    #[serde(skip_serializing_if = "Option::is_none")]
    hazard: Option<Hazard>,
    confidence: Confidence,
    disposition: Disposition,
    rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Package-manager download caches (pip/uv/cargo registry/npm)
    PackageCache,
    /// Model and dataset caches (HF hub, ollama)
    ModelCache,
    /// In-project build output (target/, node_modules/, __pycache__)
    BuildArtifact,
    /// Container and image caches (Apptainer, Podman)
    ContainerCache,
    /// Training checkpoints
    Checkpoint,
    /// Whole environments (conda envs) — always a user asset, so report-only
    Environment,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegenCost {
    Cheap,
    Costly,
}

/// Forward compatibility: consumers of the JSON output must treat unknown values
/// of this enum conservatively (as the most restrictive variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recovery {
    Unknown,
    Regenerable { cost: RegenCost },
    UserAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Unknown,
    Standalone,
    ToolCoordinated,
}

/// Deletion side-effect risk on live consumers of regenerable data. Closed
/// vocabulary owned by core: adapter free text is never a policy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hazard {
    BreaksConsumers,
    ActiveUse,
}

pub type FindingFacts = (Recovery, Ownership, Option<Hazard>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Verified,
    Unverified,
}

/// Evidence used by core to derive a finding's confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSource {
    WellKnownRoot,
    RedirectRoot { has_valid_cachedir_tag: bool },
    ProjectRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionMode {
    Eligible,
    OptIn,
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disposition {
    pub mode: DispositionMode,
    /// Highest-precedence fact that selected the mode; present iff mode != Eligible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Finding {
    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> FindingKind {
        self.kind
    }

    pub fn bytes_allocated(&self) -> u64 {
        self.bytes_allocated
    }

    pub fn age_days(&self) -> Option<u64> {
        self.age_days
    }

    pub fn bytes_hardlinked(&self) -> u64 {
        self.bytes_hardlinked
    }

    pub fn inodes(&self) -> u64 {
        self.inodes
    }

    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn measurement_incomplete(&self) -> bool {
        self.truncated || self.skipped > 0 || self.unvisited_dirs > 0
    }

    pub fn unvisited_dirs(&self) -> u64 {
        self.unvisited_dirs
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    pub fn hazard(&self) -> Option<Hazard> {
        self.hazard
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn disposition(&self) -> &Disposition {
        &self.disposition
    }
}
