use crate::lifecycle::feasibility::ProbeFailure;
use crate::presentation::escape_terminal_text;
use degu_core::backend::{
    CertificationError, HeldTreeAssessmentFailure, HeldTreeAssessmentFailureCategory,
    HeldTreeAssessmentFailureKind, HeldTreeLimitExceeded, HeldTreePolicyAssessmentOutcome,
    HeldTreeRegularHardLinkTopology, HeldTreeRegularXattrTopology,
};
use degu_core::finding::Finding;
use degu_core::seal::wal::{StagingShape, TreeShape, WalRoom, project_begin, project_tree};
use serde_json::{Map, Value};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A data-only preview fact. It is deliberately separate from the captured
/// clean plan: it carries no descriptor, seal lineage, WAL lease, store handle,
/// trash destination, or mutation authority.
pub(super) struct PreviewStagingAssessment {
    path: PathBuf,
    purge_requested: bool,
    status: PreviewStagingStatus,
}

#[derive(Debug)]
pub(super) enum PreviewStagingStatus {
    TreePolicyAssessed {
        regular_hard_links: HeldTreeRegularHardLinkTopology,
        regular_xattrs: HeldTreeRegularXattrTopology,
        directory_xattrs_block_purge: bool,
        /// What staging this tree will be sized by.
        tree: TreeShape,
        /// What its whole life needs in the seal WAL, once measured.
        wal_needed: Option<u64>,
    },
    /// The tree's policy was assessed, but its whole life does not fit in the
    /// seal WAL beside what the trash and the items before it already hold.
    WalFull {
        needed: u64,
        available: u64,
        reason: String,
    },
    Blocked {
        kind: &'static str,
        category: &'static str,
        relative_path: Option<PathBuf>,
        reason: String,
        /// The limit and the tree's size, when the assessment counted past it.
        exceeded: Option<HeldTreeLimitExceeded>,
    },
    DeferredUntilExecutionSeal {
        kind: &'static str,
        category: &'static str,
        reason: String,
    },
    SealedPathUnavailable {
        kind: &'static str,
        category: &'static str,
        relative_path: Option<PathBuf>,
        reason: String,
    },
}

/// Why staging admission would refuse each tree of a plan, or `None` for one it
/// would admit, asked in the order the plan runs.
///
/// The same assessment a dry-run preview reports, asked one finding at a time so a
/// surface that offers a plan can say what the plan would hit before it is run. It
/// walks the tree's metadata, so a caller asks once per finding and remembers.
///
/// Assessed as an explicit-path batch, because every surface that asks this builds
/// one: that is the strictest reading, and the one the reader's own preview applies.
/// Under it only a tree whose policy was assessed can run. The batch preflight
/// rejects the whole batch on any other answer, so a tree whose assessment could
/// not finish is a refusal here, although the preview, which reports rather than
/// offers, files it as unavailable rather than blocked.
///
/// A tree whose policy was assessed is then sized against `room`, the seal WAL's
/// room when it could be read, beside what the trees admitted before it will
/// leave there. A refused tree is left out of the plan it is asked for, so it
/// spends nothing.
pub(crate) fn plan_refusals(
    ctx: degu_core::ecosystem::DetectCtx,
    room: Option<WalRoom>,
) -> impl FnMut(&Finding) -> Option<String> {
    refusals_with(
        |finding| PreviewStagingAssessment::assess(finding, false, true).status,
        move |finding| crate::lifecycle::feasibility::staging_shape(&ctx, finding).ok(),
        room,
    )
}

fn refusals_with(
    assess: impl Fn(&Finding) -> PreviewStagingStatus,
    mut shape_of: impl FnMut(&Finding) -> Option<StagingShape>,
    room: Option<WalRoom>,
) -> impl FnMut(&Finding) -> Option<String> {
    let mut budget = room.map(WalBudget::new);
    move |finding| {
        let tree = match assess(finding) {
            PreviewStagingStatus::TreePolicyAssessed { tree, .. } => tree,
            PreviewStagingStatus::Blocked { reason, .. }
            | PreviewStagingStatus::WalFull { reason, .. }
            | PreviewStagingStatus::DeferredUntilExecutionSeal { reason, .. }
            | PreviewStagingStatus::SealedPathUnavailable { reason, .. } => return Some(reason),
        };
        let budget = budget.as_mut()?;
        match budget.admit(shape_of(finding)?, tree) {
            WalAdmission::Full { needed, available } => Some(wal_full_reason(needed, available)),
            WalAdmission::Fits { .. } | WalAdmission::Unsized => None,
        }
    }
}

impl PreviewStagingAssessment {
    pub(super) fn assess(finding: &Finding, purge_requested: bool, atomic_selection: bool) -> Self {
        let path = finding.path().to_path_buf();
        let status = apply_selection_policy(assess_path(&path), atomic_selection);
        Self {
            path,
            purge_requested,
            status,
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn is_tree_policy_assessed(&self) -> bool {
        matches!(self.status, PreviewStagingStatus::TreePolicyAssessed { .. })
    }

    pub(super) fn has_internal_hard_links(&self) -> bool {
        matches!(
            self.status,
            PreviewStagingStatus::TreePolicyAssessed { regular_hard_links, .. }
                if regular_hard_links.contains_multi_link_group()
        )
    }

    /// Directory metadata is the one thing no proof covers, so it is the one extended
    /// attribute that still refuses a permanent deletion. Ordinary regular-file xattrs
    /// are bound into the content manifest by proof schema v3, which this purge verifies
    /// before it unlinks anything, so they no longer block one. Nor do complete internal
    /// hard-link groups: the manifest binds each regular file's link count, the walk
    /// refuses every other topology, and the purge predicts the only drift its own
    /// unlinks cause in that count.
    pub(super) fn directory_xattrs_block_purge(&self) -> bool {
        matches!(
            self.status,
            PreviewStagingStatus::TreePolicyAssessed {
                directory_xattrs_block_purge: true,
                ..
            }
        )
    }

    pub(super) fn purge_supported(&self) -> bool {
        !self.directory_xattrs_block_purge()
    }

    pub(super) fn is_blocked(&self) -> bool {
        matches!(
            self.status,
            PreviewStagingStatus::Blocked { .. } | PreviewStagingStatus::WalFull { .. }
        )
    }

    pub(super) fn needs_execution_validation(&self) -> bool {
        matches!(
            self.status,
            PreviewStagingStatus::DeferredUntilExecutionSeal { .. }
                | PreviewStagingStatus::SealedPathUnavailable { .. }
        )
    }

    pub(super) fn reason(&self) -> Option<&str> {
        match &self.status {
            PreviewStagingStatus::TreePolicyAssessed { .. } => None,
            PreviewStagingStatus::Blocked { reason, .. }
            | PreviewStagingStatus::WalFull { reason, .. }
            | PreviewStagingStatus::DeferredUntilExecutionSeal { reason, .. }
            | PreviewStagingStatus::SealedPathUnavailable { reason, .. } => Some(reason),
        }
    }

    pub(super) fn json(&self) -> Value {
        let path = self.path.to_string_lossy();
        match &self.status {
            PreviewStagingStatus::TreePolicyAssessed {
                regular_hard_links,
                regular_xattrs,
                directory_xattrs_block_purge,
                wal_needed,
                ..
            } => {
                let has_hardlinks = regular_hard_links.contains_multi_link_group();
                let has_xattrs = regular_xattrs.contains_xattrs();
                let directory_xattrs_block_purge = *directory_xattrs_block_purge;
                let limitation = directory_xattrs_block_purge.then_some(
                    "directory extended attributes may be staged and undone, but sealed purge is unsupported",
                );
                serde_json::json!({
                    "path": path,
                    "status": "tree_policy_assessed",
                    "requested_action": if self.purge_requested { "purge" } else { "stage" },
                    "contains_internal_hardlinks": has_hardlinks,
                    "contains_ordinary_regular_xattrs": has_xattrs,
                    "directory_xattrs_block_purge": directory_xattrs_block_purge,
                    "regular_hard_links": {
                        "multi_link_groups": regular_hard_links.multi_link_groups,
                        "linked_entries": regular_hard_links.linked_entries,
                        // Every other topology was refused by the walk that
                        // produced this assessment: a group whose in-tree link
                        // count differs from the inode's never reaches here.
                        "topology": if has_hardlinks { "internal_complete" } else { "single_link_only" },
                    },
                    "regular_xattrs": {
                        "entries": regular_xattrs.entries,
                        "attributes": regular_xattrs.attributes,
                        "value_bytes": regular_xattrs.value_bytes,
                        "proof_schema": 3,
                    },
                    "purge_admission": {
                        "supported": !directory_xattrs_block_purge,
                        "limitation": limitation,
                    },
                    "wal_needed": wal_needed,
                    "pending_validation": {
                        "source_parent_seal": "requires_execution",
                        "regular_file_content_read_and_proof": "requires_execution",
                        "runtime_revalidation": "requires_execution",
                    },
                })
            }
            PreviewStagingStatus::WalFull {
                needed,
                available,
                reason,
            } => {
                let mut json = blocked_json(
                    path.into_owned(),
                    "wal_full",
                    "resource_limit",
                    None,
                    reason,
                    None,
                );
                if let Value::Object(fields) = &mut json {
                    fields.insert("needed".to_owned(), Value::from(*needed));
                    fields.insert("available".to_owned(), Value::from(*available));
                }
                json
            }
            PreviewStagingStatus::Blocked {
                kind,
                category,
                relative_path,
                reason,
                exceeded,
            } => blocked_json(
                path.into_owned(),
                kind,
                category,
                relative_path.as_deref(),
                reason,
                *exceeded,
            ),
            PreviewStagingStatus::DeferredUntilExecutionSeal {
                kind,
                category,
                reason,
            } => serde_json::json!({
                "path": path,
                "status": "deferred_until_seal",
                "kind": kind,
                "category": category,
                "reason": reason,
            }),
            PreviewStagingStatus::SealedPathUnavailable {
                kind,
                category,
                relative_path,
                reason,
            } => unavailable_json(
                path.into_owned(),
                kind,
                category,
                relative_path.as_deref(),
                reason,
            ),
        }
    }
}

/// Keeps native descendant paths out of `json!`, avoiding its
/// infallible-serialization panic path.
fn blocked_json(
    path: String,
    kind: &str,
    category: &str,
    relative_path: Option<&Path>,
    reason: &str,
    exceeded: Option<HeldTreeLimitExceeded>,
) -> Value {
    let mut json = path_status_json(path, "blocked", kind, category, relative_path, reason);
    if let (Value::Object(fields), Some(HeldTreeLimitExceeded { limit, observed })) =
        (&mut json, exceeded)
    {
        fields.insert("limit".to_owned(), Value::from(limit));
        fields.insert("observed".to_owned(), Value::from(observed));
    }
    json
}

fn unavailable_json(
    path: String,
    kind: &str,
    category: &str,
    relative_path: Option<&Path>,
    reason: &str,
) -> Value {
    path_status_json(path, "unavailable", kind, category, relative_path, reason)
}

fn path_status_json(
    path: String,
    status: &str,
    kind: &str,
    category: &str,
    relative_path: Option<&Path>,
    reason: &str,
) -> Value {
    let mut fields = Map::from_iter([
        ("path".to_owned(), Value::String(path)),
        ("status".to_owned(), Value::String(status.to_owned())),
        ("kind".to_owned(), Value::String(kind.to_owned())),
        ("category".to_owned(), Value::String(category.to_owned())),
        ("reason".to_owned(), Value::String(reason.to_owned())),
    ]);
    fields.extend(relative_path_json_fields(relative_path));
    Value::Object(fields)
}

fn relative_path_json_fields(relative_path: Option<&Path>) -> Map<String, Value> {
    let mut fields = Map::new();
    match relative_path {
        None => {
            fields.insert("relative_path".to_owned(), Value::Null);
        }
        Some(path) => match path.to_str() {
            Some(path) => {
                fields.insert("relative_path".to_owned(), Value::String(path.to_owned()));
            }
            None => {
                fields.insert("relative_path".to_owned(), Value::Null);
                #[cfg(unix)]
                fields.insert(
                    "relative_path_unix_bytes_hex".to_owned(),
                    Value::String(hex(path.as_os_str().as_bytes())),
                );
            }
        },
    }
    fields
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn assess_path(path: &Path) -> PreviewStagingStatus {
    // Resolve and hold the parent before touching the child. In particular, a
    // read-only parent without search permission must reach core's explicit
    // deferral rather than being hidden by canonicalizing the child first.
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return unavailable(
            "source_parent_unavailable",
            "input",
            "sealed staging source has no parent",
        );
    };
    let Some(basename) = path.file_name() else {
        return unavailable(
            "source_basename_unavailable",
            "input",
            "sealed staging source has no basename",
        );
    };
    let canonical_parent = match std::fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(error) => {
            return unavailable(
                "source_parent_unavailable",
                "race_or_io",
                &format!("failed to canonicalize sealed staging source parent: {error}"),
            );
        }
    };
    match crate::lifecycle::feasibility::probe(&canonical_parent, basename) {
        Err(ProbeFailure::ParentUnavailable(error)) => unavailable(
            "source_parent_unavailable",
            "race_or_io",
            &format!("failed to hold sealed staging source parent: {error}"),
        ),
        Err(ProbeFailure::Certification(error)) => certification_unavailable(error),
        Err(ProbeFailure::Assessment(error)) => assessment_failure_status(error),
        Ok(HeldTreePolicyAssessmentOutcome::TreePolicyAssessed { tree, .. }) => {
            PreviewStagingStatus::TreePolicyAssessed {
                regular_hard_links: tree.regular_hard_links,
                regular_xattrs: tree.regular_xattrs,
                directory_xattrs_block_purge: tree.directory_xattrs_block_purge,
                tree: TreeShape {
                    directories: tree.directories,
                    directory_path_bytes: tree.directory_path_bytes,
                    entries: tree.entries,
                },
                wal_needed: None,
            }
        }
        Ok(HeldTreePolicyAssessmentOutcome::TreePolicyDeferredUntilSourceParentSeal { .. }) => {
            PreviewStagingStatus::DeferredUntilExecutionSeal {
                kind: "source_parent_search_requires_execution_seal",
                category: "execution_validation",
                reason: "the entire tree policy was not assessed because traversal requires the execution-time source-parent seal"
                    .to_owned(),
            }
        }
    }
}

/// The room the seal WAL leaves for new staging, spent in plan order on what
/// each item's staging would leave there.
///
/// Staging checks the same room under the lease twice: before its first frame,
/// for the source parent's seal and its undo, and once the tree is planned, for
/// the rest of the item's life. What an item needs here is never less than
/// either check asks, and its shape rounds the reservation number and the
/// reclamation id up to their widest, so an item admitted here is admitted
/// there unless the trash changed in between. One refused here may still just
/// fit there.
struct WalBudget {
    available: u64,
}

enum WalAdmission {
    /// Its whole life fits, and what a commit leaves it holding is spent.
    Fits { needed: u64 },
    /// Its whole life does not fit in what is left. Nothing is spent.
    Full { needed: u64, available: u64 },
    /// It cannot be sized. Nothing is spent.
    Unsized,
}

impl WalBudget {
    fn new(room: WalRoom) -> Self {
        Self {
            available: room.available(),
        }
    }

    /// Admits an item whose tree was assessed, if its whole life fits. What a
    /// commit leaves it holding is the frames it wrote and the allowance its
    /// entry then keeps, which is never less than a purge writes, so a
    /// `--purge` run is measured no more loosely.
    fn admit(&mut self, shape: StagingShape, tree: TreeShape) -> WalAdmission {
        let Some(metadata) = shape.metadata() else {
            return WalAdmission::Unsized;
        };
        let (Ok(begin), Ok(projection)) = (project_begin(&metadata), project_tree(&metadata, tree))
        else {
            return WalAdmission::Unsized;
        };
        let needed = begin.forward.saturating_add(projection.needed());
        if needed > self.available {
            return WalAdmission::Full {
                needed,
                available: self.available,
            };
        }
        self.available = self.available.saturating_sub(
            begin
                .forward
                .saturating_add(projection.forward)
                .saturating_add(projection.committed),
        );
        WalAdmission::Fits { needed }
    }

    /// Spends what staging leaves when it refuses a tree once it has begun:
    /// the source parent's seal and its undo, or nothing when there is no room
    /// even for that, because then it refuses before its first frame.
    fn refuse(&mut self, shape: StagingShape) {
        let Some(round_trip) = shape
            .metadata()
            .and_then(|metadata| project_begin(&metadata).ok())
            .map(|begin| begin.needed())
        else {
            return;
        };
        if round_trip <= self.available {
            self.available -= round_trip;
        }
    }
}

fn wal_full_reason(needed: u64, available: u64) -> String {
    format!(
        "the seal WAL needs {needed} bytes for this item's whole life but has {available} to give"
    )
}

/// Sizes each assessed item's whole life in the seal WAL, in plan order, and
/// blocks every one that does not fit beside what the trash already holds and
/// what the items before it will have left there.
///
/// A clean attempts every planned item, so each is charged what its staging
/// would leave. One that commits holds what [`WalBudget::admit`] spends. One
/// whose tree staging refuses -- for its policy, or for room -- has sealed its
/// source parent first and rolled that back. A tree only the seal can walk is
/// not known here, so that round trip is all it is charged, which is the least
/// it can leave. One staging cannot even hold leaves nothing.
///
/// `shape_of` sizes an item from what preflight can see. An item it cannot
/// size is left as assessed and counts for nothing: on a machine where nothing
/// is staged yet the trash's parent may not exist to be sized from, and there
/// the WAL is empty anyway. Staging's own check is the exact one.
pub(super) fn apply_wal_room(
    assessments: &mut [PreviewStagingAssessment],
    planned: &[Finding],
    mut shape_of: impl FnMut(&Finding) -> Option<StagingShape>,
    room: WalRoom,
) {
    let mut budget = WalBudget::new(room);
    for (assessment, finding) in assessments.iter_mut().zip(planned) {
        let tree = match &assessment.status {
            PreviewStagingStatus::TreePolicyAssessed { tree, .. } => Some(*tree),
            PreviewStagingStatus::Blocked { .. }
            | PreviewStagingStatus::DeferredUntilExecutionSeal { .. } => None,
            PreviewStagingStatus::WalFull { .. }
            | PreviewStagingStatus::SealedPathUnavailable { .. } => continue,
        };
        let Some(shape) = shape_of(finding) else {
            continue;
        };
        let Some(tree) = tree else {
            budget.refuse(shape);
            continue;
        };
        match budget.admit(shape, tree) {
            WalAdmission::Fits { needed } => {
                if let PreviewStagingStatus::TreePolicyAssessed { wal_needed, .. } =
                    &mut assessment.status
                {
                    *wal_needed = Some(needed);
                }
            }
            WalAdmission::Full { needed, available } => {
                assessment.status = PreviewStagingStatus::WalFull {
                    needed,
                    available,
                    reason: wal_full_reason(needed, available),
                };
                budget.refuse(shape);
            }
            WalAdmission::Unsized => budget.refuse(shape),
        }
    }
}

fn apply_selection_policy(
    status: PreviewStagingStatus,
    atomic_selection: bool,
) -> PreviewStagingStatus {
    match (atomic_selection, status) {
        (true, PreviewStagingStatus::DeferredUntilExecutionSeal { reason, .. }) => {
            PreviewStagingStatus::Blocked {
                kind: "atomic_batch_preflight_deferred",
                category: "execution_validation",
                relative_path: None,
                exceeded: None,
                reason: safe(&format!(
                    "explicit path/review batches require every item to complete pre-seal assessment and execution will reject this batch before mutation: {reason}"
                )),
            }
        }
        (_, status) => status,
    }
}

fn assessment_failure_status(error: HeldTreeAssessmentFailure) -> PreviewStagingStatus {
    assessment_failure_status_from_parts(
        error.kind(),
        error.relative_path().map(Path::to_path_buf),
        &error.to_string(),
        error.exceeded(),
    )
}

fn assessment_failure_status_from_parts(
    kind: HeldTreeAssessmentFailureKind,
    relative_path: Option<PathBuf>,
    reason: &str,
    exceeded: Option<HeldTreeLimitExceeded>,
) -> PreviewStagingStatus {
    let category = kind.category();
    match category {
        HeldTreeAssessmentFailureCategory::Input
        | HeldTreeAssessmentFailureCategory::ResourceLimit
        | HeldTreeAssessmentFailureCategory::TreePolicy => PreviewStagingStatus::Blocked {
            kind: kind.as_str(),
            category: category.as_str(),
            relative_path,
            reason: safe(reason),
            exceeded,
        },
        HeldTreeAssessmentFailureCategory::PlatformEvidence
        | HeldTreeAssessmentFailureCategory::RaceOrIo
        | HeldTreeAssessmentFailureCategory::InternalFailClosed => {
            PreviewStagingStatus::SealedPathUnavailable {
                kind: kind.as_str(),
                category: category.as_str(),
                relative_path,
                reason: safe(reason),
            }
        }
    }
}

fn certification_unavailable(error: CertificationError) -> PreviewStagingStatus {
    match error {
        CertificationError::AclPresent => assessment_failure_status_from_parts(
            HeldTreeAssessmentFailureKind::AclPresent,
            None,
            "sealed staging source parent has an ACL",
            None,
        ),
        CertificationError::NotDirectory => assessment_failure_status_from_parts(
            HeldTreeAssessmentFailureKind::RootNotDirectory,
            None,
            "sealed staging source parent is not a directory",
            None,
        ),
        error => {
            let kind = match error {
                CertificationError::UnsupportedFilesystem => "unsupported_filesystem",
                CertificationError::UnsupportedPlatform => "unsupported_platform",
                _ => "source_parent_certification_unavailable",
            };
            unavailable(
                kind,
                "platform_evidence",
                &format!("sealed staging source-parent certification is unavailable: {error:?}"),
            )
        }
    }
}

fn unavailable(kind: &'static str, category: &'static str, reason: &str) -> PreviewStagingStatus {
    PreviewStagingStatus::SealedPathUnavailable {
        kind,
        category,
        relative_path: None,
        reason: safe(&format!(
            "sealed staging availability could not be determined without side effects; activation mode remains unknown: {reason}"
        )),
    }
}

fn safe(value: &str) -> String {
    escape_terminal_text(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_reasons_are_terminal_safe() {
        let status = unavailable("io", "race_or_io", "first\nsecond\u{1b}[31m");
        let PreviewStagingStatus::SealedPathUnavailable {
            relative_path,
            reason,
            ..
        } = status
        else {
            unreachable!()
        };
        assert!(relative_path.is_none());
        assert!(!reason.chars().any(char::is_control), "{reason:?}");
        assert!(reason.contains("\\n") && reason.contains("\\u{1b}"));
    }

    #[test]
    fn atomic_selection_discloses_that_deferred_assessment_will_be_rejected() {
        let deferred = || PreviewStagingStatus::DeferredUntilExecutionSeal {
            kind: "source_parent_search_requires_execution_seal",
            category: "execution_validation",
            reason: "source parent requires sealing".to_owned(),
        };
        assert!(matches!(
            apply_selection_policy(deferred(), false),
            PreviewStagingStatus::DeferredUntilExecutionSeal { .. }
        ));
        let PreviewStagingStatus::Blocked {
            kind,
            category,
            reason,
            ..
        } = apply_selection_policy(deferred(), true)
        else {
            panic!("atomic selection left a deferred item executable")
        };
        assert_eq!(kind, "atomic_batch_preflight_deferred");
        assert_eq!(category, "execution_validation");
        assert!(reason.contains("execution will reject this batch before mutation"));
    }

    const TREE: TreeShape = TreeShape {
        directories: 24,
        directory_path_bytes: 120,
        entries: 25,
    };

    // A source far deeper than its trash, so undoing a refused tree costs more
    // than the item holds once staged: what it needs and what it then takes
    // differ.
    const SHAPE: StagingShape = StagingShape {
        source_parent: 240,
        source_basename: 4,
        destination_parent: 20,
        destination_basename: 25,
        filesystem_id: 16,
        reclamation_id: Some(24),
        recovery_anchor: Some(18),
    };

    fn planned(path: &str) -> Finding {
        use degu_core::finding::{
            FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
            finalize_findings,
        };
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
                recovery: Recovery::Regenerable {
                    cost: RegenCost::Cheap,
                },
                ownership: Ownership::Standalone,
                hazard: None,
                rationale: "fixture".to_owned(),
            }],
            FindingSource::WellKnownRoot,
        )
        .pop()
        .expect("one finalized finding")
    }

    fn assessed_tree(tree: TreeShape) -> PreviewStagingStatus {
        PreviewStagingStatus::TreePolicyAssessed {
            regular_hard_links: HeldTreeRegularHardLinkTopology::default(),
            regular_xattrs: HeldTreeRegularXattrTopology::default(),
            directory_xattrs_block_purge: false,
            tree,
            wal_needed: None,
        }
    }

    fn assessed(path: &str) -> PreviewStagingAssessment {
        PreviewStagingAssessment {
            path: PathBuf::from(path),
            purge_requested: false,
            status: assessed_tree(TREE),
        }
    }

    fn blocked() -> PreviewStagingStatus {
        PreviewStagingStatus::Blocked {
            kind: "policy",
            category: "tree_policy",
            relative_path: None,
            reason: "refused".to_owned(),
            exceeded: None,
        }
    }

    /// A WAL that leaves `available`, beside some frames and some allowance.
    fn room(available: u64) -> WalRoom {
        WalRoom {
            limit: available + 3000,
            committed: 2000,
            reserved: 1000,
        }
    }

    fn wal_needed(assessment: &PreviewStagingAssessment) -> Option<u64> {
        match assessment.status {
            PreviewStagingStatus::TreePolicyAssessed { wal_needed, .. } => wal_needed,
            _ => None,
        }
    }

    fn wal_full_available(assessment: &PreviewStagingAssessment) -> Option<u64> {
        match assessment.status {
            PreviewStagingStatus::WalFull { available, .. } => Some(available),
            _ => None,
        }
    }

    /// Items are admitted in plan order, each into what the trash and the items
    /// before it leave. A committed item leaves what it holds; a tree staging
    /// refuses, or only the seal can walk, leaves the source parent's round
    /// trip; an item staging never begins, or that cannot be sized, leaves
    /// nothing. An exact fit is admitted, and an item that does not fit is
    /// blocked with what it needed and what was left, and still leaves its
    /// round trip.
    #[test]
    fn room_admits_in_order() {
        let metadata = SHAPE.metadata().unwrap();
        let begin = project_begin(&metadata).unwrap();
        let tree = project_tree(&metadata, TREE).unwrap();
        let needed = begin.forward + tree.needed();
        let holds = begin.forward + tree.forward + tree.committed;
        let round_trip = begin.needed();
        let last = needed - holds;
        assert!(needed > holds && last >= 2 * round_trip);

        let paths = [
            "/a",
            "/refused",
            "/deferred",
            "/unavailable",
            "/unsized",
            "/b",
            "/c",
            "/d",
        ];
        let planned = paths.map(planned);
        let mut assessments = paths.map(assessed);
        assessments[1].status = blocked();
        assessments[2].status = PreviewStagingStatus::DeferredUntilExecutionSeal {
            kind: "deferred",
            category: "execution_validation",
            reason: "deferred".to_owned(),
        };
        assessments[3].status = PreviewStagingStatus::SealedPathUnavailable {
            kind: "unavailable",
            category: "race_or_io",
            relative_path: None,
            reason: "unavailable".to_owned(),
        };
        apply_wal_room(
            &mut assessments,
            &planned,
            |finding| (finding.path() != Path::new("/unsized")).then_some(SHAPE),
            room(holds + 2 * round_trip + needed),
        );

        assert_eq!(wal_needed(&assessments[0]), Some(needed));
        assert!(assessments[1].is_blocked());
        assert_eq!(wal_needed(&assessments[4]), None);
        // What came before leaves exactly what `/b` needs.
        assert_eq!(wal_needed(&assessments[5]), Some(needed));
        assert!(matches!(
            assessments[6].status,
            PreviewStagingStatus::WalFull { needed: n, .. } if n == needed
        ));
        assert_eq!(wal_full_available(&assessments[6]), Some(last));
        assert_eq!(wal_full_available(&assessments[7]), Some(last - round_trip));
        assert_eq!(assessments[6].json()["kind"], "wal_full");
        assert_eq!(assessments[6].json()["available"], last);
    }

    /// An item whose first check would already refuse it writes no frame, so
    /// the next item finds the room it found.
    #[test]
    fn refused_begin_leaves_nothing() {
        let metadata = SHAPE.metadata().unwrap();
        let short = project_begin(&metadata).unwrap().needed() - 1;
        let paths = ["/refused", "/full", "/next"];
        let planned = paths.map(planned);
        let mut assessments = paths.map(assessed);
        assessments[0].status = blocked();
        apply_wal_room(&mut assessments, &planned, |_| Some(SHAPE), room(short));

        assert_eq!(wal_full_available(&assessments[1]), Some(short));
        assert_eq!(wal_full_available(&assessments[2]), Some(short));
    }

    /// A plan's trees are sized in the order it runs them, and a refused tree is
    /// left out of the plan, so it spends nothing: the tree after it finds the
    /// room it found. A tree refused for its policy keeps that reason, and with
    /// no room to read, no tree is refused for room.
    #[test]
    fn refusals_spend_nothing() {
        const BIG: TreeShape = TreeShape {
            directories: 48,
            directory_path_bytes: 240,
            entries: 49,
        };
        let metadata = SHAPE.metadata().unwrap();
        let begin = project_begin(&metadata).unwrap();
        let tree = project_tree(&metadata, TREE).unwrap();
        let needed = begin.forward + tree.needed();
        let holds = begin.forward + tree.forward + tree.committed;
        let big = begin.forward + project_tree(&metadata, BIG).unwrap().needed();
        assert!(big > needed);

        let assess = |finding: &Finding| match finding.path().to_str() {
            Some("/policy") => blocked(),
            Some("/big") => assessed_tree(BIG),
            _ => assessed_tree(TREE),
        };
        let mut refusal = refusals_with(assess, |_| Some(SHAPE), Some(room(holds + needed)));
        let mut ask = |path| refusal(&planned(path));
        assert_eq!(ask("/a"), None);
        assert_eq!(ask("/policy").as_deref(), Some("refused"));
        assert_eq!(ask("/big"), Some(wal_full_reason(big, needed)));
        assert_eq!(ask("/b"), None);
        assert_eq!(ask("/c"), Some(wal_full_reason(needed, needed - holds)));

        let mut unread = refusals_with(assess, |_| Some(SHAPE), None);
        assert_eq!(unread(&planned("/big")), None);
        assert_eq!(unread(&planned("/policy")).as_deref(), Some("refused"));
    }

    #[test]
    fn json_status_labels_are_stable() {
        let path = PathBuf::from("/preview/item");
        for (status, expected) in [
            (
                PreviewStagingStatus::TreePolicyAssessed {
                    regular_hard_links: HeldTreeRegularHardLinkTopology::default(),
                    regular_xattrs: HeldTreeRegularXattrTopology::default(),
                    directory_xattrs_block_purge: false,
                    tree: TREE,
                    wal_needed: None,
                },
                "tree_policy_assessed",
            ),
            (
                PreviewStagingStatus::WalFull {
                    needed: 2,
                    available: 1,
                    reason: "full".to_owned(),
                },
                "blocked",
            ),
            (
                PreviewStagingStatus::Blocked {
                    kind: "policy",
                    category: "tree_policy",
                    relative_path: Some(PathBuf::from("child")),
                    reason: "blocked".to_owned(),
                    exceeded: None,
                },
                "blocked",
            ),
            (
                PreviewStagingStatus::DeferredUntilExecutionSeal {
                    kind: "seal",
                    category: "execution_validation",
                    reason: "deferred".to_owned(),
                },
                "deferred_until_seal",
            ),
            (
                PreviewStagingStatus::SealedPathUnavailable {
                    kind: "platform",
                    category: "platform_evidence",
                    relative_path: None,
                    reason: "unavailable".to_owned(),
                },
                "unavailable",
            ),
        ] {
            let assessment = PreviewStagingAssessment {
                purge_requested: false,
                path: path.clone(),
                status,
            };
            assert_eq!(assessment.json()["path"], "/preview/item");
            assert_eq!(assessment.json()["status"], expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn blocked_json_preserves_non_utf8_relative_path_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let json = blocked_json(
            "/preview/item".to_owned(),
            "external_or_unenumerated_hard_link",
            "tree_policy",
            Some(Path::new(&OsString::from_vec(vec![
                b'd', b'i', b'r', b'/', 0xff,
            ]))),
            "blocked",
            None,
        );
        assert!(json["relative_path"].is_null());
        assert_eq!(json["relative_path_unix_bytes_hex"], "6469722fff");
    }

    #[test]
    fn utf8_blocked_json_keeps_string_without_native_encoding_sidecar() {
        let json = blocked_json(
            "/preview/item".to_owned(),
            "policy",
            "tree_policy",
            Some(Path::new("child")),
            "blocked",
            None,
        );
        assert_eq!(json["relative_path"], "child");
        assert!(json.get("relative_path_unix_bytes_hex").is_none());
    }

    #[test]
    fn only_a_counted_refusal_reports_a_limit_and_a_size() {
        let blocked = |exceeded| {
            blocked_json(
                "/preview/item".to_owned(),
                "directory_limit_exceeded",
                "resource_limit",
                None,
                "blocked",
                exceeded,
            )
        };
        let counted = blocked(Some(HeldTreeLimitExceeded {
            limit: 1_023,
            observed: 5_080,
        }));
        assert_eq!(counted["limit"], 1_023);
        assert_eq!(counted["observed"], 5_080);
        let uncounted = blocked(None);
        assert!(uncounted.get("limit").is_none(), "{uncounted:#}");
        assert!(uncounted.get("observed").is_none(), "{uncounted:#}");
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_json_preserves_non_utf8_relative_path_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let status = assessment_failure_status_from_parts(
            HeldTreeAssessmentFailureKind::IdentityChanged,
            Some(PathBuf::from(OsString::from_vec(vec![
                b'd', b'i', b'r', b'/', 0xff,
            ]))),
            "identity changed",
            None,
        );
        let assessment = PreviewStagingAssessment {
            purge_requested: false,
            path: PathBuf::from("/preview/item"),
            status,
        };
        let json = assessment.json();
        assert_eq!(json["status"], "unavailable");
        assert!(json["relative_path"].is_null());
        assert_eq!(json["relative_path_unix_bytes_hex"], "6469722fff");
    }

    #[test]
    fn unstable_assessment_failures_retain_child_path_and_stable_identity() {
        for (kind, expected_category) in [
            (HeldTreeAssessmentFailureKind::IoFailure, "race_or_io"),
            (HeldTreeAssessmentFailureKind::IdentityChanged, "race_or_io"),
            (
                HeldTreeAssessmentFailureKind::MetadataEvidenceUnavailable,
                "race_or_io",
            ),
            (
                HeldTreeAssessmentFailureKind::CertificationFailed,
                "platform_evidence",
            ),
        ] {
            let status = assessment_failure_status_from_parts(
                kind,
                Some(PathBuf::from("child")),
                "first\nsecond\u{1b}[31m",
                None,
            );
            assert!(
                !matches!(status, PreviewStagingStatus::Blocked { .. }),
                "{kind:?} must not be shown as a stable policy block"
            );
            let assessment = PreviewStagingAssessment {
                purge_requested: false,
                path: PathBuf::from("/preview/item"),
                status,
            };
            assert!(assessment.needs_execution_validation());
            assert!(!assessment.is_blocked());
            assert!(!assessment.is_tree_policy_assessed());
            let json = assessment.json();
            assert_eq!(json["status"], "unavailable");
            assert_eq!(json["kind"], kind.as_str());
            assert_eq!(json["category"], expected_category);
            assert_eq!(json["relative_path"], "child");
            assert!(json.get("relative_path_unix_bytes_hex").is_none());
            let reason = json["reason"].as_str().unwrap();
            assert!(!reason.chars().any(char::is_control), "{reason:?}");
            assert!(reason.contains("\\n") && reason.contains("\\u{1b}"));
        }
    }

    #[test]
    fn stable_policy_assessment_failure_remains_blocked() {
        let status = assessment_failure_status_from_parts(
            HeldTreeAssessmentFailureKind::ProtectedName,
            Some(PathBuf::from(".git")),
            "protected name encountered",
            None,
        );
        let PreviewStagingStatus::Blocked { kind, category, .. } = status else {
            panic!("stable tree policy must remain blocked")
        };
        assert_eq!(kind, "protected_name");
        assert_eq!(category, "tree_policy");
    }

    #[test]
    fn deterministic_certification_failures_are_blocked() {
        for (error, expected_kind) in [
            (CertificationError::AclPresent, "acl_present"),
            (CertificationError::NotDirectory, "root_not_directory"),
        ] {
            let PreviewStagingStatus::Blocked { kind, .. } = certification_unavailable(error)
            else {
                panic!("deterministic certification failure was not blocked")
            };
            assert_eq!(kind, expected_kind);
        }
    }

    #[test]
    fn unsupported_filesystem_is_explicitly_unavailable() {
        let status = certification_unavailable(CertificationError::UnsupportedFilesystem);
        let PreviewStagingStatus::SealedPathUnavailable {
            kind,
            category,
            relative_path,
            reason,
        } = status
        else {
            panic!("unsupported filesystem must not be called assessed or blocked")
        };
        assert_eq!(kind, "unsupported_filesystem");
        assert_eq!(category, "platform_evidence");
        assert!(relative_path.is_none());
        assert!(reason.contains("UnsupportedFilesystem"));
    }
}
