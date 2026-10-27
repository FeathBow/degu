use crate::lifecycle::feasibility::{ProbeFailure, ShapeBounds};
use crate::presentation::escape_terminal_text;
use degu_core::backend::{
    CertificationError, HeldTreeAssessmentFailure, HeldTreeAssessmentFailureCategory,
    HeldTreeAssessmentFailureKind, HeldTreePolicyAssessmentOutcome,
    HeldTreeRegularHardLinkTopology, HeldTreeRegularXattrTopology,
};
use degu_core::finding::Finding;
use degu_core::seal::wal::{TreeShape, WalRoom, project_begin, project_tree};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
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

/// What a review needs to know of one tree to say whether a plan holding it
/// can be staged.
pub(crate) enum PlanAssessment {
    /// Staging refuses it whatever else the plan holds.
    Refused(String),
    /// Its policy admits it. Whether the seal WAL has room for it depends on
    /// the trees planned before it; `None` when it cannot be sized.
    Admitted(Option<WalCost>),
}

/// How staging admission would take each tree of a plan.
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
/// A tree whose policy was assessed is sized as well, so that [`room_refusals`]
/// can measure the plan's room again whenever the plan changes.
pub(crate) fn plan_assessment(
    ctx: degu_core::ecosystem::DetectCtx,
) -> impl Fn(&Finding) -> PlanAssessment {
    move |finding| match PreviewStagingAssessment::assess(finding, false, true).status {
        PreviewStagingStatus::TreePolicyAssessed { tree, .. } => PlanAssessment::Admitted(
            crate::lifecycle::feasibility::staging_shapes(&ctx, finding)
                .ok()
                .and_then(|shapes| WalCost::of(shapes, Some(tree))),
        ),
        PreviewStagingStatus::Blocked { reason, .. }
        | PreviewStagingStatus::WalFull { reason, .. }
        | PreviewStagingStatus::DeferredUntilExecutionSeal { reason, .. }
        | PreviewStagingStatus::SealedPathUnavailable { reason, .. } => {
            PlanAssessment::Refused(reason)
        }
    }
}

/// Why the seal WAL would have no room for each of `trees`, given in the order
/// a clean runs them, beside what the trees planned before it would leave.
///
/// `planned` says whether a tree is in the plan, told whether it fits. A tree
/// left out is never attempted, so it spends nothing, but it is still asked
/// what it would find were it put in. What a tree finds depends only on the
/// trees before it.
pub(crate) fn room_refusals<'a>(
    room: WalRoom,
    trees: impl IntoIterator<Item = (&'a Path, Option<WalCost>)>,
    mut planned: impl FnMut(&Path, bool) -> bool,
) -> BTreeMap<PathBuf, String> {
    let mut budget = WalBudget::new(room);
    let mut refusals = BTreeMap::new();
    for (path, cost) in trees {
        let full = match cost.and_then(|cost| budget.admits(cost)) {
            Some(WalAdmission::Full { needed, available }) => {
                refusals.insert(path.to_path_buf(), wal_full_reason(needed, available));
                true
            }
            Some(WalAdmission::Fits { .. }) | None => false,
        };
        if planned(path, !full)
            && let Some(cost) = cost
        {
            budget.spend(cost);
        }
    }
    refusals
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
            } => blocked_json(
                path.into_owned(),
                kind,
                category,
                relative_path.as_deref(),
                reason,
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
) -> Value {
    path_status_json(path, "blocked", kind, category, relative_path, reason)
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
    // The preview reads no trash, so it asks of the first sequence.
    match crate::lifecycle::feasibility::probe(&canonical_parent, basename, 1) {
        Err(ProbeFailure::ParentUnavailable(error)) => unavailable(
            "source_parent_unavailable",
            "race_or_io",
            &format!("failed to hold sealed staging source parent: {error}"),
        ),
        Err(ProbeFailure::Certification(error)) => certification_unavailable(error),
        Err(ProbeFailure::NameTooLong) => PreviewStagingStatus::Blocked {
            kind: "trash_name_too_long",
            category: "resource_limit",
            relative_path: None,
            reason: crate::lifecycle::feasibility::NAME_TOO_LONG.to_owned(),
        },
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

/// The least and the most of one figure, at the narrowest and the widest
/// shape an item's staging can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    least: u64,
    most: u64,
}

/// What staging one item can leave in the seal WAL, worked out once from the
/// narrowest and the widest shape it can take, so that a plan can be measured
/// again without sizing its items again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalCost {
    /// The source parent's seal and its undo, which a tree refused once
    /// staging has begun leaves behind.
    round_trip: Span,
    /// The room its whole life needs before its first frame, for both of
    /// staging's checks, for an item whose tree was assessed and sized. That
    /// is also the most the life can leave: it is the larger of what a commit
    /// holds, its frames and the allowance its entry keeps, and what a
    /// rollback leaves, its frames and their undo.
    needed: Option<Span>,
}

impl WalCost {
    /// Sizes an item from its shapes and, if its policy was assessed, its
    /// tree. `None` when not even its source parent's seal can be sized.
    fn of(shapes: ShapeBounds, tree: Option<TreeShape>) -> Option<Self> {
        let narrowest = shapes.narrowest.metadata()?;
        let widest = shapes.widest.metadata()?;
        let low = project_begin(&narrowest).ok()?;
        let high = project_begin(&widest).ok()?;
        let needed = tree.and_then(|tree| {
            let low_tree = project_tree(&narrowest, tree).ok()?;
            let high_tree = project_tree(&widest, tree).ok()?;
            Some(Span {
                least: low.forward.saturating_add(low_tree.needed()),
                most: high.forward.saturating_add(high_tree.needed()),
            })
        });
        Some(Self {
            round_trip: Span {
                least: low.needed(),
                most: high.needed(),
            },
            needed,
        })
    }

    /// A cost whose shape is known exactly.
    #[cfg(test)]
    pub(crate) fn exact(needed: u64, round_trip: u64) -> Self {
        Self {
            round_trip: Span {
                least: round_trip,
                most: round_trip,
            },
            needed: Some(Span {
                least: needed,
                most: needed,
            }),
        }
    }
}

/// The room the seal WAL leaves for new staging, spent in plan order on the
/// most each item's staging can leave there.
///
/// Staging checks the same room under the lease twice: before its first frame,
/// for the source parent's seal and its undo, and once the tree is planned, for
/// the rest of the item's life. What an item needs here is never less than
/// either check asks at its widest, so an item admitted here is admitted there
/// unless the trash changed in between. One refused here may still fit there
/// and run: at the lengths its sequence and reclamation id turn out to have,
/// in what the lease's compaction took back before the first item, or in room
/// the items before it did not take. Any of them may fail before its first
/// frame, for a reason other than room, and leave nothing, and the run goes on
/// to the next. So no item is sure to spend anything, and whether an item may
/// run is asked of the most room any item can find.
struct WalBudget {
    /// The least room left: what the trash leaves, less the most each item
    /// before can leave.
    available: u64,
    /// The most room any item can find: what the trash leaves once the
    /// lease has compacted it.
    ceiling: u64,
}

enum WalAdmission {
    /// Its whole life fits at its widest.
    Fits { needed: u64 },
    /// Its whole life at its widest does not fit in what is left.
    Full { needed: u64, available: u64 },
}

impl WalBudget {
    fn new(room: WalRoom) -> Self {
        Self {
            available: room.available(),
            ceiling: room.available_once_compacted(),
        }
    }

    /// Whether an item's whole life fits in what is left, or `None` for an
    /// item whose life was not sized. Nothing is spent.
    fn admits(&self, cost: WalCost) -> Option<WalAdmission> {
        let needed = cost.needed?.most;
        Some(if needed <= self.available {
            WalAdmission::Fits { needed }
        } else {
            WalAdmission::Full {
                needed,
                available: self.available,
            }
        })
    }

    /// Spends the most staging can leave of an item it attempts: its whole
    /// life at its widest, if that may fit at its narrowest in the most room
    /// any item can find, or else the source parent's round trip at its
    /// widest, if that may. Either way it leaves no more than was left.
    fn spend(&mut self, cost: WalCost) {
        let leaves = match cost.needed {
            Some(needed) if needed.least <= self.ceiling => needed.most,
            _ if cost.round_trip.least <= self.ceiling => cost.round_trip.most,
            _ => 0,
        };
        self.available = self.available.saturating_sub(leaves);
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
/// A clean attempts every planned item, so each is charged the most its
/// staging can leave, as [`WalBudget::spend`] reckons it. A tree whose policy
/// staging refuses is charged the round trip the refusal leaves. A tree only
/// the seal can walk is not known here, so it is charged that round trip and
/// no more, though it may commit and leave more.
///
/// `shapes_of` sizes an item from what preflight can see. An item it cannot
/// size is left as assessed and counts for nothing: staging needs the same
/// lengths for its first frame. Staging's own check is the exact one.
pub(super) fn apply_wal_room(
    assessments: &mut [PreviewStagingAssessment],
    planned: &[Finding],
    mut shapes_of: impl FnMut(&Finding) -> Option<ShapeBounds>,
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
        let Some(cost) = shapes_of(finding).and_then(|shapes| WalCost::of(shapes, tree)) else {
            continue;
        };
        match budget.admits(cost) {
            Some(WalAdmission::Fits { needed }) => {
                if let PreviewStagingStatus::TreePolicyAssessed { wal_needed, .. } =
                    &mut assessment.status
                {
                    *wal_needed = Some(needed);
                }
            }
            Some(WalAdmission::Full { needed, available }) => {
                assessment.status = PreviewStagingStatus::WalFull {
                    needed,
                    available,
                    reason: wal_full_reason(needed, available),
                };
            }
            None => {}
        }
        budget.spend(cost);
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
    )
}

fn assessment_failure_status_from_parts(
    kind: HeldTreeAssessmentFailureKind,
    relative_path: Option<PathBuf>,
    reason: &str,
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
        ),
        CertificationError::NotDirectory => assessment_failure_status_from_parts(
            HeldTreeAssessmentFailureKind::RootNotDirectory,
            None,
            "sealed staging source parent is not a directory",
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
    use degu_core::seal::wal::StagingShape;

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

    /// `SHAPE` known exactly.
    const EXACT: ShapeBounds = ShapeBounds {
        narrowest: SHAPE,
        widest: SHAPE,
    };

    /// `SHAPE` with a sequence of four digits rather than twenty, and a process
    /// id of one digit rather than ten.
    const NARROW: StagingShape = StagingShape {
        destination_basename: 9,
        reclamation_id: Some(15),
        ..SHAPE
    };

    /// `SHAPE` as wide as it can be, and as narrow.
    const BOUNDED: ShapeBounds = ShapeBounds {
        narrowest: NARROW,
        widest: SHAPE,
    };

    /// What an item costs at `NARROW`, known exactly.
    fn narrow_cost(tree: Option<TreeShape>) -> WalCost {
        WalCost::of(
            ShapeBounds {
                narrowest: NARROW,
                widest: NARROW,
            },
            tree,
        )
        .unwrap()
    }

    /// Half of `TREE`.
    const HALF: TreeShape = TreeShape {
        directories: 12,
        directory_path_bytes: 60,
        entries: 13,
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
        }
    }

    /// A WAL that leaves `available`, beside some frames and some allowance.
    fn room(available: u64) -> WalRoom {
        WalRoom {
            limit: available + 3000,
            committed: 2000,
            reserved: 1000,
            reclaimable: 0,
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
    /// before it leave, and each is charged at its widest. An admitted item
    /// may leave as much as its whole life needs, which here is more than a
    /// commit holds: the source is deep against a shallow trash, so a rollback
    /// leaves more. A tree staging
    /// refuses, or only the seal can walk, leaves the source parent's round
    /// trip; an item that is unavailable or cannot be sized leaves nothing. An
    /// exact fit is admitted, and an item that does not fit is blocked with
    /// what it needed and what was left.
    #[test]
    fn admits_in_order() {
        let metadata = SHAPE.metadata().unwrap();
        let begin = project_begin(&metadata).unwrap();
        let tree = project_tree(&metadata, TREE).unwrap();
        let needed = begin.forward + tree.needed();
        let round_trip = begin.needed();
        assert!(tree.rolled_back > tree.forward + tree.committed);

        let paths = [
            "/a",
            "/refused",
            "/deferred",
            "/unavailable",
            "/unsized",
            "/b",
            "/c",
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
            |finding| (finding.path() != Path::new("/unsized")).then_some(BOUNDED),
            room(2 * needed + 3 * round_trip),
        );

        assert_eq!(wal_needed(&assessments[0]), Some(needed));
        assert!(assessments[1].is_blocked());
        assert_eq!(wal_needed(&assessments[4]), None);
        // What came before leaves `/b` what it needs and a round trip more.
        assert_eq!(wal_needed(&assessments[5]), Some(needed));
        assert!(matches!(
            assessments[6].status,
            PreviewStagingStatus::WalFull { needed: n, .. } if n == needed
        ));
        assert_eq!(wal_full_available(&assessments[6]), Some(round_trip));
        assert_eq!(assessments[6].json()["kind"], "wal_full");
        assert_eq!(assessments[6].json()["available"], round_trip);
    }

    /// An item whose first check would refuse it even at its narrowest writes
    /// no frame, so the next item finds the room it found.
    #[test]
    fn unbegun_leaves_nothing() {
        let short = narrow_cost(None).round_trip.most - 1;
        let paths = ["/refused", "/full", "/next"];
        let planned = paths.map(planned);
        let mut assessments = paths.map(assessed);
        assessments[0].status = blocked();
        apply_wal_room(&mut assessments, &planned, |_| Some(BOUNDED), room(short));

        assert_eq!(wal_full_available(&assessments[1]), Some(short));
        assert_eq!(wal_full_available(&assessments[2]), Some(short));
    }

    /// A refused tree whose source parent's round trip fits at its narrowest
    /// may be begun and rolled back, and then leaves that round trip at up to
    /// its widest: the next item finds nothing left when only the narrowest
    /// fits, and what the widest leaves when that fits too.
    #[test]
    fn refusal_may_begin() {
        let narrowest = narrow_cost(None).round_trip.most;
        let widest = WalCost::of(EXACT, None).unwrap().round_trip.most;
        assert!(widest > narrowest);
        for (available, left) in [(narrowest, 0), (2 * widest, widest)] {
            let paths = ["/refused", "/next"];
            let mut assessments = paths.map(assessed);
            assessments[0].status = blocked();
            apply_wal_room(
                &mut assessments,
                &paths.map(planned),
                |_| Some(BOUNDED),
                room(available),
            );

            assert_eq!(wal_full_available(&assessments[1]), Some(left));
        }
    }

    /// An item that does not fit at its widest may still fit at the lengths
    /// its sequence and reclamation id turn out to have, and then it runs. It
    /// is blocked, and the item after it is measured as if it had run: that
    /// item would fit beside the first one's refusal, but not beside its life.
    #[test]
    fn full_may_commit() {
        let widest = WalCost::of(EXACT, Some(TREE)).unwrap();
        let needed = widest.needed.unwrap().most;
        let available = narrow_cost(Some(TREE)).needed.unwrap().most;
        let half = WalCost::of(EXACT, Some(HALF)).unwrap().needed.unwrap().most;
        assert!(needed > available);
        assert!(available - widest.round_trip.most >= half);

        let paths = ["/bounded", "/half"];
        let mut assessments = paths.map(assessed);
        assessments[1].status = assessed_tree(HALF);
        apply_wal_room(
            &mut assessments,
            &paths.map(planned),
            |finding| {
                Some(if finding.path() == Path::new("/bounded") {
                    BOUNDED
                } else {
                    EXACT
                })
            },
            room(available),
        );

        assert!(matches!(
            assessments[0].status,
            PreviewStagingStatus::WalFull { needed: n, .. } if n == needed
        ));
        assert_eq!(wal_full_available(&assessments[0]), Some(available));
        assert_eq!(wal_full_available(&assessments[1]), Some(0));
    }

    /// An admitted item may still fail before its first frame, for a reason
    /// other than room, and leave nothing, and the run goes on. The next item,
    /// which does not fit beside the first even at its narrowest, may then
    /// run, so the third is measured as if it had: it would fit beside the
    /// second one's refusal, but not beside its life.
    #[test]
    fn admitted_may_fail() {
        const QUARTER: TreeShape = TreeShape {
            directories: 6,
            directory_path_bytes: 30,
            entries: 7,
        };
        let cost = WalCost::of(EXACT, Some(TREE)).unwrap();
        let needed = cost.needed.unwrap().most;
        let round_trip = cost.round_trip.most;
        let quarter = WalCost::of(EXACT, Some(QUARTER))
            .unwrap()
            .needed
            .unwrap()
            .most;
        // Room for one life and half of another.
        let available = needed + needed / 2;
        assert!(available - needed - round_trip >= quarter);

        let paths = ["/first", "/second", "/third"];
        let mut assessments = paths.map(assessed);
        assessments[2].status = assessed_tree(QUARTER);
        apply_wal_room(
            &mut assessments,
            &paths.map(planned),
            |_| Some(EXACT),
            room(available),
        );

        assert_eq!(wal_needed(&assessments[0]), Some(needed));
        assert_eq!(
            wal_full_available(&assessments[1]),
            Some(available - needed)
        );
        assert_eq!(wal_full_available(&assessments[2]), Some(0));
    }

    /// A review's trees are measured in the order a clean runs them, and a
    /// tree left out of the plan spends nothing: the tree after it finds the
    /// room it found. A tree kept in the plan that could never fit still
    /// spends what its refusal leaves.
    #[test]
    fn refusals_follow_plan() {
        const BIG: TreeShape = TreeShape {
            directories: 120,
            directory_path_bytes: 600,
            entries: 121,
        };
        let cost = WalCost::of(EXACT, Some(TREE)).unwrap();
        let big = WalCost::of(EXACT, Some(BIG)).unwrap();
        let needed = cost.needed.unwrap().most;
        let big_needed = big.needed.unwrap().most;
        let round_trip = cost.round_trip.most;
        let available = 2 * needed + round_trip;
        assert!(big_needed > available);
        let trees = [("/a", cost), ("/big", big), ("/b", cost), ("/c", cost)]
            .map(|(path, cost)| (Path::new(path), Some(cost)));
        let big_refused = (
            PathBuf::from("/big"),
            wal_full_reason(big_needed, needed + round_trip),
        );

        assert_eq!(
            room_refusals(room(available), trees, |_, fits| fits),
            BTreeMap::from([
                big_refused.clone(),
                (PathBuf::from("/c"), wal_full_reason(needed, round_trip)),
            ])
        );
        assert_eq!(
            room_refusals(room(available), trees, |_, _| true),
            BTreeMap::from([
                big_refused,
                (PathBuf::from("/c"), wal_full_reason(needed, 0)),
            ])
        );
    }

    /// A clean's lease may compact the WAL before its first item, so an item
    /// that does not fit in the room measured may run, or begin and be
    /// refused, in the room compacted, and the next item is measured as if it
    /// had. With nothing to take back it could do neither.
    #[test]
    fn room_once_compacted() {
        let cost = WalCost::of(EXACT, Some(TREE)).unwrap();
        let needed = cost.needed.unwrap().most;
        let round_trip = cost.round_trip.most;
        let half = WalCost::of(EXACT, Some(HALF)).unwrap().needed.unwrap().most;
        // Short of the tree's life by its round trip, and then of the round
        // trip by half of it.
        let short = needed - round_trip;
        let shorter = round_trip / 2;
        assert!(short - round_trip >= half);
        let compactable = |available: u64, reclaimable: u64| WalRoom {
            limit: available + reclaimable + 1000,
            committed: reclaimable,
            reserved: 1000,
            reclaimable,
        };

        for (reclaimable, compacted) in [(0, false), (2 * round_trip, true)] {
            let paths = ["/first", "/next"];
            let mut assessments = paths.map(assessed);
            assessments[1].status = assessed_tree(HALF);
            apply_wal_room(
                &mut assessments,
                &paths.map(planned),
                |_| Some(EXACT),
                compactable(short, reclaimable),
            );
            assert_eq!(wal_full_available(&assessments[0]), Some(short));
            if compacted {
                assert_eq!(wal_full_available(&assessments[1]), Some(0));
            } else {
                assert_eq!(wal_needed(&assessments[1]), Some(half));
            }

            let mut assessments = paths.map(assessed);
            assessments[0].status = blocked();
            apply_wal_room(
                &mut assessments,
                &paths.map(planned),
                |_| Some(EXACT),
                compactable(shorter, reclaimable),
            );
            assert_eq!(
                wal_full_available(&assessments[1]),
                Some(if compacted { 0 } else { shorter })
            );
        }
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
        );
        assert_eq!(json["relative_path"], "child");
        assert!(json.get("relative_path_unix_bytes_hex").is_none());
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
