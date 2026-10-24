use crate::lifecycle::feasibility::{ProbeFailure, ShapeBounds};
use crate::presentation::escape_terminal_text;
use degu_core::backend::{
    CertificationError, HeldTreeAssessmentFailure, HeldTreeAssessmentFailureCategory,
    HeldTreeAssessmentFailureKind, HeldTreeLimitExceeded, HeldTreePolicyAssessmentOutcome,
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
/// trees before it. A review's clean stages and does not purge.
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
            budget.spend(cost, false);
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

/// The least and the most one figure can come to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    least: u64,
    most: u64,
}

/// An item's whole life in the seal WAL, at the narrowest and the widest
/// shape its staging can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Life {
    /// The room it needs before its first frame, for both of staging's checks.
    needed: Span,
    /// What a commit leaves it holding: the frames it wrote and the allowance
    /// its entry then keeps, which is never less than a purge writes, so a
    /// `--purge` run is measured no more loosely.
    holds: Span,
    /// The frames a commit writes, at its narrowest: all a commit is sure to
    /// leave once a purge in the same run has spent its allowance.
    writes: u64,
}

/// What staging one item can leave in the seal WAL, worked out once from the
/// narrowest and the widest shape it can take, so that a plan can be measured
/// again without sizing its items again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalCost {
    /// The source parent's seal and its undo, which a tree refused once
    /// staging has begun leaves behind, at its narrowest and its widest.
    round_trip: Span,
    /// Its whole life, for an item whose tree was assessed and sized.
    life: Option<Life>,
}

impl WalCost {
    /// Sizes an item from its shapes and, if its policy was assessed, its
    /// tree. `None` when not even its source parent's seal can be sized.
    fn of(shapes: ShapeBounds, tree: Option<TreeShape>) -> Option<Self> {
        let narrowest = shapes.narrowest.metadata()?;
        let widest = shapes.widest.metadata()?;
        let low = project_begin(&narrowest).ok()?;
        let high = project_begin(&widest).ok()?;
        let life = tree.and_then(|tree| {
            let low_tree = project_tree(&narrowest, tree).ok()?;
            let high_tree = project_tree(&widest, tree).ok()?;
            Some(Life {
                needed: Span {
                    least: low.forward.saturating_add(low_tree.needed()),
                    most: high.forward.saturating_add(high_tree.needed()),
                },
                holds: Span {
                    least: low
                        .forward
                        .saturating_add(low_tree.forward)
                        .saturating_add(low_tree.committed),
                    most: high
                        .forward
                        .saturating_add(high_tree.forward)
                        .saturating_add(high_tree.committed),
                },
                writes: low.forward.saturating_add(low_tree.forward),
            })
        });
        Some(Self {
            round_trip: Span {
                least: low.needed(),
                most: high.needed(),
            },
            life,
        })
    }

    /// A cost whose shape is known exactly, and whose commit holds no more
    /// than it writes.
    #[cfg(test)]
    pub(crate) fn exact(needed: u64, holds: u64, round_trip: u64) -> Self {
        Self {
            round_trip: Span {
                least: round_trip,
                most: round_trip,
            },
            life: Some(Life {
                needed: Span {
                    least: needed,
                    most: needed,
                },
                holds: Span {
                    least: holds,
                    most: holds,
                },
                writes: holds,
            }),
        }
    }
}

/// The room the seal WAL leaves for new staging, spent in plan order on what
/// each item's staging can leave there.
///
/// Staging checks the same room under the lease twice: before its first frame,
/// for the source parent's seal and its undo, and once the tree is planned, for
/// the rest of the item's life. What an item needs here is never less than
/// either check asks at its widest, so an item admitted here is admitted there
/// unless the trash changed in between. One refused here may still fit there
/// and commit: at the lengths its sequence and reclamation id turn out to
/// have, beside items before it that turned out narrower, or in what the
/// lease's compaction took back before the first item.
///
/// So the room left is known only between two figures. The least is what
/// admits an item. The most is what says whether an item that was not
/// admitted may still begin, or commit.
struct WalBudget {
    left: Span,
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
            left: Span {
                least: room.available(),
                most: room.available_once_compacted(),
            },
        }
    }

    /// Whether an item's whole life fits in the least that is left, or `None`
    /// for an item whose life was not sized. Nothing is spent.
    fn admits(&self, cost: WalCost) -> Option<WalAdmission> {
        let needed = cost.life?.needed.most;
        Some(if needed <= self.left.least {
            WalAdmission::Fits { needed }
        } else {
            WalAdmission::Full {
                needed,
                available: self.left.least,
            }
        })
    }

    /// Spends what staging can leave of an item it attempts.
    ///
    /// The least left loses the most the item can leave: the larger of what a
    /// commit leaves it holding, if its whole life fits at its narrowest in
    /// the most left, and the source parent's round trip, which a refusal once
    /// begun leaves, if that fits there at its narrowest.
    ///
    /// The most left loses the least the item is sure to leave. One admitted
    /// commits, and holds at least what it holds at its narrowest, or under
    /// `purge` the frames it writes. One sure to begin leaves at least the
    /// round trip at its narrowest: a refusal leaves just that, and a commit
    /// restores the source parent as the undo would, among more. Any other
    /// may be refused before its first frame, and leave nothing.
    fn spend(&mut self, cost: WalCost, purge: bool) {
        let Span { least, most } = self.left;
        let committed = cost
            .life
            .filter(|life| life.needed.least <= most)
            .map_or(0, |life| life.holds.most);
        let refused = if cost.round_trip.least <= most {
            cost.round_trip.most
        } else {
            0
        };
        let kept = match cost.life {
            Some(life) if life.needed.most <= least => {
                if purge {
                    life.writes
                } else {
                    life.holds.least
                }
            }
            _ if cost.round_trip.most <= least => cost.round_trip.least,
            _ => 0,
        };
        self.left = Span {
            least: least.saturating_sub(committed.max(refused)),
            most: most.saturating_sub(kept),
        };
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
/// the seal can walk is not known here, so that round trip is all it is
/// charged, which is the least it can leave.
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
        let purge = assessment.purge_requested;
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
        budget.spend(cost, purge);
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

    /// A cost whose round trip and whole life lie between the figures given,
    /// and whose commit holds `holds`, all of it frames it wrote.
    fn cost(round_trip: (u64, u64), needed: (u64, u64), holds: u64) -> WalCost {
        WalCost {
            round_trip: Span {
                least: round_trip.0,
                most: round_trip.1,
            },
            life: Some(Life {
                needed: Span {
                    least: needed.0,
                    most: needed.1,
                },
                holds: Span {
                    least: holds,
                    most: holds,
                },
                writes: holds,
            }),
        }
    }

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
            exceeded: None,
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
    /// before it leave. A committed item leaves what it holds; a tree staging
    /// refuses, or only the seal can walk, leaves the source parent's round
    /// trip; an item staging never begins, or that cannot be sized, leaves
    /// nothing. An exact fit is admitted, and an item that does not fit is
    /// blocked with what it needed and what was left, and still leaves its
    /// round trip.
    #[test]
    fn admits_in_order() {
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
            |finding| (finding.path() != Path::new("/unsized")).then_some(EXACT),
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

    /// An item whose first check would refuse it even at its narrowest writes
    /// no frame, so the next item finds the room it found, and, admitted, is
    /// charged the commit it makes there.
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

        let trees = [
            ("/unbegun", cost((5000, 5000), (9000, 9000), 9000)),
            ("/admitted", cost((50, 50), (3000, 3000), 2500)),
            ("/next", cost((50, 50), (2000, 2000), 1000)),
        ]
        .map(|(path, cost)| (Path::new(path), Some(cost)));
        assert_eq!(
            room_refusals(room(4000), trees, |_, _| true),
            BTreeMap::from([
                (PathBuf::from("/unbegun"), wal_full_reason(9000, 4000)),
                (PathBuf::from("/next"), wal_full_reason(2000, 1500)),
            ])
        );
    }

    /// A tree sure to begin but not to fit is sure to leave only its round
    /// trip at its narrowest. Here that may leave the next tree, blocked in
    /// the least, the room to commit, so the third is measured as if it had.
    #[test]
    fn refusal_leaves_least() {
        let trees = [
            ("/first", cost((100, 300), (5000, 5000), 3000)),
            ("/second", cost((50, 50), (3800, 3800), 3000)),
            ("/third", cost((50, 50), (1000, 1000), 500)),
        ]
        .map(|(path, cost)| (Path::new(path), Some(cost)));
        assert_eq!(
            room_refusals(room(4000), trees, |_, _| true),
            BTreeMap::from([
                (PathBuf::from("/first"), wal_full_reason(5000, 4000)),
                (PathBuf::from("/second"), wal_full_reason(3800, 3700)),
                (PathBuf::from("/third"), wal_full_reason(1000, 700)),
            ])
        );
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
    /// its sequence and reclamation id turn out to have, and then it commits.
    /// It is blocked, and the item after it is measured as if it had
    /// committed: that item would fit beside the first one's refusal, but not
    /// beside its commit. The first may as well be refused and leave only its
    /// round trip, and then the second commits, so the third is measured as if
    /// it had.
    #[test]
    fn full_may_commit() {
        let widest = WalCost::of(EXACT, Some(TREE)).unwrap();
        let life = widest.life.unwrap();
        let available = narrow_cost(Some(TREE)).life.unwrap().needed.most;
        let half_life = WalCost::of(EXACT, Some(HALF)).unwrap().life.unwrap();
        let half = half_life.needed.most;
        assert!(life.needed.most > available);
        assert!(available - widest.round_trip.most >= half);
        assert!(available.saturating_sub(life.holds.most) < half);
        assert!(available - life.holds.most <= half_life.holds.most);

        let paths = ["/bounded", "/half", "/third"];
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
            PreviewStagingStatus::WalFull { needed, .. } if needed == life.needed.most
        ));
        assert_eq!(wal_full_available(&assessments[0]), Some(available));
        assert_eq!(
            wal_full_available(&assessments[1]),
            Some(available.saturating_sub(life.holds.most))
        );
        assert_eq!(wal_full_available(&assessments[2]), Some(0));
    }

    /// A review's trees are measured in the order a clean runs them, and a
    /// tree left out of the plan spends nothing: the tree after it finds the
    /// room it found. A tree kept in the plan that does not fit still spends
    /// what its refusal leaves.
    #[test]
    fn refusals_follow_plan() {
        const BIG: TreeShape = TreeShape {
            directories: 48,
            directory_path_bytes: 240,
            entries: 49,
        };
        let cost = WalCost::of(EXACT, Some(TREE)).unwrap();
        let big = WalCost::of(EXACT, Some(BIG)).unwrap();
        let life = cost.life.unwrap();
        let (needed, holds) = (life.needed.most, life.holds.most);
        let big_needed = big.life.unwrap().needed.most;
        assert!(big_needed > needed);
        let trees = [("/a", cost), ("/big", big), ("/b", cost), ("/c", cost)]
            .map(|(path, cost)| (Path::new(path), Some(cost)));
        let available = holds + needed;

        let fitting = room_refusals(room(available), trees, |_, fits| fits);
        assert_eq!(
            fitting,
            BTreeMap::from([
                (PathBuf::from("/big"), wal_full_reason(big_needed, needed)),
                (PathBuf::from("/c"), wal_full_reason(needed, needed - holds)),
            ])
        );

        let all = room_refusals(room(available), trees, |_, _| true);
        let after_big = needed - cost.round_trip.most;
        assert_eq!(
            all.get(Path::new("/b")),
            Some(&wal_full_reason(needed, after_big))
        );
        assert_eq!(
            all.get(Path::new("/c")),
            Some(&wal_full_reason(needed, after_big - cost.round_trip.most))
        );
    }

    /// An admitted item may turn out narrower than its widest and leave more
    /// than the least. The next item, blocked in the least, may then commit
    /// beside it, so the item after is measured as if it had. Here both fit
    /// at their narrowest, and the third does not fit beside them.
    #[test]
    fn full_after_commit() {
        let cost = WalCost::of(BOUNDED, Some(TREE)).unwrap();
        let narrow = narrow_cost(Some(TREE)).life.unwrap();
        let life = WalCost::of(EXACT, Some(TREE)).unwrap().life.unwrap();
        let half = WalCost::of(EXACT, Some(HALF))
            .unwrap()
            .life
            .unwrap()
            .needed
            .most;
        // Halfway between the second fitting beside the first at its narrowest
        // and at its widest.
        let available = narrow.needed.most + (narrow.holds.most + life.holds.most) / 2;
        let after = available - life.holds.most;
        assert!(life.needed.most > after);
        assert!(narrow.needed.most <= available - narrow.holds.most);
        assert!(after - cost.round_trip.most >= half);
        assert!(after - life.holds.most < half);

        let paths = ["/a", "/b", "/c"];
        let mut assessments = paths.map(assessed);
        assessments[2].status = assessed_tree(HALF);
        apply_wal_room(
            &mut assessments,
            &paths.map(planned),
            |_| Some(BOUNDED),
            room(available),
        );

        assert_eq!(wal_needed(&assessments[0]), Some(life.needed.most));
        assert_eq!(wal_full_available(&assessments[1]), Some(after));
        assert_eq!(
            wal_full_available(&assessments[2]),
            Some(after - life.holds.most)
        );
    }

    /// A purge in the same run spends a committed item's allowance on less
    /// than it was, so under `--purge` an admitted item is sure to leave only
    /// the frames it wrote. The next item, blocked in the least, may then
    /// commit where beside a commit that keeps its allowance it could not, and
    /// the item after is measured as if it had.
    #[test]
    fn purge_gives_back() {
        let cost = WalCost::of(BOUNDED, Some(TREE)).unwrap();
        let narrow = narrow_cost(Some(TREE)).life.unwrap();
        let life = WalCost::of(EXACT, Some(TREE)).unwrap().life.unwrap();
        let half = WalCost::of(EXACT, Some(HALF))
            .unwrap()
            .life
            .unwrap()
            .needed
            .most;
        // Halfway between the second fitting beside the first's frames at
        // their narrowest and at their widest, and so short of fitting beside
        // all the first holds.
        let available = narrow.needed.most + (narrow.writes + life.writes) / 2;
        let after = available - life.holds.most;
        assert!(narrow.needed.most > available - narrow.holds.most);
        assert!(narrow.needed.most <= available - narrow.writes);
        assert!(narrow.needed.most > available - life.writes);
        assert!(after - cost.round_trip.most >= half);
        assert!(after.saturating_sub(life.holds.most) < half);

        for purge in [false, true] {
            let paths = ["/a", "/b", "/c"];
            let mut assessments = paths.map(assessed);
            assessments[2].status = assessed_tree(HALF);
            for assessment in &mut assessments {
                assessment.purge_requested = purge;
            }
            apply_wal_room(
                &mut assessments,
                &paths.map(planned),
                |_| Some(BOUNDED),
                room(available),
            );

            assert_eq!(wal_full_available(&assessments[1]), Some(after));
            if purge {
                assert_eq!(
                    wal_full_available(&assessments[2]),
                    Some(after.saturating_sub(life.holds.most))
                );
            } else {
                assert_eq!(wal_needed(&assessments[2]), Some(half));
            }
        }
    }

    /// A clean's lease may compact the WAL before its first item, so an item
    /// that does not fit in the room measured may commit, or begin and be
    /// refused, in the room compacted, and the next item is measured as if it
    /// had. With nothing to take back it could do neither.
    #[test]
    fn room_once_compacted() {
        let cost = WalCost::of(EXACT, Some(TREE)).unwrap();
        let life = cost.life.unwrap();
        let round_trip = cost.round_trip.most;
        let half = WalCost::of(EXACT, Some(HALF))
            .unwrap()
            .life
            .unwrap()
            .needed
            .most;
        // Short of the tree's life by its round trip, and then of the round
        // trip by half of it.
        let short = life.needed.most - round_trip;
        let shorter = round_trip / 2;
        assert!(short - round_trip >= half && short - life.holds.most < half);
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
                assert_eq!(
                    wal_full_available(&assessments[1]),
                    Some(short - life.holds.most)
                );
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
