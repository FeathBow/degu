//! Quota observation around one permanent action batch.
//!
//! This module is reporting-only. Canonical anchors are probe inputs and never
//! mutation authority.

use crate::action_result::{
    ActionId, ActionKind, ActionObservationTargets, ActionObservations, ActionResultOwner,
    CompletedActionBatchResult, ContractError, NotStartedReason, ObservationRequestPath,
    PlannedActionBatch, QuotaObservationState, QuotaObservationTarget, ResolvedQuotaObservation,
    StartedActionOutcome,
};
use crate::quota::{ProbeError, QuotaSnapshot};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub(crate) type CompletedQuotaAction =
    CompletedActionBatchResult<UnavailableObservation, IncomparableDimension, ObservedUsageDelta>;
type NotAttemptedQuotaAction = CompletedActionBatchResult<(), (), ()>;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QuotaActionReport {
    Attempted(CompletedQuotaAction),
    NotAttempted(NotAttemptedQuotaAction),
}

#[derive(Debug)]
pub(crate) enum ObservationPlanError {
    Contract(ContractError),
}

impl std::fmt::Display for ObservationPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid observation contract: {error:?}"),
        }
    }
}

impl std::error::Error for ObservationPlanError {}

pub(crate) fn planned_action(
    owner: ActionResultOwner,
    kind: ActionKind,
    id: &'static str,
    anchors: impl IntoIterator<Item = PathBuf>,
) -> Result<PlannedActionBatch, ObservationPlanError> {
    let targets = anchors
        .into_iter()
        .map(ObservationRequestPath::new)
        .map(QuotaObservationTarget::new)
        .collect::<Vec<_>>();
    Ok(PlannedActionBatch::new(
        owner,
        kind,
        ActionId::new(id).map_err(ObservationPlanError::Contract)?,
        ActionObservationTargets::new(targets),
    ))
}

pub(crate) fn not_attempted(
    planned: PlannedActionBatch,
    reason: NotStartedReason,
) -> QuotaActionReport {
    QuotaActionReport::NotAttempted(planned.complete_not_started(reason))
}

pub(crate) fn not_attempted_action(
    owner: ActionResultOwner,
    kind: ActionKind,
    id: &'static str,
    anchors: impl IntoIterator<Item = PathBuf>,
    reason: NotStartedReason,
) -> Result<QuotaActionReport, ObservationPlanError> {
    // A not-attempted action never dereferences an anchor, so a dry-run keeps its
    // captured lexical targets without touching or requiring the filesystem.
    Ok(not_attempted(
        planned_action(owner, kind, id, anchors)?,
        reason,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbePhase {
    Before,
    After,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct UnavailableObservation {
    pub(crate) phase: ProbePhase,
    pub(crate) category: &'static str,
    pub(crate) message: String,
}

impl UnavailableObservation {
    fn from_error(phase: ProbePhase, error: ProbeError) -> Self {
        Self {
            phase,
            category: error.category(),
            message: error.raw_message(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IncomparableDimension {
    ActiveState,
    Provider,
    DataSource,
    Filesystem,
    MountPoint,
    ScopeIdentity,
    SubjectKind,
    SubjectId,
    ObservationAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ObservedSubject {
    pub(crate) kind: &'static str,
    pub(crate) id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ObservedUsageDelta {
    pub(crate) provider: &'static str,
    pub(crate) data_source: &'static str,
    pub(crate) filesystem: String,
    pub(crate) mount_point: PathBuf,
    pub(crate) subject: ObservedSubject,
    pub(crate) space_used_before_bytes: u64,
    pub(crate) space_used_after_bytes: u64,
    pub(crate) space_used_delta_bytes: i128,
    pub(crate) inodes_used_before: u64,
    pub(crate) inodes_used_after: u64,
    pub(crate) inodes_used_delta: i128,
}

pub(crate) fn compare(
    anchor: &Path,
    before: &QuotaSnapshot,
    after: &QuotaSnapshot,
) -> Result<ObservedUsageDelta, IncomparableDimension> {
    if before.state != "active" || after.state != "active" {
        return Err(IncomparableDimension::ActiveState);
    }
    if before.provider != after.provider {
        return Err(IncomparableDimension::Provider);
    }
    if before.data_source != after.data_source {
        return Err(IncomparableDimension::DataSource);
    }
    if before.scope.filesystem != after.scope.filesystem {
        return Err(IncomparableDimension::Filesystem);
    }
    if before.scope.mount_point != after.scope.mount_point {
        return Err(IncomparableDimension::MountPoint);
    }
    if before.scope.identity != after.scope.identity {
        return Err(IncomparableDimension::ScopeIdentity);
    }
    if before.subject.kind != after.subject.kind {
        return Err(IncomparableDimension::SubjectKind);
    }
    if before.subject.id != after.subject.id {
        return Err(IncomparableDimension::SubjectId);
    }
    if before.scope.path != anchor || after.scope.path != anchor {
        return Err(IncomparableDimension::ObservationAnchor);
    }
    Ok(ObservedUsageDelta {
        provider: before.provider,
        data_source: before.data_source,
        filesystem: before.scope.filesystem.clone(),
        mount_point: before.scope.mount_point.clone(),
        subject: ObservedSubject {
            kind: before.subject.kind,
            id: before.subject.id,
        },
        space_used_before_bytes: before.space.used,
        space_used_after_bytes: after.space.used,
        space_used_delta_bytes: i128::from(after.space.used) - i128::from(before.space.used),
        inodes_used_before: before.inodes.used,
        inodes_used_after: after.inodes.used,
        inodes_used_delta: i128::from(after.inodes.used) - i128::from(before.inodes.used),
    })
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ScopeIdentity {
    provider: &'static str,
    data_source: &'static str,
    filesystem: String,
    mount_point: PathBuf,
    provider_scope: crate::quota::model::QuotaScopeIdentity,
    subject_kind: &'static str,
    subject_id: u32,
}

impl ScopeIdentity {
    fn from_snapshot(snapshot: &QuotaSnapshot) -> Self {
        Self {
            provider: snapshot.provider,
            data_source: snapshot.data_source,
            filesystem: snapshot.scope.filesystem.clone(),
            mount_point: snapshot.scope.mount_point.clone(),
            provider_scope: snapshot.scope.identity.clone(),
            subject_kind: snapshot.subject.kind,
            subject_id: snapshot.subject.id,
        }
    }
}

enum PreResolution {
    Scope {
        identity: ScopeIdentity,
        anchors: Vec<ObservationRequestPath>,
        canonical: PathBuf,
        before: Box<QuotaSnapshot>,
    },
    Unavailable {
        anchor: ObservationRequestPath,
        detail: UnavailableObservation,
    },
}

fn canonicalize_before(anchor: &Path) -> Result<PathBuf, UnavailableObservation> {
    if !anchor.is_absolute() {
        return Err(UnavailableObservation {
            phase: ProbePhase::Before,
            category: "invalid_request",
            message: format!(
                "quota observation request is not absolute: {}",
                anchor.display()
            ),
        });
    }
    std::fs::canonicalize(anchor).map_err(|source| UnavailableObservation {
        phase: ProbePhase::Before,
        category: "canonicalize_io",
        message: format!("failed to canonicalize {}: {source}", anchor.display()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PostObservationPolicy {
    Probe,
    Unavailable {
        category: &'static str,
        message: String,
    },
}

/// The only injectable quota-probe seam. Canonicalization is deliberately part
/// of this best-effort phase: neither it nor a provider failure can prevent the
/// execution closure. A successful pre probe binds post probing to that exact
/// canonical path. Pre-discovery must inspect each distinct requested anchor;
/// once identity is known, post probing occurs once per stable identity.
pub(crate) fn coordinate<R>(
    planned: PlannedActionBatch,
    probe: &mut impl FnMut(&Path) -> Result<QuotaSnapshot, ProbeError>,
    execute: impl FnOnce() -> (R, StartedActionOutcome),
) -> (R, CompletedQuotaAction) {
    coordinate_with_post_policy(planned, probe, || {
        let (result, outcome) = execute();
        (result, outcome, PostObservationPolicy::Probe)
    })
}

/// Native runners use this variant when child termination cannot be confirmed.
/// It completes the started action but refuses to label a concurrent snapshot
/// as post-action data while the first action may still be mutating.
pub(crate) fn coordinate_with_post_policy<R>(
    planned: PlannedActionBatch,
    probe: &mut impl FnMut(&Path) -> Result<QuotaSnapshot, ProbeError>,
    execute: impl FnOnce() -> (R, StartedActionOutcome, PostObservationPolicy),
) -> (R, CompletedQuotaAction) {
    let anchors = planned
        .observation_targets()
        .quota_scopes()
        .iter()
        .map(|target| target.anchor().clone())
        .collect::<Vec<_>>();
    let mut pre = Vec::<PreResolution>::new();
    for anchor in anchors {
        let canonical = match canonicalize_before(anchor.as_path()) {
            Ok(canonical) => canonical,
            Err(detail) => {
                pre.push(PreResolution::Unavailable { anchor, detail });
                continue;
            }
        };
        match probe(&canonical) {
            Ok(before) => {
                let identity = ScopeIdentity::from_snapshot(&before);
                if let Some(PreResolution::Scope { anchors, .. }) = pre.iter_mut().find(|entry| {
                    matches!(entry, PreResolution::Scope { identity: existing, .. } if *existing == identity)
                }) {
                    anchors.push(anchor);
                } else {
                    pre.push(PreResolution::Scope {
                        identity,
                        anchors: vec![anchor],
                        canonical,
                        before: Box::new(before),
                    });
                }
            }
            Err(error) => pre.push(PreResolution::Unavailable {
                anchor,
                detail: UnavailableObservation::from_error(ProbePhase::Before, error),
            }),
        }
    }

    let started = planned.start();
    let (result, outcome, post_policy) = execute();
    let mut pending = started.finish_execution(outcome);

    let mut resolved = Vec::with_capacity(pre.len());
    for entry in pre {
        match entry {
            PreResolution::Scope {
                anchors,
                canonical,
                before,
                ..
            } => {
                let state = match &post_policy {
                    PostObservationPolicy::Unavailable { category, message } => {
                        QuotaObservationState::Unavailable(UnavailableObservation {
                            phase: ProbePhase::After,
                            category,
                            message: message.clone(),
                        })
                    }
                    PostObservationPolicy::Probe => match probe(&canonical) {
                        Err(error) => QuotaObservationState::Unavailable(
                            UnavailableObservation::from_error(ProbePhase::After, error),
                        ),
                        Ok(after) => match compare(&canonical, &before, &after) {
                            Ok(delta) => match serde_json::to_value(&delta) {
                                Ok(_) => QuotaObservationState::Observed(delta),
                                Err(error) => {
                                    QuotaObservationState::Unavailable(UnavailableObservation {
                                        phase: ProbePhase::After,
                                        category: "output_unrepresentable",
                                        message: format!(
                                            "quota observation cannot be represented in JSON: {error}"
                                        ),
                                    })
                                }
                            },
                            Err(dimension) => QuotaObservationState::Incomparable(dimension),
                        },
                    },
                };
                resolved.push(ResolvedQuotaObservation::new(anchors, state));
            }
            PreResolution::Unavailable { anchor, detail } => {
                // A pre-unavailable anchor has no before snapshot, so no post
                // probe could yield a delta; it stays unavailable as observed.
                resolved.push(ResolvedQuotaObservation::new(
                    [anchor],
                    QuotaObservationState::Unavailable(detail),
                ));
            }
        }
    }
    let observations = resolved
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .and_then(|resolved| {
            let ticket = pending.take_observation_ticket()?;
            ActionObservations::resolve(ticket, resolved)
        });
    let internal_unavailable = UnavailableObservation {
        phase: ProbePhase::After,
        category: "internal_contract",
        message: observations.as_ref().err().map_or_else(
            || "internal observation contract failure".to_owned(),
            |error| format!("internal observation contract failure: {error:?}"),
        ),
    };
    let completed = pending.complete_or_all_unavailable(observations, internal_unavailable);
    (result, completed)
}

fn output_unrepresentable_json(message: &str) -> serde_json::Value {
    serde_json::json!({
        "state": "unavailable",
        "phase": ProbePhase::After,
        "error_category": "output_unrepresentable",
        "message": message,
    })
}

pub(crate) fn json(report: &QuotaActionReport) -> serde_json::Value {
    match report {
        QuotaActionReport::Attempted(action) => serde_json::json!({
            "observation_state": "resolved",
            "owner": owner_json(action.owner()),
            "kind": kind_label(action.kind()),
            "id": action.id().as_str(),
            "quota_observations": action.observations().quota_scopes().iter().map(|scope| {
                let detail = match scope.state() {
                    QuotaObservationState::NotAttempted => serde_json::json!({"state": "not_attempted"}),
                    QuotaObservationState::Unavailable(unavailable) => serde_json::json!({
                        "state": "unavailable",
                        "phase": unavailable.phase,
                        "error_category": unavailable.category,
                        "message": unavailable.message,
                    }),
                    QuotaObservationState::Incomparable(dimension) => serde_json::json!({
                        "state": "incomparable",
                        "dimension": dimension,
                    }),
                    QuotaObservationState::Observed(observed) => {
                        match serde_json::to_value(observed) {
                            Ok(mut value) => {
                                if let Some(object) = value.as_object_mut() {
                                    object.insert(
                                        "state".to_owned(),
                                        serde_json::Value::String("observed".to_owned()),
                                    );
                                    value
                                } else {
                                    output_unrepresentable_json("observed quota delta was not an object")
                                }
                            }
                            Err(error) => output_unrepresentable_json(&error.to_string()),
                        }
                    }
                };
                serde_json::json!({
                    "anchors": scope.anchors().iter().map(|anchor| anchor.as_path().to_string_lossy().into_owned()).collect::<Vec<_>>(),
                    "quota_observed_usage_delta": detail,
                })
            }).collect::<Vec<_>>(),
        }),
        QuotaActionReport::NotAttempted(action) => serde_json::json!({
            "observation_state": "not_attempted",
            "owner": owner_json(action.owner()),
            "kind": kind_label(action.kind()),
            "id": action.id().as_str(),
            "quota_observations": action.observations().quota_scopes().iter().map(|scope| {
                debug_assert!(matches!(scope.state(), QuotaObservationState::NotAttempted));
                serde_json::json!({
                    "anchors": scope.anchors().iter().map(|anchor| anchor.as_path().to_string_lossy().into_owned()).collect::<Vec<_>>(),
                    "quota_observed_usage_delta": {"state": "not_attempted"},
                })
            }).collect::<Vec<_>>(),
        }),
    }
}

fn owner_json(owner: &ActionResultOwner) -> serde_json::Value {
    match owner {
        ActionResultOwner::CleanCommand => serde_json::json!("clean"),
        ActionResultOwner::TrashPurgeCommand => serde_json::json!("trash_purge"),
        ActionResultOwner::NativeAdapter { adapter_id } => {
            serde_json::json!({"native_adapter": adapter_id.as_str()})
        }
    }
}

fn kind_label(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::DirectPurge => "direct_purge",
        ActionKind::ExpiryPurge => "expiry_purge",
        ActionKind::TrashPurge => "trash_purge",
        ActionKind::Native => "native",
    }
}

#[derive(Debug, Eq, PartialEq)]
enum HumanObservationLine {
    Stdout(String),
    Warning(String),
}

fn human_lines(report: &QuotaActionReport) -> Vec<HumanObservationLine> {
    let QuotaActionReport::Attempted(action) = report else {
        return Vec::new();
    };
    action
        .observations()
        .quota_scopes()
        .iter()
        .filter_map(|scope| {
            let anchors = scope
                .anchors()
                .iter()
                .map(|anchor| {
                    crate::presentation::escape_terminal_text(
                        &anchor.as_path().display().to_string(),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            match scope.state() {
                QuotaObservationState::Observed(delta) => Some(HumanObservationLine::Stdout(
                    format!(
                        "Observed quota usage change for {anchors}: {} bytes, {} inodes. Negative means usage decreased during the observation window; this is not attributed exclusively to degu.",
                        delta.space_used_delta_bytes, delta.inodes_used_delta
                    ),
                )),
                QuotaObservationState::Unavailable(detail) => {
                    Some(HumanObservationLine::Warning(format!(
                        "quota observation unavailable for {anchors} ({:?}, {}): {}",
                        detail.phase,
                        detail.category,
                        crate::presentation::escape_terminal_text(&detail.message)
                    )))
                }
                QuotaObservationState::Incomparable(dimension) => {
                    Some(HumanObservationLine::Warning(format!(
                        "quota observations for {anchors} are incomparable: {} changed",
                        serde_json::to_value(dimension)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "identity".to_owned())
                    )))
                }
                QuotaObservationState::NotAttempted => None,
            }
        })
        .collect()
}

pub(crate) fn print_warnings(report: &QuotaActionReport, colors: crate::runtime::OutputColors) {
    for line in human_lines(report) {
        if let HumanObservationLine::Warning(line) = line {
            crate::presentation::print_stderr_note(
                crate::presentation::Severity::Warning,
                &line,
                colors,
            );
        }
    }
}

pub(crate) fn print_human(
    report: &QuotaActionReport,
    colors: crate::runtime::OutputColors,
) -> anyhow::Result<()> {
    for line in human_lines(report) {
        match line {
            HumanObservationLine::Stdout(line) => crate::output::stdoutln!("{line}")?,
            HumanObservationLine::Warning(line) => crate::presentation::print_stderr_note(
                crate::presentation::Severity::Warning,
                &line,
                colors,
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_result::{
        ActionId, ActionKind, ActionObservationTargets, ActionOutcome, ActionResultOwner,
        QuotaObservationTarget,
    };
    use crate::quota::model::{
        ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaScope,
        QuotaScopeIdentity,
    };
    use std::collections::VecDeque;

    fn snapshot(path: &str, used: u64, inodes: u64) -> QuotaSnapshot {
        QuotaSnapshot::active(
            QuotaScope::new(
                PathBuf::from(path),
                PathBuf::from("/home"),
                "ext4".into(),
                QuotaScopeIdentity::new(36, 8, 1, PathBuf::from("/dev/root")),
            ),
            1000,
            ActiveQuota {
                provider: "linux_vfs",
                data_source: "linux_quotactl",
                space: QuotaDimension::new(used, QuotaLimits::new(0, 0), None),
                inodes: QuotaDimension::new(inodes, QuotaLimits::new(0, 0), None),
            },
        )
    }

    fn planned(paths: &[&str]) -> PlannedActionBatch {
        let targets = ActionObservationTargets::new(paths.iter().map(|path| {
            QuotaObservationTarget::new(ObservationRequestPath::new(PathBuf::from(path)))
        }));
        PlannedActionBatch::new(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            ActionId::new("test:purge").unwrap(),
            targets,
        )
    }

    #[test]
    fn signed_edges_do_not_underflow_or_saturate() {
        let low = snapshot("/home", 0, 0);
        let high = snapshot("/home", u64::MAX, u64::MAX);
        let increase = compare(Path::new("/home"), &low, &high).unwrap();
        let decrease = compare(Path::new("/home"), &high, &low).unwrap();
        assert_eq!(increase.space_used_delta_bytes, i128::from(u64::MAX));
        assert_eq!(decrease.space_used_delta_bytes, -i128::from(u64::MAX));
        assert_eq!(decrease.inodes_used_delta, -i128::from(u64::MAX));
        assert_eq!(
            compare(Path::new("/home"), &low, &snapshot("/home", 0, 0))
                .unwrap()
                .space_used_delta_bytes,
            0
        );
        let mut replies = VecDeque::from([
            Ok(snapshot("/", u64::MAX, u64::MAX)),
            Ok(snapshot("/", 0, 0)),
        ]);
        let (_, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        let encoded =
            serde_json::to_string(&json(&QuotaActionReport::Attempted(completed))).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            roundtrip["quota_observations"][0]["quota_observed_usage_delta"]
                ["space_used_delta_bytes"]
                .to_string(),
            "-18446744073709551615"
        );
    }

    #[test]
    fn limits_may_change_while_usage_remains_comparable() {
        let before = snapshot("/home", 10, 2);
        let mut after = snapshot("/home", 8, 1);
        after.space.soft_limit = Some(99);
        after.space.grace = Some(QuotaGrace {
            state: QuotaGraceState::Expired,
            expires_at_unix: None,
        });
        assert_eq!(
            compare(Path::new("/home"), &before, &after)
                .unwrap()
                .space_used_delta_bytes,
            -2
        );
    }

    #[test]
    fn mismatch_order_is_fail_closed() {
        let before = snapshot("/home", 10, 2);
        let mut after = snapshot("/wrong", 8, 1);
        after.state = "inactive";
        after.provider = "other";
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::ActiveState)
        );
        after.state = "active";
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::Provider)
        );
        after.provider = before.provider;
        after.data_source = "other";
        after.scope.filesystem = "xfs".into();
        after.scope.mount_point = "/other".into();
        after.subject.kind = "group";
        after.subject.id = 1001;
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::DataSource)
        );
        after.data_source = before.data_source;
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::Filesystem)
        );
        after.scope.filesystem = before.scope.filesystem.clone();
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::MountPoint)
        );
        after.scope.mount_point = before.scope.mount_point.clone();
        after.scope.identity = QuotaScopeIdentity::new(37, 8, 2, PathBuf::from("/dev/replacement"));
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::ScopeIdentity)
        );
        after.scope.identity = before.scope.identity.clone();
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::SubjectKind)
        );
        after.subject.kind = before.subject.kind;
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::SubjectId)
        );
        after.subject.id = before.subject.id;
        assert_eq!(
            compare(Path::new("/home"), &before, &after),
            Err(IncomparableDimension::ObservationAnchor)
        );
    }

    #[test]
    fn every_identity_dimension_is_checked_independently() {
        fn assert_mismatch(
            mutate: impl FnOnce(&mut QuotaSnapshot),
            expected: IncomparableDimension,
        ) {
            let before = snapshot("/home", 10, 2);
            let mut after = snapshot("/home", 8, 1);
            mutate(&mut after);
            assert_eq!(compare(Path::new("/home"), &before, &after), Err(expected));
        }
        assert_mismatch(
            |after| after.state = "inactive",
            IncomparableDimension::ActiveState,
        );
        assert_mismatch(
            |after| after.provider = "other",
            IncomparableDimension::Provider,
        );
        assert_mismatch(
            |after| after.data_source = "other",
            IncomparableDimension::DataSource,
        );
        assert_mismatch(
            |after| after.scope.filesystem = "xfs".into(),
            IncomparableDimension::Filesystem,
        );
        assert_mismatch(
            |after| after.scope.mount_point = "/other".into(),
            IncomparableDimension::MountPoint,
        );
        assert_mismatch(
            |after| {
                after.scope.identity =
                    QuotaScopeIdentity::new(37, 8, 2, PathBuf::from("/dev/replacement"));
            },
            IncomparableDimension::ScopeIdentity,
        );
        assert_mismatch(
            |after| after.subject.kind = "group",
            IncomparableDimension::SubjectKind,
        );
        assert_mismatch(
            |after| after.subject.id = 1001,
            IncomparableDimension::SubjectId,
        );
        assert_mismatch(
            |after| after.scope.path = "/other".into(),
            IncomparableDimension::ObservationAnchor,
        );
    }

    #[test]
    fn coordinator_orders_pre_execute_post_and_keeps_post_on_failure() {
        let events = std::cell::RefCell::new(Vec::new());
        let mut replies = VecDeque::from([Ok(snapshot("/", 10, 2)), Ok(snapshot("/", 7, 1))]);
        let mut probe = |_: &Path| {
            events.borrow_mut().push("probe");
            replies.pop_front().unwrap()
        };
        let (value, completed) = coordinate(planned(&["/"]), &mut probe, || {
            events.borrow_mut().push("execute");
            (42, StartedActionOutcome::Failure)
        });
        assert_eq!(value, 42);
        assert_eq!(*events.borrow(), ["probe", "execute", "probe"]);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(delta) if delta.space_used_delta_bytes == -3
        ));
    }

    #[test]
    fn unconfirmed_termination_suppresses_post_probe_and_marks_after_unavailable() {
        let mut replies = VecDeque::from([Ok(snapshot("/", 10, 2))]);
        let mut calls = 0;
        let (_, completed) = coordinate_with_post_policy(
            planned(&["/"]),
            &mut |_| {
                calls += 1;
                replies.pop_front().unwrap()
            },
            || {
                (
                    (),
                    StartedActionOutcome::Failure,
                    PostObservationPolicy::Unavailable {
                        category: "action_not_terminal",
                        message: "termination unconfirmed".to_owned(),
                    },
                )
            },
        );
        assert_eq!(calls, 1, "only the pre-action probe may run");
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::After,
                category: "action_not_terminal",
                message,
            }) if message == "termination unconfirmed"
        ));
    }

    #[test]
    fn coordinator_observes_a_partially_failed_batch() {
        let mut replies = VecDeque::from([Ok(snapshot("/", 10, 2)), Ok(snapshot("/", 6, 1))]);
        let mut probe = |_: &Path| replies.pop_front().unwrap();
        let (_, completed) = coordinate(planned(&["/"]), &mut probe, || {
            ((), StartedActionOutcome::Partial)
        });
        assert_eq!(completed.outcome(), ActionOutcome::Partial);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(delta) if delta.space_used_delta_bytes == -4
        ));
    }

    #[test]
    fn canonicalization_failure_is_before_unavailable_and_never_blocks_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("created-by-action");
        let action = planned_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "test:canonicalize",
            [requested.clone()],
        )
        .unwrap();
        let mut calls = 0;
        let (_, completed) = coordinate(
            action,
            &mut |path| {
                calls += 1;
                Ok(snapshot(path.to_str().unwrap(), 7, 1))
            },
            || {
                std::fs::create_dir(&requested).unwrap();
                ((), StartedActionOutcome::Success)
            },
        );
        assert_eq!(
            calls, 0,
            "an anchor whose pre canonicalization failed is never probed"
        );
        assert!(requested.is_dir());
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::Before,
                category: "canonicalize_io",
                ..
            })
        ));
    }

    #[test]
    fn invalid_relative_request_cannot_mask_mutation_failure() {
        let action = planned_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "test:relative-request",
            [PathBuf::from(".")],
        )
        .unwrap();
        let mut probes = 0;
        let (mutation, completed) = coordinate(
            action,
            &mut |_| {
                probes += 1;
                unreachable!("relative requests must never probe")
            },
            || ("mutation-failed", StartedActionOutcome::Failure),
        );
        assert_eq!(mutation, "mutation-failed");
        assert_eq!(probes, 0);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::Before,
                category: "invalid_request",
                ..
            })
        ));
    }

    #[test]
    fn lexical_parent_alias_is_canonicalized_with_filesystem_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let physical = temp.path().join("physical");
        let alias = temp.path().join("alias");
        let real = temp.path().join("real");
        std::fs::create_dir(&physical).unwrap();
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&physical, &alias).unwrap();
        let requested = alias.join("..").join("real");
        let action = planned_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "test:parent-alias",
            [requested],
        )
        .unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        let mut probed = Vec::new();
        let (_, completed) = coordinate(
            action,
            &mut |path| {
                probed.push(path.to_path_buf());
                Ok(snapshot(path.to_str().unwrap(), 10, 1))
            },
            || ((), StartedActionOutcome::Success),
        );
        assert_eq!(probed, [canonical.clone(), canonical]);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_mount_becomes_output_unrepresentable_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let non_utf8_mount = PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff]));
        let mut before = snapshot("/", 10, 2);
        before.scope.mount_point = non_utf8_mount.clone();
        let mut after = snapshot("/", 7, 2);
        after.scope.mount_point = non_utf8_mount;
        let mut replies = VecDeque::from([Ok(before), Ok(after)]);
        let (_, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Failure),
        );
        let report = QuotaActionReport::Attempted(completed);
        assert!(matches!(
            report,
            QuotaActionReport::Attempted(ref completed)
                if matches!(completed.observations().quota_scopes()[0].state(),
                    QuotaObservationState::Unavailable(UnavailableObservation {
                        category: "output_unrepresentable", ..
                    }))
        ));
        assert_eq!(
            json(&report)["quota_observations"][0]["quota_observed_usage_delta"]["state"],
            "unavailable"
        );
    }

    #[test]
    fn post_probe_retains_the_successful_pre_canonical_binding() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let requested = temp.path().join("requested");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        symlink(&first, &requested).unwrap();
        let action = planned_action(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            "test:canonical-binding",
            [requested.clone()],
        )
        .unwrap();
        let mut probed = Vec::new();
        let (_, completed) = coordinate(
            action,
            &mut |path| {
                probed.push(path.to_path_buf());
                Ok(snapshot(
                    path.to_str().unwrap(),
                    10 - probed.len() as u64,
                    1,
                ))
            },
            || {
                std::fs::rename(&requested, temp.path().join("old-request")).unwrap();
                symlink(&second, &requested).unwrap();
                ((), StartedActionOutcome::Success)
            },
        );
        let first = std::fs::canonicalize(first).unwrap();
        assert_eq!(probed, [first.clone(), first]);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(_)
        ));
    }

    #[test]
    fn equal_identities_fold_despite_different_pre_usage_and_probe_post_once() {
        let mut second_before = snapshot("/dev", 99, 42);
        // Identity excludes the requested observation path and usage values.
        second_before.scope.mount_point = "/home".into();
        let mut replies = VecDeque::from([
            Ok(snapshot("/", 10, 2)),
            Ok(second_before),
            Ok(snapshot("/", 7, 1)),
        ]);
        let mut calls = 0;
        let (_, completed) = coordinate(
            planned(&["/", "/dev"]),
            &mut |_| {
                calls += 1;
                replies.pop_front().unwrap()
            },
            || ((), StartedActionOutcome::Success),
        );
        assert_eq!(calls, 3);
        assert_eq!(completed.observations().quota_scopes().len(), 1);
        assert_eq!(
            completed.observations().quota_scopes()[0].anchors().len(),
            2
        );
    }

    #[test]
    fn different_filesystems_are_never_folded() {
        let a_before = snapshot("/", 10, 2);
        let mut b_before = snapshot("/dev", 10, 2);
        b_before.scope.mount_point = "/scratch".into();
        b_before.scope.filesystem = "xfs".into();
        let a_after = snapshot("/", 7, 1);
        let mut b_after = snapshot("/dev", 7, 1);
        b_after.scope.mount_point = "/scratch".into();
        b_after.scope.filesystem = "xfs".into();
        let mut replies = VecDeque::from([Ok(a_before), Ok(b_before), Ok(a_after), Ok(b_after)]);
        let (_, completed) = coordinate(
            planned(&["/", "/dev"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        assert_eq!(completed.observations().quota_scopes().len(), 2);
    }

    #[test]
    fn replacement_mount_identities_are_never_folded() {
        let a_before = snapshot("/", 10, 2);
        let mut b_before = snapshot("/dev", 10, 2);
        b_before.scope.identity =
            QuotaScopeIdentity::new(37, 8, 2, PathBuf::from("/dev/replacement"));
        let a_after = snapshot("/", 7, 1);
        let mut b_after = snapshot("/dev", 7, 1);
        b_after.scope.identity = b_before.scope.identity.clone();
        let mut replies = VecDeque::from([Ok(a_before), Ok(b_before), Ok(a_after), Ok(b_after)]);
        let (_, completed) = coordinate(
            planned(&["/", "/dev"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        assert_eq!(completed.observations().quota_scopes().len(), 2);
    }

    #[test]
    fn pre_failure_does_not_block_execution_and_is_explicit() {
        let mut executed = false;
        let mut replies = VecDeque::from([
            Err(ProbeError::Unavailable {
                filesystem: "ext4".into(),
                mount_point: "/home".into(),
                reason: "before failed".into(),
            }),
            Ok(snapshot("/", 7, 1)),
        ]);
        let (_, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || {
                executed = true;
                ((), StartedActionOutcome::Success)
            },
        );
        assert!(executed);
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::Before,
                category: "unavailable",
                ..
            })
        ));
    }

    #[test]
    fn observed_json_is_signed_and_keeps_the_b0_action_envelope() {
        let mut replies = VecDeque::from([Ok(snapshot("/", 10, 2)), Ok(snapshot("/", 7, 1))]);
        let (_, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        let value = json(&QuotaActionReport::Attempted(completed));
        assert_eq!(value["owner"], "clean");
        assert_eq!(value["kind"], "direct_purge");
        let delta = &value["quota_observations"][0]["quota_observed_usage_delta"];
        assert_eq!(delta["state"], "observed");
        assert_eq!(delta["space_used_delta_bytes"], -3);
        assert_eq!(delta["inodes_used_delta"], -1);
        assert_eq!(
            delta["subject"],
            serde_json::json!({"kind": "user", "id": 1000})
        );
        assert_eq!(
            delta
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "data_source",
                "filesystem",
                "inodes_used_after",
                "inodes_used_before",
                "inodes_used_delta",
                "mount_point",
                "provider",
                "space_used_after_bytes",
                "space_used_before_bytes",
                "space_used_delta_bytes",
                "state",
                "subject",
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn human_observed_copy_is_noncausal_and_warning_text_is_escaped() {
        let mut observed_replies =
            VecDeque::from([Ok(snapshot("/", 10, 2)), Ok(snapshot("/", 7, 1))]);
        let (_, observed) = coordinate(
            planned(&["/"]),
            &mut |_| observed_replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        let lines = human_lines(&QuotaActionReport::Attempted(observed));
        let HumanObservationLine::Stdout(line) = &lines[0] else {
            panic!("expected observed stdout")
        };
        assert!(line.starts_with("Observed quota usage change"));
        assert!(line.contains("Negative means usage decreased"));
        assert!(line.contains("not attributed exclusively to degu"));

        let mut unavailable_replies = VecDeque::from([
            Err(ProbeError::Unavailable {
                filesystem: "ext4\u{1b}[31m".into(),
                mount_point: "/home\nother".into(),
                reason: "bad\tprobe".into(),
            }),
            Ok(snapshot("/", 7, 1)),
        ]);
        let (_, unavailable) = coordinate(
            planned(&["/"]),
            &mut |_| unavailable_replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        let report = QuotaActionReport::Attempted(unavailable);
        let machine = json(&report);
        let detail = &machine["quota_observations"][0]["quota_observed_usage_delta"];
        assert!(detail["message"].as_str().unwrap().contains('\u{1b}'));
        assert!(detail["message"].as_str().unwrap().contains('\n'));
        assert_eq!(
            detail
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["error_category", "message", "phase", "state"]
                .into_iter()
                .collect()
        );
        let lines = human_lines(&report);
        let HumanObservationLine::Warning(line) = &lines[0] else {
            panic!("expected warning")
        };
        assert!(!line.contains('\u{1b}'));
        assert!(line.contains("ext4\\u{1b}[31m"));
        assert!(line.contains("/home\\nother"));
        assert!(line.contains("bad\\tprobe"));
    }

    #[test]
    fn incomparable_json_shape_is_frozen() {
        let before = snapshot("/", 10, 2);
        let mut after = snapshot("/", 7, 1);
        after.subject.id = 2000;
        let mut replies = VecDeque::from([Ok(before), Ok(after)]);
        let (_, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || ((), StartedActionOutcome::Success),
        );
        let value = json(&QuotaActionReport::Attempted(completed));
        let detail = &value["quota_observations"][0]["quota_observed_usage_delta"];
        assert_eq!(
            detail,
            &serde_json::json!({
                "state": "incomparable",
                "dimension": "subject_id",
            })
        );
    }

    #[test]
    fn post_failure_is_explicit_and_does_not_replace_execution_result() {
        let mut replies = VecDeque::from([
            Ok(snapshot("/", 10, 2)),
            Err(ProbeError::Unavailable {
                filesystem: "ext4".into(),
                mount_point: "/home".into(),
                reason: "after failed".into(),
            }),
        ]);
        let (mutation, completed) = coordinate(
            planned(&["/"]),
            &mut |_| replies.pop_front().unwrap(),
            || ("mutation-failed", StartedActionOutcome::Failure),
        );
        assert_eq!(mutation, "mutation-failed");
        assert!(matches!(
            completed.observations().quota_scopes()[0].state(),
            QuotaObservationState::Unavailable(UnavailableObservation {
                phase: ProbePhase::After,
                ..
            })
        ));
    }
}
