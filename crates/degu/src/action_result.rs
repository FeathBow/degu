//! Internal action/batch result contract shared by permanent cleanup paths.
//!
//! This module deliberately contains no runner, quota provider, filesystem
//! mutation, rendering, or serialization. In particular, an observation anchor
//! is a read-only probe location; it is never mutation authority and cannot be
//! converted into a lifecycle capability.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Stable identity of one action within the result owner's namespace.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ActionId(String);

impl ActionId {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ContractError::InvalidActionId);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The command surface which owns presentation and exit behavior for a result.
/// This is reporting ownership only; it confers no mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActionResultOwner {
    CleanCommand,
    TrashPurgeCommand,
    NativeAdapter { adapter_id: ActionId },
}

/// Closed normalization shared by current direct batches and future native work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActionKind {
    DirectPurge,
    ExpiryPurge,
    TrashPurge,
    Native,
}

/// Why an action reached a completed result without crossing its start boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotStartedReason {
    DryRun,
    Cancelled,
    Empty,
    PrerequisiteFailed,
}

/// Terminal execution state for an action which crossed its start boundary.
/// Owner-specific item reports remain outside this normalized envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartedActionOutcome {
    Success,
    Partial,
    Failure,
    Timeout,
    Signal { signal: Option<i32> },
    OutputParseFailure,
    OutputTruncated,
}

/// Normalized terminal state retained by a completed result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActionOutcome {
    NotStarted { reason: NotStartedReason },
    Success,
    Partial,
    Failure,
    Timeout,
    Signal { signal: Option<i32> },
    OutputParseFailure,
    OutputTruncated,
}

impl From<StartedActionOutcome> for ActionOutcome {
    fn from(outcome: StartedActionOutcome) -> Self {
        match outcome {
            StartedActionOutcome::Success => Self::Success,
            StartedActionOutcome::Partial => Self::Partial,
            StartedActionOutcome::Failure => Self::Failure,
            StartedActionOutcome::Timeout => Self::Timeout,
            StartedActionOutcome::Signal { signal } => Self::Signal { signal },
            StartedActionOutcome::OutputParseFailure => Self::OutputParseFailure,
            StartedActionOutcome::OutputTruncated => Self::OutputTruncated,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartBoundary {
    NotStarted,
    Started,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompletionBoundary {
    Completed,
}

/// Uninterpreted path requested solely for read-only action observation.
///
/// It is intentionally an infallible data wrapper: lexical `.`/`..` and symlink
/// traversal retain filesystem meaning until the observation pass canonicalizes
/// inside the non-authoritative probe phase. Relative requests are also captured
/// and later reported as unavailable rather than becoming setup failures.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ObservationRequestPath(PathBuf);

impl ObservationRequestPath {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// Read-only quota probe input. Possessing this path grants no permission to
    /// mutate the path, its children, or the action subject.
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// One prospective quota scope, addressed by an uninterpreted path request.
/// The quota-observation pass canonicalizes and probes it, then decides whether
/// requests identify the same provider scope and subject; this module intentionally
/// does not duplicate the quota identity vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuotaObservationTarget {
    anchor: ObservationRequestPath,
}

impl QuotaObservationTarget {
    pub(crate) fn new(anchor: ObservationRequestPath) -> Self {
        Self { anchor }
    }

    pub(crate) fn anchor(&self) -> &ObservationRequestPath {
        &self.anchor
    }
}

/// Per-action fan-out of read-only quota observations. Exact duplicate anchors
/// are folded while preserving first-seen order; provider-level scope/subject
/// deduplication remains the quota-observation pass's responsibility after probing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ActionObservationTargets {
    quota_scopes: Vec<QuotaObservationTarget>,
}

impl ActionObservationTargets {
    pub(crate) fn new(quota_scopes: impl IntoIterator<Item = QuotaObservationTarget>) -> Self {
        let mut seen = HashSet::new();
        let quota_scopes = quota_scopes
            .into_iter()
            .filter(|target| seen.insert(target.anchor.clone()))
            .collect();
        Self { quota_scopes }
    }

    pub(crate) fn quota_scopes(&self) -> &[QuotaObservationTarget] {
        &self.quota_scopes
    }

    fn anchors(&self) -> HashSet<ObservationRequestPath> {
        self.quota_scopes
            .iter()
            .map(|target| target.anchor.clone())
            .collect()
    }
}

/// Explicit per-scope observation resolution. The observation pass supplies the
/// typed details for unavailable probes, incomparable snapshots, and observed
/// deltas without changing this action envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QuotaObservationState<Unavailable, Incomparable, Observed> {
    NotAttempted,
    Unavailable(Unavailable),
    Incomparable(Incomparable),
    Observed(Observed),
}

/// One resolved quota scope. Multiple input anchors may fold into one record
/// after the observation pass proves they address the same provider scope and subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedQuotaObservation<Unavailable, Incomparable, Observed> {
    anchors: Vec<ObservationRequestPath>,
    state: QuotaObservationState<Unavailable, Incomparable, Observed>,
}

impl<Unavailable, Incomparable, Observed>
    ResolvedQuotaObservation<Unavailable, Incomparable, Observed>
{
    pub(crate) fn new(
        anchors: impl IntoIterator<Item = ObservationRequestPath>,
        state: QuotaObservationState<Unavailable, Incomparable, Observed>,
    ) -> Result<Self, ContractError> {
        let mut seen = HashSet::new();
        let mut collected = Vec::new();
        for anchor in anchors {
            if !seen.insert(anchor.clone()) {
                return Err(ContractError::DuplicateObservationAnchor);
            }
            collected.push(anchor);
        }
        if collected.is_empty() {
            return Err(ContractError::EmptyObservationScope);
        }
        Ok(Self {
            anchors: collected,
            state,
        })
    }

    pub(crate) fn anchors(&self) -> &[ObservationRequestPath] {
        &self.anchors
    }

    pub(crate) fn state(&self) -> &QuotaObservationState<Unavailable, Incomparable, Observed> {
        &self.state
    }
}

/// Resolved observation slot carried by the completed action envelope. Its
/// private fields prevent bypassing target coverage validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionObservations<Unavailable, Incomparable, Observed> {
    correlation: BatchCorrelation,
    quota_scopes: Vec<ResolvedQuotaObservation<Unavailable, Incomparable, Observed>>,
}

impl<Unavailable, Incomparable, Observed> ActionObservations<Unavailable, Incomparable, Observed> {
    /// Consumes the one-shot ticket issued by the exact batch. The resulting
    /// payload cannot be completed by another batch, even when descriptor
    /// values and observation anchors are identical.
    pub(crate) fn resolve(
        ticket: ObservationCorrelationTicket,
        quota_scopes: impl IntoIterator<
            Item = ResolvedQuotaObservation<Unavailable, Incomparable, Observed>,
        >,
    ) -> Result<Self, ContractError> {
        let ObservationCorrelationTicket {
            correlation,
            targets,
        } = ticket;
        let quota_scopes = quota_scopes.into_iter().collect::<Vec<_>>();
        let expected = targets.anchors();
        let mut actual = HashSet::new();
        for scope in &quota_scopes {
            for anchor in &scope.anchors {
                if !actual.insert(anchor.clone()) {
                    return Err(ContractError::DuplicateObservationAnchor);
                }
            }
        }
        if actual != expected {
            return Err(ContractError::ObservationTargetMismatch);
        }
        Ok(Self {
            correlation,
            quota_scopes,
        })
    }

    pub(crate) fn quota_scopes(
        &self,
    ) -> &[ResolvedQuotaObservation<Unavailable, Incomparable, Observed>] {
        &self.quota_scopes
    }

    fn belongs_to(&self, correlation: &BatchCorrelation) -> bool {
        self.correlation.matches(correlation)
    }

    fn covers(&self, targets: &ActionObservationTargets) -> bool {
        self.quota_scopes
            .iter()
            .flat_map(|scope| scope.anchors.iter().cloned())
            .collect::<HashSet<_>>()
            == targets.anchors()
    }

    fn any_not_attempted(&self) -> bool {
        self.quota_scopes
            .iter()
            .any(|scope| matches!(scope.state, QuotaObservationState::NotAttempted))
    }
}

impl ActionObservations<(), (), ()> {
    fn not_attempted(correlation: &BatchCorrelation, targets: &ActionObservationTargets) -> Self {
        let quota_scopes = targets
            .quota_scopes()
            .iter()
            .map(|target| ResolvedQuotaObservation {
                anchors: vec![target.anchor.clone()],
                state: QuotaObservationState::NotAttempted,
            })
            .collect();
        Self {
            correlation: correlation.clone(),
            quota_scopes,
        }
    }
}

/// Private identity minted once with a batch descriptor. Pointer identity is
/// the nonce; descriptor fields bind that nonce to its reporting semantics.
#[derive(Clone, Debug)]
struct BatchCorrelation {
    nonce: Arc<()>,
    owner: ActionResultOwner,
    kind: ActionKind,
    id: ActionId,
}

impl BatchCorrelation {
    fn new(owner: &ActionResultOwner, kind: ActionKind, id: &ActionId) -> Self {
        Self {
            nonce: Arc::new(()),
            owner: owner.clone(),
            kind,
            id: id.clone(),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.nonce, &other.nonce)
            && self.owner == other.owner
            && self.kind == other.kind
            && self.id == other.id
    }
}

impl PartialEq for BatchCorrelation {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for BatchCorrelation {}

/// Non-clone, one-shot capability for resolving observations for one exact
/// batch. It is minted only by `finish_execution` and issued only by the
/// post-execution pending typestate.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservationCorrelationTicket {
    correlation: BatchCorrelation,
    targets: ActionObservationTargets,
}

#[derive(Debug, Eq, PartialEq)]
struct ActionDescriptor {
    owner: ActionResultOwner,
    kind: ActionKind,
    id: ActionId,
    targets: ActionObservationTargets,
    correlation: BatchCorrelation,
}

/// One action/batch which has not crossed its start boundary.
///
/// Direct purge means the selected direct-clean purge batch, expiry means one
/// captured expiry plan, trash purge means one explicitly confirmed purge-all
/// plan, and native means one future validated process invocation. Owner plus ID
/// identifies that batch independently of its kind.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PlannedActionBatch {
    descriptor: ActionDescriptor,
}

impl PlannedActionBatch {
    pub(crate) fn new(
        owner: ActionResultOwner,
        kind: ActionKind,
        id: ActionId,
        targets: ActionObservationTargets,
    ) -> Self {
        let correlation = BatchCorrelation::new(&owner, kind, &id);
        Self {
            descriptor: ActionDescriptor {
                owner,
                kind,
                id,
                targets,
                correlation,
            },
        }
    }

    /// Targets are available before start so the caller can take pre-action snapshots.
    pub(crate) fn observation_targets(&self) -> &ActionObservationTargets {
        &self.descriptor.targets
    }

    pub(crate) fn start(self) -> StartedActionBatch {
        StartedActionBatch {
            descriptor: self.descriptor,
        }
    }

    /// A batch which never starts cannot accept caller-supplied observation
    /// payload. Its exact targets are sealed as `NotAttempted` internally.
    pub(crate) fn complete_not_started(
        self,
        reason: NotStartedReason,
    ) -> CompletedActionBatchResult<(), (), ()> {
        let observations = ActionObservations::not_attempted(
            &self.descriptor.correlation,
            &self.descriptor.targets,
        );
        CompletedActionBatchResult {
            descriptor: self.descriptor,
            start: StartBoundary::NotStarted,
            completion: CompletionBoundary::Completed,
            outcome: ActionOutcome::NotStarted { reason },
            observations,
        }
    }
}

/// An action which crossed the stable start boundary. Execution owns this value
/// until it can normalize its terminal state.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StartedActionBatch {
    descriptor: ActionDescriptor,
}

impl StartedActionBatch {
    pub(crate) fn finish_execution(
        self,
        outcome: StartedActionOutcome,
    ) -> BatchPostObservationPending {
        let observation_ticket = ObservationCorrelationTicket {
            correlation: self.descriptor.correlation.clone(),
            targets: self.descriptor.targets.clone(),
        };
        BatchPostObservationPending {
            descriptor: self.descriptor,
            outcome: outcome.into(),
            observation_ticket: Some(observation_ticket),
        }
    }
}

/// Execution has ended, but the completed boundary has not yet been emitted.
/// The caller can perform post observation through this state even after partial,
/// failure, timeout, signal, parse-failure, or truncation outcomes.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BatchPostObservationPending {
    descriptor: ActionDescriptor,
    outcome: ActionOutcome,
    observation_ticket: Option<ObservationCorrelationTicket>,
}

impl BatchPostObservationPending {
    pub(crate) fn observation_targets(&self) -> &ActionObservationTargets {
        &self.descriptor.targets
    }

    pub(crate) fn take_observation_ticket(
        &mut self,
    ) -> Result<ObservationCorrelationTicket, ContractError> {
        self.observation_ticket
            .take()
            .ok_or(ContractError::ObservationTicketAlreadyTaken)
    }

    /// Completes with the supplied resolution, or seals every exact target as
    /// unavailable if an internal observation contract check fails. This keeps
    /// reporting defects from discarding an already-produced mutation result.
    pub(crate) fn complete_or_all_unavailable<Unavailable: Clone, Incomparable, Observed>(
        self,
        observations: Result<
            ActionObservations<Unavailable, Incomparable, Observed>,
            ContractError,
        >,
        unavailable: Unavailable,
    ) -> CompletedActionBatchResult<Unavailable, Incomparable, Observed> {
        let observations = match observations {
            Ok(observations)
                if observations.belongs_to(&self.descriptor.correlation)
                    && observations.covers(&self.descriptor.targets)
                    && !observations.any_not_attempted() =>
            {
                observations
            }
            Ok(_) | Err(_) => ActionObservations {
                correlation: self.descriptor.correlation.clone(),
                quota_scopes: self
                    .descriptor
                    .targets
                    .quota_scopes()
                    .iter()
                    .map(|target| ResolvedQuotaObservation {
                        anchors: vec![target.anchor.clone()],
                        state: QuotaObservationState::Unavailable(unavailable.clone()),
                    })
                    .collect(),
            },
        };
        CompletedActionBatchResult {
            descriptor: self.descriptor,
            start: StartBoundary::Started,
            completion: CompletionBoundary::Completed,
            outcome: self.outcome,
            observations,
        }
    }

    /// Crosses the completion boundary only with an observation resolution that
    /// covers the exact targets carried across the start/execution boundaries.
    pub(crate) fn complete<Unavailable, Incomparable, Observed>(
        self,
        observations: ActionObservations<Unavailable, Incomparable, Observed>,
    ) -> Result<CompletedActionBatchResult<Unavailable, Incomparable, Observed>, ContractError>
    {
        if !observations.belongs_to(&self.descriptor.correlation) {
            return Err(ContractError::ObservationBatchMismatch);
        }
        if !observations.covers(&self.descriptor.targets) {
            return Err(ContractError::ObservationTargetMismatch);
        }
        if observations.any_not_attempted() {
            return Err(ContractError::StartedObservationNotResolved);
        }
        Ok(CompletedActionBatchResult {
            descriptor: self.descriptor,
            start: StartBoundary::Started,
            completion: CompletionBoundary::Completed,
            outcome: self.outcome,
            observations,
        })
    }
}

/// Stable internal envelope. It is intentionally not `Serialize` and is not
/// connected to existing command reports, JSON schemas, or exit-code logic.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompletedActionBatchResult<Unavailable, Incomparable, Observed> {
    descriptor: ActionDescriptor,
    start: StartBoundary,
    completion: CompletionBoundary,
    outcome: ActionOutcome,
    observations: ActionObservations<Unavailable, Incomparable, Observed>,
}

impl<Unavailable, Incomparable, Observed>
    CompletedActionBatchResult<Unavailable, Incomparable, Observed>
{
    pub(crate) fn owner(&self) -> &ActionResultOwner {
        &self.descriptor.owner
    }

    pub(crate) fn kind(&self) -> ActionKind {
        self.descriptor.kind
    }

    pub(crate) fn id(&self) -> &ActionId {
        &self.descriptor.id
    }

    pub(crate) fn observation_targets(&self) -> &ActionObservationTargets {
        &self.descriptor.targets
    }

    pub(crate) fn start_boundary(&self) -> StartBoundary {
        self.start
    }

    pub(crate) fn completion_boundary(&self) -> CompletionBoundary {
        self.completion
    }

    pub(crate) fn outcome(&self) -> ActionOutcome {
        self.outcome
    }

    pub(crate) fn observations(&self) -> &ActionObservations<Unavailable, Incomparable, Observed> {
        &self.observations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContractError {
    InvalidActionId,
    EmptyObservationScope,
    DuplicateObservationAnchor,
    ObservationTargetMismatch,
    ObservationBatchMismatch,
    ObservationTicketAlreadyTaken,
    StartedObservationNotResolved,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> ActionId {
        ActionId::new(value).unwrap()
    }

    fn anchor(path: &str) -> ObservationRequestPath {
        ObservationRequestPath::new(PathBuf::from(path))
    }

    fn planned(targets: ActionObservationTargets) -> PlannedActionBatch {
        PlannedActionBatch::new(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            id("clean:direct-purge:1"),
            targets,
        )
    }

    #[test]
    fn ids_are_stable_machine_tokens() {
        assert_eq!(id("adapter.native_1:run").as_str(), "adapter.native_1:run");
        for invalid in ["", "contains space", "line\nbreak", "slash/value"] {
            assert_eq!(ActionId::new(invalid), Err(ContractError::InvalidActionId));
        }
    }

    #[test]
    fn observation_request_preserves_alias_components_without_validation() {
        for request in ["relative", "../escape", "/home/./cache", "/alias/../real"] {
            assert_eq!(anchor(request).as_path(), Path::new(request));
        }
    }

    #[test]
    fn quota_targets_deduplicate_exact_anchors_without_collapsing_scopes() {
        let targets = ActionObservationTargets::new([
            QuotaObservationTarget::new(anchor("/home")),
            QuotaObservationTarget::new(anchor("/scratch")),
            QuotaObservationTarget::new(anchor("/home")),
        ]);
        let paths = targets
            .quota_scopes()
            .iter()
            .map(|target| target.anchor().as_path())
            .collect::<Vec<_>>();
        assert_eq!(paths, [Path::new("/home"), Path::new("/scratch")]);
    }

    #[test]
    fn planned_state_exposes_only_borrowed_pre_probe_targets() {
        fn pre_probe_seam(batch: &PlannedActionBatch) -> &ActionObservationTargets {
            batch.observation_targets()
        }

        let action = planned(ActionObservationTargets::new([
            QuotaObservationTarget::new(anchor("/home")),
        ]));
        assert_eq!(pre_probe_seam(&action).quota_scopes().len(), 1);

        // There is deliberately no ticket API on `PlannedActionBatch` or
        // `StartedActionBatch`. The first ticket-producing method exists only
        // after consuming both `start` and `finish_execution`.
        let mut pending = action
            .start()
            .finish_execution(StartedActionOutcome::Success);
        assert!(pending.take_observation_ticket().is_ok());
    }

    #[test]
    fn not_started_actions_internally_seal_not_attempted_observations() {
        for reason in [
            NotStartedReason::DryRun,
            NotStartedReason::Cancelled,
            NotStartedReason::Empty,
            NotStartedReason::PrerequisiteFailed,
        ] {
            let action = planned(ActionObservationTargets::new([
                QuotaObservationTarget::new(anchor("/home")),
            ]));
            let result = action.complete_not_started(reason);
            assert_eq!(result.start_boundary(), StartBoundary::NotStarted);
            assert_eq!(result.completion_boundary(), CompletionBoundary::Completed);
            assert_eq!(result.outcome(), ActionOutcome::NotStarted { reason });
            assert!(matches!(
                result.observations().quota_scopes()[0].state(),
                QuotaObservationState::NotAttempted
            ));
        }
    }

    #[test]
    fn owner_kind_id_and_targets_survive_both_boundaries() {
        let targets = ActionObservationTargets::new([QuotaObservationTarget::new(anchor("/home"))]);
        let action = PlannedActionBatch::new(
            ActionResultOwner::NativeAdapter {
                adapter_id: id("uv"),
            },
            ActionKind::Native,
            id("uv:cache-prune:42"),
            targets,
        );
        assert_eq!(action.observation_targets().quota_scopes().len(), 1);
        let mut pending = action
            .start()
            .finish_execution(StartedActionOutcome::Success);
        assert_eq!(pending.observation_targets().quota_scopes().len(), 1);
        let ticket = pending.take_observation_ticket().unwrap();
        let observations = ActionObservations::resolve(
            ticket,
            [ResolvedQuotaObservation::new(
                [anchor("/home")],
                QuotaObservationState::<&str, &str, i128>::Observed(-5),
            )
            .unwrap()],
        )
        .unwrap();
        let result = pending.complete(observations).unwrap();
        assert_eq!(
            result.owner(),
            &ActionResultOwner::NativeAdapter {
                adapter_id: id("uv")
            }
        );
        assert_eq!(result.kind(), ActionKind::Native);
        assert_eq!(result.id().as_str(), "uv:cache-prune:42");
        assert_eq!(result.start_boundary(), StartBoundary::Started);
        assert_eq!(result.completion_boundary(), CompletionBoundary::Completed);
        assert_eq!(result.observation_targets().quota_scopes().len(), 1);
        assert!(matches!(
            result.observations().quota_scopes()[0].state(),
            QuotaObservationState::Observed(-5)
        ));
    }

    #[test]
    fn every_started_terminal_state_keeps_post_observation_open_until_completion() {
        let outcomes = [
            StartedActionOutcome::Success,
            StartedActionOutcome::Partial,
            StartedActionOutcome::Failure,
            StartedActionOutcome::Timeout,
            StartedActionOutcome::Signal { signal: Some(9) },
            StartedActionOutcome::Signal { signal: None },
            StartedActionOutcome::OutputParseFailure,
            StartedActionOutcome::OutputTruncated,
        ];
        for outcome in outcomes {
            let targets = ActionObservationTargets::new([QuotaObservationTarget::new(anchor(
                "/quota-anchor",
            ))]);
            let mut pending = planned(targets).start().finish_execution(outcome);
            assert_eq!(pending.observation_targets().quota_scopes().len(), 1);
            let ticket = pending.take_observation_ticket().unwrap();
            let observations = ActionObservations::resolve(
                ticket,
                [ResolvedQuotaObservation::new(
                    [anchor("/quota-anchor")],
                    QuotaObservationState::<&str, &str, u64>::Observed(1),
                )
                .unwrap()],
            )
            .unwrap();
            let result = pending.complete(observations).unwrap();
            assert_eq!(result.start_boundary(), StartBoundary::Started);
            assert_eq!(result.completion_boundary(), CompletionBoundary::Completed);
            assert_eq!(result.outcome(), ActionOutcome::from(outcome));
        }
    }

    #[test]
    fn observation_resolution_supports_mixed_scope_states_and_anchor_folding() {
        let targets = ActionObservationTargets::new([
            QuotaObservationTarget::new(anchor("/a")),
            QuotaObservationTarget::new(anchor("/b")),
            QuotaObservationTarget::new(anchor("/c")),
            QuotaObservationTarget::new(anchor("/d")),
            QuotaObservationTarget::new(anchor("/e")),
        ]);
        let action = planned(targets);
        assert_eq!(action.observation_targets().quota_scopes().len(), 5);
        let mut pending = action
            .start()
            .finish_execution(StartedActionOutcome::Success);
        let ticket = pending.take_observation_ticket().unwrap();
        let observations = ActionObservations::resolve(
            ticket,
            [
                ResolvedQuotaObservation::new(
                    [anchor("/a")],
                    QuotaObservationState::Unavailable("before probe failed"),
                )
                .unwrap(),
                ResolvedQuotaObservation::new(
                    [anchor("/b")],
                    QuotaObservationState::Unavailable("after probe failed"),
                )
                .unwrap(),
                ResolvedQuotaObservation::new(
                    [anchor("/c")],
                    QuotaObservationState::Incomparable("provider changed"),
                )
                .unwrap(),
                ResolvedQuotaObservation::new(
                    [anchor("/d"), anchor("/e")],
                    QuotaObservationState::Observed(-12_i128),
                )
                .unwrap(),
            ],
        )
        .unwrap();

        let result = pending.complete(observations).unwrap();
        assert_eq!(result.observations().quota_scopes().len(), 4);
        assert_eq!(result.observations().quota_scopes()[3].anchors().len(), 2);
        assert!(matches!(
            result.observations().quota_scopes()[1].state(),
            QuotaObservationState::Unavailable("after probe failed")
        ));
    }

    #[test]
    fn identical_anchors_from_a_different_action_id_are_rejected() {
        let targets = ActionObservationTargets::new([QuotaObservationTarget::new(anchor("/home"))]);
        let mut source = PlannedActionBatch::new(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            id("batch:source"),
            targets.clone(),
        )
        .start()
        .finish_execution(StartedActionOutcome::Success);
        let observations = ActionObservations::resolve(
            source.take_observation_ticket().unwrap(),
            [ResolvedQuotaObservation::new(
                [anchor("/home")],
                QuotaObservationState::<(), (), u64>::Observed(1),
            )
            .unwrap()],
        )
        .unwrap();
        let pending = PlannedActionBatch::new(
            ActionResultOwner::CleanCommand,
            ActionKind::DirectPurge,
            id("batch:destination"),
            targets,
        )
        .start()
        .finish_execution(StartedActionOutcome::Success);

        assert_eq!(
            pending.complete(observations),
            Err(ContractError::ObservationBatchMismatch)
        );
    }

    #[test]
    fn identical_descriptors_still_have_distinct_one_shot_tickets() {
        let targets = ActionObservationTargets::new([QuotaObservationTarget::new(anchor("/home"))]);
        let mut first = planned(targets.clone())
            .start()
            .finish_execution(StartedActionOutcome::Success);
        let first_ticket = first.take_observation_ticket().unwrap();
        assert_eq!(
            first.take_observation_ticket(),
            Err(ContractError::ObservationTicketAlreadyTaken)
        );
        let observations = ActionObservations::resolve(
            first_ticket,
            [ResolvedQuotaObservation::new(
                [anchor("/home")],
                QuotaObservationState::<(), (), u64>::Observed(1),
            )
            .unwrap()],
        )
        .unwrap();
        let second = planned(targets)
            .start()
            .finish_execution(StartedActionOutcome::Success);

        assert_eq!(
            second.complete(observations),
            Err(ContractError::ObservationBatchMismatch)
        );
        // `PlannedActionBatch` is intentionally not `Clone`; consuming `start`
        // is the only transition and therefore cannot be repeated.
    }

    #[test]
    fn started_boundary_rejects_an_unresolved_observation_state() {
        let targets = ActionObservationTargets::new([QuotaObservationTarget::new(anchor("/a"))]);
        let started = planned(targets)
            .start()
            .finish_execution(StartedActionOutcome::Failure);
        let not_attempted = ActionObservations::not_attempted(
            &started.descriptor.correlation,
            &started.descriptor.targets,
        );
        assert_eq!(
            started.complete(not_attempted),
            Err(ContractError::StartedObservationNotResolved)
        );
    }

    #[test]
    fn observation_resolution_rejects_missing_unexpected_and_duplicate_anchors() {
        let targets = ActionObservationTargets::new([
            QuotaObservationTarget::new(anchor("/a")),
            QuotaObservationTarget::new(anchor("/b")),
        ]);
        let mut missing_batch = planned(targets.clone())
            .start()
            .finish_execution(StartedActionOutcome::Success);
        let missing = ActionObservations::<(), (), ()>::resolve(
            missing_batch.take_observation_ticket().unwrap(),
            [
                ResolvedQuotaObservation::new([anchor("/a")], QuotaObservationState::NotAttempted)
                    .unwrap(),
            ],
        );
        assert_eq!(missing, Err(ContractError::ObservationTargetMismatch));

        let mut unexpected_batch = planned(targets)
            .start()
            .finish_execution(StartedActionOutcome::Success);
        let unexpected = ActionObservations::<(), (), ()>::resolve(
            unexpected_batch.take_observation_ticket().unwrap(),
            [
                ResolvedQuotaObservation::new([anchor("/a")], QuotaObservationState::NotAttempted)
                    .unwrap(),
                ResolvedQuotaObservation::new(
                    [anchor("/unexpected")],
                    QuotaObservationState::NotAttempted,
                )
                .unwrap(),
            ],
        );
        assert_eq!(unexpected, Err(ContractError::ObservationTargetMismatch));

        assert_eq!(
            ResolvedQuotaObservation::<(), (), ()>::new(
                [anchor("/a"), anchor("/a")],
                QuotaObservationState::NotAttempted,
            ),
            Err(ContractError::DuplicateObservationAnchor)
        );
    }

    #[test]
    fn current_direct_batch_owners_and_kinds_are_distinct() {
        let cases = [
            (ActionResultOwner::CleanCommand, ActionKind::DirectPurge),
            (ActionResultOwner::CleanCommand, ActionKind::ExpiryPurge),
            (ActionResultOwner::TrashPurgeCommand, ActionKind::TrashPurge),
        ];
        for (owner, kind) in cases {
            let action = PlannedActionBatch::new(
                owner.clone(),
                kind,
                id("batch:1"),
                ActionObservationTargets::default(),
            );
            let mut pending = action
                .start()
                .finish_execution(StartedActionOutcome::Success);
            let ticket = pending.take_observation_ticket().unwrap();
            let observations = ActionObservations::<(), (), ()>::resolve(ticket, []).unwrap();
            let result = pending.complete(observations).unwrap();
            assert_eq!(result.owner(), &owner);
            assert_eq!(result.kind(), kind);
        }
    }
}
