//! Phase-0 vocabulary for proving mutation authority.
//!
//! Nothing in this module is wired into the current planner or executor. The
//! types keep content policy, writer risk, OS capability, evidence freshness,
//! identity, and transaction state separate before later work expands cleanup.

pub mod local_mode;

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

pub const CLEANUP_ASSESSMENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Principal {
    PosixUid(u32),
    PosixGid(u32),
    Nfs4(String),
    Everyone,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct NamespaceRights {
    pub create_file: bool,
    pub create_dir: bool,
    pub delete_child: bool,
    pub replace_child: bool,
    pub traverse: bool,
}

impl NamespaceRights {
    pub fn is_subset_of(self, confirmed: Self) -> bool {
        (!self.create_file || confirmed.create_file)
            && (!self.create_dir || confirmed.create_dir)
            && (!self.delete_child || confirmed.delete_child)
            && (!self.replace_child || confirmed.replace_child)
            && (!self.traverse || confirmed.traverse)
    }

    fn union(self, other: Self) -> Self {
        Self {
            create_file: self.create_file || other.create_file,
            create_dir: self.create_dir || other.create_dir,
            delete_child: self.delete_child || other.delete_child,
            replace_child: self.replace_child || other.replace_child,
            traverse: self.traverse || other.traverse,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AuthorityControlRights {
    pub change_mode: bool,
    pub change_acl: bool,
    pub replace_binding: bool,
}

impl AuthorityControlRights {
    pub fn is_subset_of(self, confirmed: Self) -> bool {
        (!self.change_mode || confirmed.change_mode)
            && (!self.change_acl || confirmed.change_acl)
            && (!self.replace_binding || confirmed.replace_binding)
    }

    fn union(self, other: Self) -> Self {
        Self {
            change_mode: self.change_mode || other.change_mode,
            change_acl: self.change_acl || other.change_acl,
            replace_binding: self.replace_binding || other.replace_binding,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityBackend {
    PosixMode,
    LinuxPosixAcl,
    MacOsAcl,
    Nfs4Acl,
    Unknown,
}

impl AuthorityBackend {
    pub fn is_known(self) -> bool {
        self != Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCertainty {
    Verified,
    Inferred,
    Unknown,
}

impl EvidenceCertainty {
    fn is_no_weaker_than(self, confirmed: Self) -> bool {
        matches!(
            (self, confirmed),
            (Self::Verified, Self::Verified | Self::Inferred) | (Self::Inferred, Self::Inferred)
        )
    }

    fn least(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Inferred, _) | (_, Self::Inferred) => Self::Inferred,
            (Self::Verified, Self::Verified) => Self::Verified,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Fresh,
    Stale,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MutationUnitId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MountId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFileType {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StableObjectId {
    pub mount_id: MountId,
    pub device: u64,
    pub inode: u64,
    pub file_type: ObjectFileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatSnapshot {
    pub stable_id: StableObjectId,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

/// The held descriptor is this type's authority-bearing component. Its stable
/// identity is only replacement evidence while that descriptor remains live.
#[derive(Debug)]
pub struct LiveObjectRef {
    fd: OwnedFd,
    stat: StatSnapshot,
}

impl LiveObjectRef {
    pub fn new(fd: OwnedFd, stat: StatSnapshot) -> Self {
        Self { fd, stat }
    }

    pub fn stat(&self) -> StatSnapshot {
        self.stat
    }
}

impl AsFd for LiveObjectRef {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Durable recovery evidence, never an execution-authority token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersistentRecoveryEvidence {
    relative_path: PathBuf,
    filesystem_id: Option<String>,
    device: u64,
    inode: u64,
    generation_or_btime: Option<u64>,
    expected_mode: u32,
}

impl PersistentRecoveryEvidence {
    pub fn new(
        relative_path: PathBuf,
        filesystem_id: Option<String>,
        device: u64,
        inode: u64,
        generation_or_btime: Option<u64>,
        expected_mode: u32,
    ) -> Option<Self> {
        is_confined_relative_path(&relative_path).then_some(Self {
            relative_path,
            filesystem_id,
            device,
            inode,
            generation_or_btime,
            expected_mode,
        })
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn filesystem_id(&self) -> Option<&str> {
        self.filesystem_id.as_deref()
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn generation_or_btime(&self) -> Option<u64> {
        self.generation_or_btime
    }

    pub fn expected_mode(&self) -> u32 {
        self.expected_mode
    }
}

fn is_confined_relative_path(path: &Path) -> bool {
    let mut components = path.components();
    let Some(Component::Normal(_)) = components.next() else {
        return false;
    };
    components.all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "object", rename_all = "snake_case")]
pub enum AuthorityScope {
    RootBinding,
    WholeMutationUnit,
    Directory(StableObjectId),
}

impl AuthorityScope {
    pub fn is_within(&self, confirmed: &Self) -> bool {
        match (self, confirmed) {
            (Self::RootBinding, Self::RootBinding)
            | (Self::WholeMutationUnit, Self::WholeMutationUnit) => true,
            (Self::Directory(_), Self::WholeMutationUnit) => true,
            (Self::Directory(actual), Self::Directory(expected)) => actual == expected,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExposureKey {
    pub mutation_unit_id: MutationUnitId,
    pub scope: AuthorityScope,
    pub principal: Principal,
    pub backend: AuthorityBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExposureValue {
    pub rights: NamespaceRights,
    pub control_rights: AuthorityControlRights,
    pub certainty: EvidenceCertainty,
}

impl ExposureValue {
    fn is_no_wider_than(self, confirmed: Self) -> bool {
        self.rights.is_subset_of(confirmed.rights)
            && self.control_rights.is_subset_of(confirmed.control_rights)
            && self.certainty.is_no_weaker_than(confirmed.certainty)
    }

    fn union(self, other: Self) -> Self {
        Self {
            rights: self.rights.union(other.rights),
            control_rights: self.control_rights.union(other.control_rights),
            certainty: self.certainty.least(other.certainty),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriterExposureSet {
    entries: BTreeMap<ExposureKey, ExposureValue>,
}

impl WriterExposureSet {
    pub fn insert(&mut self, key: ExposureKey, value: ExposureValue) {
        self.entries
            .entry(key)
            .and_modify(|existing| *existing = existing.union(value))
            .or_insert(value);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ExposureKey, &ExposureValue)> {
        self.entries.iter()
    }

    /// Every stage-time exposure must fit within a confirmed exposure with the
    /// same unit, principal, and known backend. New rights, controller rights,
    /// scope, backend, unknown principal, or weaker certainty fail closed.
    pub fn is_no_wider_than(&self, confirmed: &Self) -> bool {
        self.entries.iter().all(|(actual_key, actual_value)| {
            actual_key.principal != Principal::Unknown
                && actual_key.backend.is_known()
                && confirmed
                    .entries
                    .iter()
                    .any(|(confirmed_key, confirmed_value)| {
                        confirmed_key.principal != Principal::Unknown
                            && confirmed_key.backend.is_known()
                            && actual_key.mutation_unit_id == confirmed_key.mutation_unit_id
                            && actual_key.principal == confirmed_key.principal
                            && actual_key.backend == confirmed_key.backend
                            && actual_key.scope.is_within(&confirmed_key.scope)
                            && actual_value.is_no_wider_than(*confirmed_value)
                    })
        })
    }
}

impl Serialize for WriterExposureSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Entry<'a> {
            key: &'a ExposureKey,
            value: &'a ExposureValue,
        }

        let mut sequence = serializer.serialize_seq(Some(self.entries.len()))?;
        for (key, value) in &self.entries {
            sequence.serialize_element(&Entry { key, value })?;
        }
        sequence.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriterExposure {
    pub principal: Principal,
    pub rights: NamespaceRights,
    pub source: AuthorityBackend,
    pub inherited: bool,
    pub certainty: EvidenceCertainty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityControllerExposure {
    pub principal: Principal,
    pub rights: AuthorityControlRights,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanBoundAcceptance {
    plan_id: String,
    principals: BTreeSet<Principal>,
}

impl PlanBoundAcceptance {
    pub fn new(plan_id: impl Into<String>, principals: BTreeSet<Principal>) -> Option<Self> {
        let plan_id = plan_id.into();
        (!plan_id.is_empty() && !principals.is_empty() && !principals.contains(&Principal::Unknown))
            .then_some(Self {
                plan_id,
                principals,
            })
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn principals(&self) -> &BTreeSet<Principal> {
        &self.principals
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReason {
    ForeignContent,
    ProtectedContent,
    UnacceptedWriter,
    UnknownEvidence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum CleanupDisposition {
    Eligible,
    ReviewRequired,
    #[default]
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum WriterRiskDecision {
    NoAdditionalWriter,
    AcceptanceRequired(BTreeSet<Principal>),
    Accepted(PlanBoundAcceptance),
    Forbidden(PolicyReason),
}

impl Default for WriterRiskDecision {
    fn default() -> Self {
        Self::Forbidden(PolicyReason::UnknownEvidence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityEvidence {
    backend: AuthorityBackend,
}

impl CapabilityEvidence {
    fn new(backend: AuthorityBackend) -> Option<Self> {
        backend.is_known().then_some(Self { backend })
    }

    pub fn backend(self) -> AuthorityBackend {
        self.backend
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilityAcquisition {
    OwnerModeTransform { original: u32, required: u32 },
    BackendSpecific { backend: AuthorityBackend },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    PermissionDenied,
    NotOwner,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    UncertifiedBackend,
    ProbeFailed,
    ServerDecides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum CapabilityAssessment {
    Present(CapabilityEvidence),
    Acquirable(CapabilityAcquisition),
    Missing(CapabilityReason),
    Unknown(UnknownReason),
}

impl Default for CapabilityAssessment {
    fn default() -> Self {
        Self::Unknown(UnknownReason::ProbeFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "strategy", content = "acceptance", rename_all = "snake_case")]
pub enum RootBindingStrategy {
    AlreadyExclusive,
    SealOwnedParent,
    StickyConfinement,
    AcceptedWriters(PlanBoundAcceptance),
}

#[derive(Debug)]
pub struct RootBindingGuard {
    pub parent: LiveObjectRef,
    pub strategy: RootBindingStrategy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentStabilityRequirement {
    PathAndOwnershipOnly,
    ImmutableAfterClassification,
    #[default]
    NativeCoordinationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Prepared,
    ParentSealIntent,
    ParentSealed,
    TreeSealIntent,
    TreeSealed,
    RenameIntent,
    StagedUnverified,
    StagedSealed,
    VerifiedCommitted,
    Purgeable,
    Purged,
    RollbackIntent,
    RolledBack,
    RestoreIntent,
    Restored,
    Quarantined,
    RecoveryRequired,
}

impl TransactionState {
    pub fn writer_acceptance_expired(self) -> bool {
        matches!(
            self,
            Self::VerifiedCommitted | Self::Purgeable | Self::Purged
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeAuthority(());

impl TryFrom<TransactionState> for PurgeAuthority {
    type Error = TransactionState;

    fn try_from(state: TransactionState) -> Result<Self, Self::Error> {
        if state == TransactionState::Purgeable {
            Ok(Self(()))
        } else {
            Err(state)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum MutationUnitAuthority {
    Authorized,
    Denied(PolicyReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MutationUnitAssessment {
    pub id: MutationUnitId,
    pub authority: MutationUnitAuthority,
}

/// Versioned future payload; current CLI and JSON documents do not include it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanupAssessmentV1 {
    pub schema_version: u16,
    pub disposition: CleanupDisposition,
    pub writer_exposure: WriterExposureSet,
    pub writer_risk: WriterRiskDecision,
    pub capability: CapabilityAssessment,
    pub freshness: EvidenceFreshness,
    pub root_binding: Option<RootBindingStrategy>,
    pub content_stability: ContentStabilityRequirement,
    pub mutation_units: Vec<MutationUnitAssessment>,
}

impl Default for CleanupAssessmentV1 {
    fn default() -> Self {
        Self {
            schema_version: CLEANUP_ASSESSMENT_SCHEMA_VERSION,
            disposition: CleanupDisposition::ReportOnly,
            writer_exposure: WriterExposureSet::default(),
            writer_risk: WriterRiskDecision::default(),
            capability: CapabilityAssessment::default(),
            freshness: EvidenceFreshness::default(),
            root_binding: None,
            content_stability: ContentStabilityRequirement::default(),
            mutation_units: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rights(create: bool, delete: bool) -> NamespaceRights {
        NamespaceRights {
            create_file: create,
            delete_child: delete,
            traverse: true,
            ..NamespaceRights::default()
        }
    }

    fn stable(inode: u64) -> StableObjectId {
        StableObjectId {
            mount_id: MountId(1),
            device: 2,
            inode,
            file_type: ObjectFileType::Directory,
        }
    }

    fn key(scope: AuthorityScope, principal: Principal, backend: AuthorityBackend) -> ExposureKey {
        ExposureKey {
            mutation_unit_id: MutationUnitId(7),
            scope,
            principal,
            backend,
        }
    }

    fn value(rights: NamespaceRights, certainty: EvidenceCertainty) -> ExposureValue {
        ExposureValue {
            rights,
            control_rights: AuthorityControlRights::default(),
            certainty,
        }
    }

    #[test]
    fn rights_and_scope_must_not_widen() {
        let confirmed_rights = rights(true, false);
        assert!(rights(false, false).is_subset_of(confirmed_rights));
        assert!(!rights(false, true).is_subset_of(confirmed_rights));

        let whole = AuthorityScope::WholeMutationUnit;
        let directory = AuthorityScope::Directory(stable(9));
        assert!(directory.is_within(&whole));
        assert!(!whole.is_within(&directory));
    }

    #[test]
    fn exposure_comparison_fails_closed_on_every_authority_axis() {
        let gid = Principal::PosixGid(42);
        let mut confirmed = WriterExposureSet::default();
        confirmed.insert(
            key(
                AuthorityScope::WholeMutationUnit,
                gid.clone(),
                AuthorityBackend::PosixMode,
            ),
            value(rights(true, true), EvidenceCertainty::Verified),
        );

        let mut narrower = WriterExposureSet::default();
        narrower.insert(
            key(
                AuthorityScope::Directory(stable(9)),
                gid.clone(),
                AuthorityBackend::PosixMode,
            ),
            value(rights(false, true), EvidenceCertainty::Verified),
        );
        assert!(narrower.is_no_wider_than(&confirmed));

        let cases = [
            key(
                AuthorityScope::WholeMutationUnit,
                Principal::PosixGid(99),
                AuthorityBackend::PosixMode,
            ),
            key(
                AuthorityScope::WholeMutationUnit,
                gid.clone(),
                AuthorityBackend::LinuxPosixAcl,
            ),
            key(
                AuthorityScope::WholeMutationUnit,
                Principal::Unknown,
                AuthorityBackend::PosixMode,
            ),
            key(
                AuthorityScope::WholeMutationUnit,
                gid,
                AuthorityBackend::Unknown,
            ),
        ];
        for actual_key in cases {
            let mut actual = WriterExposureSet::default();
            actual.insert(
                actual_key,
                value(rights(true, true), EvidenceCertainty::Verified),
            );
            assert!(!actual.is_no_wider_than(&confirmed));
        }

        let mut weaker_certainty = WriterExposureSet::default();
        weaker_certainty.insert(
            key(
                AuthorityScope::WholeMutationUnit,
                Principal::PosixGid(42),
                AuthorityBackend::PosixMode,
            ),
            value(rights(true, true), EvidenceCertainty::Inferred),
        );
        assert!(!weaker_certainty.is_no_wider_than(&confirmed));
    }

    #[test]
    fn recovery_evidence_accepts_only_confined_relative_paths() {
        let evidence = |path: &str| {
            PersistentRecoveryEvidence::new(PathBuf::from(path), None, 1, 2, None, 0o700)
        };
        assert_eq!(
            evidence("root/child").unwrap().relative_path(),
            Path::new("root/child")
        );
        assert!(evidence("").is_none());
        assert!(evidence(".").is_none());
        assert!(evidence("../root").is_none());
        assert!(evidence("/root").is_none());
    }

    #[test]
    fn purge_and_writer_acceptance_follow_committed_state() {
        for state in [
            TransactionState::Prepared,
            TransactionState::TreeSealed,
            TransactionState::StagedSealed,
            TransactionState::VerifiedCommitted,
            TransactionState::Purged,
            TransactionState::RecoveryRequired,
        ] {
            assert_eq!(PurgeAuthority::try_from(state), Err(state));
        }
        assert!(PurgeAuthority::try_from(TransactionState::Purgeable).is_ok());
        assert!(TransactionState::VerifiedCommitted.writer_acceptance_expired());
        assert!(!TransactionState::StagedSealed.writer_acceptance_expired());
    }

    #[test]
    fn plan_acceptance_rejects_unknown_or_unbound_principals() {
        assert!(PlanBoundAcceptance::new("", BTreeSet::from([Principal::PosixUid(1)])).is_none());
        assert!(PlanBoundAcceptance::new("plan", BTreeSet::new()).is_none());
        assert!(PlanBoundAcceptance::new("plan", BTreeSet::from([Principal::Unknown])).is_none());
        let acceptance =
            PlanBoundAcceptance::new("plan", BTreeSet::from([Principal::PosixUid(1)])).unwrap();
        assert_eq!(acceptance.plan_id(), "plan");
    }

    #[test]
    fn assessment_schema_is_fail_closed_and_json_representable() {
        let assessment = CleanupAssessmentV1::default();
        let json = serde_json::to_value(assessment).unwrap();
        assert_eq!(json["schema_version"], CLEANUP_ASSESSMENT_SCHEMA_VERSION);
        assert_eq!(json["disposition"]["state"], "report_only");
        assert_eq!(json["writer_risk"]["state"], "forbidden");
        assert!(json["writer_exposure"].is_array());
        assert!(json["mutation_units"].is_array());
    }
}
