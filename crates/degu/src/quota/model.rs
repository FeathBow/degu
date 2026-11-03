use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub(crate) struct QuotaSnapshot {
    pub(crate) scope: QuotaScope,
    pub(crate) subject: QuotaSubject,
    pub(crate) provider: &'static str,
    pub(crate) data_source: &'static str,
    pub(crate) state: &'static str,
    pub(crate) space: QuotaDimension,
    pub(crate) inodes: QuotaDimension,
    /// The group and project this path also answers to. `subject` stays the
    /// user, whose usage is what a clean observes changing.
    pub(crate) other_subjects: Vec<SubjectQuota>,
    /// The limit a reader should look at first: one already reached if any is,
    /// otherwise the one with the highest use. See [`LeadingLimit`].
    pub(crate) leading_limit: Option<LeadingLimit>,
    /// False when a subject could not be read, so `leading_limit` may not be
    /// the one that matters, and its absence does not mean there is no limit.
    pub(crate) limits_complete: bool,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaSnapshot {
    pub(crate) fn active(scope: QuotaScope, subject_id: u32, quota: ActiveQuota) -> Self {
        let mut snapshot = Self {
            scope,
            subject: QuotaSubject::user(subject_id),
            provider: quota.provider,
            data_source: quota.data_source,
            state: "active",
            space: quota.space,
            inodes: quota.inodes,
            other_subjects: Vec::new(),
            leading_limit: None,
            limits_complete: true,
        };
        snapshot.settle_limits();
        snapshot
    }

    pub(crate) fn with_subjects(mut self, others: Vec<SubjectQuota>) -> Self {
        self.other_subjects = others;
        self.settle_limits();
        self
    }

    fn settle_limits(&mut self) {
        self.limits_complete = self
            .other_subjects
            .iter()
            .all(|subject| subject.state == SUBJECT_ACTIVE);
        let mut leading = None;
        offer_dimensions(
            &mut leading,
            self.subject.kind,
            Some(self.subject.id),
            &self.space,
            &self.inodes,
        );
        for other in &self.other_subjects {
            if let (Some(space), Some(inodes)) = (&other.space, &other.inodes) {
                offer_dimensions(&mut leading, other.kind, other.id, space, inodes);
            }
        }
        self.leading_limit = leading;
    }
}

#[cfg(any(target_os = "linux", test))]
fn offer_dimensions(
    leading: &mut Option<LeadingLimit>,
    kind: &'static str,
    id: Option<u32>,
    space: &QuotaDimension,
    inodes: &QuotaDimension,
) {
    for (dimension, values) in [("space", space), ("inodes", inodes)] {
        // Soft first: an equal hard limit then replaces it, because that is the
        // one that actually refuses a write.
        for (limit_kind, limit) in [("soft", values.soft_limit), ("hard", values.hard_limit)] {
            let Some(limit) = limit else {
                continue;
            };
            let candidate = LeadingLimit {
                subject_kind: kind,
                subject_id: id,
                dimension,
                limit_kind,
                used: values.used,
                limit,
                headroom: limit.saturating_sub(values.used),
                at_limit: limit_reached(limit_kind, values.used, limit, values.grace.as_ref()),
            };
            if leading
                .as_ref()
                .is_none_or(|held| candidate.displaces(held))
            {
                *leading = Some(candidate);
            }
        }
    }
}

/// Usage has reached a hard limit, or passed a soft limit whose grace has expired.
/// This reads the numbers and nothing else. No provider asks whether the limit is
/// enforced, and ext4 can account without enforcing, so a write can still succeed.
/// A provider that reports no grace for an exceeded soft limit has not said it ran
/// out, so that does not count.
#[cfg(any(target_os = "linux", test))]
fn limit_reached(kind: &str, used: u64, limit: u64, grace: Option<&QuotaGrace>) -> bool {
    if kind == "hard" {
        return used >= limit;
    }
    used > limit && grace.is_some_and(|grace| grace.state == QuotaGraceState::Expired)
}

/// The limit a report leads with. One at its limit outranks any that is not.
/// Otherwise this is the highest use, which is a hint and not a prediction of what
/// fills first. Bytes and inodes share no unit, so limits compare by the fraction
/// used, and that fraction says nothing about room: 990 of 1000 GiB outranks 9 of
/// 10 GiB, though the second has less left, and what runs out first depends on what
/// is written next.
#[derive(Debug, Serialize)]
pub(crate) struct LeadingLimit {
    pub(crate) subject_kind: &'static str,
    pub(crate) subject_id: Option<u32>,
    pub(crate) dimension: &'static str,
    pub(crate) limit_kind: &'static str,
    pub(crate) used: u64,
    pub(crate) limit: u64,
    pub(crate) headroom: u64,
    pub(crate) at_limit: bool,
}

#[cfg(any(target_os = "linux", test))]
impl LeadingLimit {
    fn displaces(&self, held: &Self) -> bool {
        if self.at_limit != held.at_limit {
            return self.at_limit;
        }
        let same_quantity = self.subject_kind == held.subject_kind
            && self.subject_id == held.subject_id
            && self.dimension == held.dimension;
        // Past both limits of one quantity, the hard limit is the one to name,
        // even though the soft limit has the larger fraction.
        if same_quantity && self.at_limit && self.limit_kind == "hard" {
            return true;
        }
        let mine = u128::from(self.used) * u128::from(held.limit);
        let theirs = u128::from(held.used) * u128::from(self.limit);
        mine > theirs
            || (mine == theirs
                && self.limit_kind == "hard"
                && held.limit_kind == "soft"
                && same_quantity)
    }
}

#[cfg(any(target_os = "linux", test))]
const SUBJECT_ACTIVE: &str = "active";

/// A group or project read alongside the user, or the reason it could not be.
/// Every key is always present, so a reader never has to infer a missing one.
#[derive(Debug, Serialize)]
pub(crate) struct SubjectQuota {
    pub(crate) kind: &'static str,
    /// `None` only when reading the subject's own id is what failed.
    pub(crate) id: Option<u32>,
    pub(crate) state: &'static str,
    pub(crate) reason: Option<String>,
    pub(crate) space: Option<QuotaDimension>,
    pub(crate) inodes: Option<QuotaDimension>,
}

#[cfg(any(target_os = "linux", test))]
impl SubjectQuota {
    pub(crate) fn active(
        kind: &'static str,
        id: u32,
        space: QuotaDimension,
        inodes: QuotaDimension,
    ) -> Self {
        Self {
            kind,
            id: Some(id),
            state: SUBJECT_ACTIVE,
            reason: None,
            space: Some(space),
            inodes: Some(inodes),
        }
    }

    pub(crate) fn unavailable(kind: &'static str, id: Option<u32>, reason: String) -> Self {
        Self {
            kind,
            id,
            state: "unavailable",
            reason: Some(reason),
            space: None,
            inodes: None,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) struct ActiveQuota {
    pub(crate) provider: &'static str,
    pub(crate) data_source: &'static str,
    pub(crate) space: QuotaDimension,
    pub(crate) inodes: QuotaDimension,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct QuotaScopeIdentity {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
    source: PathBuf,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaScopeIdentity {
    pub(crate) fn new(
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
        source: PathBuf,
    ) -> Self {
        Self {
            mount_id,
            device_major,
            device_minor,
            source,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct QuotaScope {
    pub(crate) path: PathBuf,
    pub(crate) mount_point: PathBuf,
    pub(crate) filesystem: String,
    /// Provider-private identity used to reject comparisons across mount
    /// replacement. It is evidence for observation only, not public quota data.
    #[serde(skip)]
    pub(crate) identity: QuotaScopeIdentity,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaScope {
    pub(crate) fn new(
        path: PathBuf,
        mount_point: PathBuf,
        filesystem: String,
        identity: QuotaScopeIdentity,
    ) -> Self {
        Self {
            path,
            mount_point,
            filesystem,
            identity,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct QuotaSubject {
    pub(crate) kind: &'static str,
    pub(crate) id: u32,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaSubject {
    fn user(id: u32) -> Self {
        Self { kind: "user", id }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct QuotaDimension {
    pub(crate) used: u64,
    pub(crate) soft_limit: Option<u64>,
    pub(crate) hard_limit: Option<u64>,
    pub(crate) headroom_to_soft_limit: Option<u64>,
    pub(crate) headroom_to_hard_limit: Option<u64>,
    pub(crate) grace: Option<QuotaGrace>,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaDimension {
    pub(crate) fn new(used: u64, limits: QuotaLimits, grace: Option<QuotaGrace>) -> Self {
        let soft_limit = nonzero_limit(limits.soft);
        let hard_limit = nonzero_limit(limits.hard);
        Self {
            used,
            soft_limit,
            hard_limit,
            headroom_to_soft_limit: headroom(soft_limit, used),
            headroom_to_hard_limit: headroom(hard_limit, used),
            grace,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct QuotaGrace {
    pub(crate) state: QuotaGraceState,
    /// `None` means the provider reported an expired grace period without a
    /// deadline (Lustre prints `none` or `expired`); degu never synthesizes
    /// one. Serialized as an explicit `null`: the key is part of the frozen
    /// JSON contract and must never be omitted.
    pub(crate) expires_at_unix: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaGrace {
    pub(crate) fn from_kernel_deadline(deadline: u64, observed_at_unix: u64) -> Option<Self> {
        nonzero_limit(deadline).map(|expires_at_unix| Self {
            state: if expires_at_unix > observed_at_unix {
                QuotaGraceState::Active
            } else {
                QuotaGraceState::Expired
            },
            expires_at_unix: Some(expires_at_unix),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuotaGraceState {
    #[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
    Active,
    #[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
    Expired,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) struct QuotaLimits {
    pub(crate) soft: u64,
    pub(crate) hard: u64,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaLimits {
    pub(crate) fn new(soft: u64, hard: u64) -> Self {
        Self { soft, hard }
    }
}

#[cfg(any(target_os = "linux", test))]
fn nonzero_limit(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[cfg(any(target_os = "linux", test))]
fn headroom(limit: Option<u64>, used: u64) -> Option<u64> {
    limit.map(|value| value.saturating_sub(used))
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaScope,
        QuotaScopeIdentity, QuotaSnapshot, SubjectQuota,
    };
    use std::path::PathBuf;

    const DIMENSION_KEYS: &[&str] = &[
        "grace",
        "hard_limit",
        "headroom_to_hard_limit",
        "headroom_to_soft_limit",
        "soft_limit",
        "used",
    ];

    fn assert_json_keys(value: &serde_json::Value, expected: &[&str]) {
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, expected);
    }

    #[test]
    fn quota_dimension_normalizes_unlimited_values_and_headroom() {
        let unlimited = QuotaDimension::new(12, QuotaLimits::new(0, 0), None);
        assert_eq!(unlimited.soft_limit, None);
        assert_eq!(unlimited.headroom_to_hard_limit, None);

        let limited = QuotaDimension::new(
            12,
            QuotaLimits::new(10, 20),
            QuotaGrace::from_kernel_deadline(42, 10),
        );
        assert_eq!(limited.headroom_to_soft_limit, Some(0));
        assert_eq!(limited.headroom_to_hard_limit, Some(8));
        assert_eq!(limited.grace.unwrap().expires_at_unix, Some(42));
    }

    #[test]
    fn quota_grace_json_reports_active_snapshot_state() {
        let grace = QuotaGrace::from_kernel_deadline(200, 100);
        let dimension = QuotaDimension::new(12, QuotaLimits::new(10, 20), grace);
        let json = serde_json::to_value(dimension).unwrap();

        assert_json_keys(&json, DIMENSION_KEYS);
        assert_json_keys(&json["grace"], &["expires_at_unix", "state"]);
        assert_eq!(json["grace"]["state"], "active");
        assert_eq!(json["grace"]["expires_at_unix"], 200);
        assert!(json.get("grace_expires_at_unix").is_none());
    }

    #[test]
    fn quota_grace_json_keeps_the_deadline_key_as_null_when_unreported() {
        let grace = QuotaGrace {
            state: QuotaGraceState::Expired,
            expires_at_unix: None,
        };
        let dimension = QuotaDimension::new(12, QuotaLimits::new(10, 20), Some(grace));
        let json = serde_json::to_value(dimension).unwrap();

        assert_json_keys(&json, DIMENSION_KEYS);
        assert_json_keys(&json["grace"], &["expires_at_unix", "state"]);
        assert_eq!(json["grace"]["state"], "expired");
        assert!(json["grace"]["expires_at_unix"].is_null());
    }

    #[test]
    fn quota_grace_classifies_expiry_against_an_injected_observation_time() {
        let expired = QuotaGrace::from_kernel_deadline(200, 200).unwrap();

        assert_eq!(expired.state, QuotaGraceState::Expired);
        assert!(QuotaGrace::from_kernel_deadline(0, 200).is_none());
    }

    #[test]
    fn quota_active_json_keeps_scope_subject_provider_and_limits_distinct() {
        let scope = QuotaScope::new(
            PathBuf::from("/home/me"),
            PathBuf::from("/home"),
            "ext4".to_owned(),
            QuotaScopeIdentity::new(36, 8, 1, PathBuf::from("/dev/root")),
        );
        let report = QuotaSnapshot::active(
            scope,
            1000,
            ActiveQuota {
                provider: "linux_vfs",
                data_source: "linux_quotactl",
                space: QuotaDimension::new(10, QuotaLimits::new(20, 30), None),
                inodes: QuotaDimension::new(1, QuotaLimits::new(2, 3), None),
            },
        );
        let json = serde_json::to_value(report).unwrap();

        assert_json_keys(
            &json,
            &[
                "data_source",
                "inodes",
                "leading_limit",
                "limits_complete",
                "other_subjects",
                "provider",
                "scope",
                "space",
                "state",
                "subject",
            ],
        );
        assert_json_keys(&json["scope"], &["filesystem", "mount_point", "path"]);
        assert_json_keys(&json["subject"], &["id", "kind"]);
        for dimension in [&json["space"], &json["inodes"]] {
            assert_json_keys(dimension, DIMENSION_KEYS);
        }
        assert_eq!(json["state"], "active");
        assert_eq!(json["scope"]["filesystem"], "ext4");
        assert_eq!(json["subject"]["kind"], "user");
        assert_eq!(json["provider"], "linux_vfs");
        assert_eq!(json["data_source"], "linux_quotactl");
        assert_eq!(json["space"]["headroom_to_hard_limit"], 20);
        assert_eq!(json["other_subjects"], serde_json::json!([]));
        assert_eq!(json["limits_complete"], true);
    }

    fn scope() -> QuotaScope {
        QuotaScope::new(
            PathBuf::from("/scratch/me"),
            PathBuf::from("/scratch"),
            "lustre".to_owned(),
            QuotaScopeIdentity::new(36, 0, 1, PathBuf::from("server:/scratch")),
        )
    }

    fn dimension(used: u64, soft: u64, hard: u64) -> QuotaDimension {
        QuotaDimension::new(used, QuotaLimits::new(soft, hard), None)
    }

    fn user(space: QuotaDimension, inodes: QuotaDimension) -> QuotaSnapshot {
        QuotaSnapshot::active(
            scope(),
            1000,
            ActiveQuota {
                provider: "lustre_lfs",
                data_source: "lfs_quota",
                space,
                inodes,
            },
        )
    }

    fn unlimited_user() -> QuotaSnapshot {
        user(dimension(8, 0, 0), dimension(8, 0, 0))
    }

    fn expired(used: u64, soft: u64, hard: u64) -> QuotaDimension {
        QuotaDimension::new(
            used,
            QuotaLimits::new(soft, hard),
            Some(QuotaGrace {
                state: QuotaGraceState::Expired,
                expires_at_unix: None,
            }),
        )
    }

    fn in_grace(used: u64, soft: u64, hard: u64) -> QuotaDimension {
        QuotaDimension::new(
            used,
            QuotaLimits::new(soft, hard),
            QuotaGrace::from_kernel_deadline(200, 100),
        )
    }

    // The shape that made `degu quota` say "no configured limit" on a real
    // cluster: nothing on the user, and the project nearly out of inodes.
    #[test]
    fn project_outranks_user() {
        let report = unlimited_user().with_subjects(vec![
            SubjectQuota::active(
                "project",
                654_321,
                dimension(2_307_527_940, 0, 5_368_709_120),
                dimension(828_409, 0, 1_024_000),
            ),
            SubjectQuota::active("group", 2000, dimension(9, 0, 0), dimension(9, 0, 0)),
        ]);
        let leading = report.leading_limit.as_ref().unwrap();
        assert_eq!(leading.subject_kind, "project");
        assert_eq!(leading.subject_id, Some(654_321));
        assert_eq!(leading.dimension, "inodes");
        assert_eq!(leading.limit_kind, "hard");
        assert_eq!(leading.headroom, 1_024_000 - 828_409);
        assert!(!leading.at_limit);
        assert!(report.limits_complete);
    }

    #[test]
    fn no_limit_leader() {
        let report = unlimited_user().with_subjects(vec![SubjectQuota::active(
            "group",
            2000,
            dimension(9, 0, 0),
            dimension(9, 0, 0),
        )]);
        assert!(report.leading_limit.is_none());
        assert!(report.limits_complete);
    }

    // No limit found is not the same as no limit once a subject went unread.
    #[test]
    fn unread_marks_incomplete() {
        let report = unlimited_user().with_subjects(vec![SubjectQuota::unavailable(
            "group",
            Some(2000),
            "Connection refused".to_owned(),
        )]);
        assert!(report.leading_limit.is_none());
        assert!(!report.limits_complete);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["limits_complete"], false);
        assert!(json["leading_limit"].is_null());
        let other = &json["other_subjects"][0];
        assert_json_keys(other, &["id", "inodes", "kind", "reason", "space", "state"]);
        assert_eq!(other["state"], "unavailable");
        assert_eq!(other["reason"], "Connection refused");
        assert!(other["space"].is_null());
    }

    // A soft limit has the larger fraction until they are equal, and then the hard
    // limit is the one that refuses a write.
    #[test]
    fn soft_leads_first() {
        let report = user(dimension(50, 60, 100), dimension(1, 0, 0));
        assert_eq!(report.leading_limit.as_ref().unwrap().limit_kind, "soft");
        let equal = user(dimension(50, 100, 100), dimension(1, 0, 0));
        assert_eq!(equal.leading_limit.as_ref().unwrap().limit_kind, "hard");
    }

    #[test]
    fn huge_limits_exact() {
        // A float would call these equal; the larger fraction is the second.
        let report = user(
            dimension(u64::MAX - 2, 0, u64::MAX),
            dimension(u64::MAX - 1, 0, u64::MAX),
        );
        assert_eq!(report.leading_limit.as_ref().unwrap().dimension, "inodes");
    }

    // The documented limit of "highest use": it names the larger fraction, not the
    // quantity with the least room, and the report still shows the group's numbers.
    #[test]
    fn use_ignores_room() {
        let gib = 1024 * 1024 * 1024;
        let report =
            user(dimension(990 * gib, 0, 1000 * gib), dimension(1, 0, 0)).with_subjects(vec![
                SubjectQuota::active(
                    "group",
                    2000,
                    dimension(9 * gib, 0, 10 * gib),
                    dimension(1, 0, 0),
                ),
            ]);
        let leading = report.leading_limit.as_ref().unwrap();
        assert_eq!(leading.subject_kind, "user");
        assert_eq!(leading.headroom, 10 * gib);
        assert_eq!(
            report.other_subjects[0]
                .space
                .as_ref()
                .unwrap()
                .headroom_to_hard_limit,
            Some(gib)
        );
    }

    // A soft limit at 120% still in grace has not run out. An inode hard limit at 100%
    // has been reached, so it leads despite the smaller fraction.
    #[test]
    fn reached_outranks_use() {
        let report = user(in_grace(120, 100, 1000), dimension(1, 0, 0)).with_subjects(vec![
            SubjectQuota::active(
                "project",
                654_321,
                dimension(1, 0, 1000),
                dimension(500, 0, 500),
            ),
        ]);
        let leading = report.leading_limit.as_ref().unwrap();
        assert_eq!(leading.subject_kind, "project");
        assert_eq!(leading.dimension, "inodes");
        assert!(leading.at_limit);
    }

    #[test]
    fn soft_needs_expiry() {
        let expired_soft = user(expired(120, 100, 1000), dimension(1, 0, 0));
        let leading = expired_soft.leading_limit.as_ref().unwrap();
        assert_eq!(leading.limit_kind, "soft");
        assert!(leading.at_limit);

        let in_grace_soft = user(in_grace(120, 100, 1000), dimension(1, 0, 0));
        assert!(!in_grace_soft.leading_limit.as_ref().unwrap().at_limit);

        // Exceeded with no grace reported: not claimed as enforced.
        let silent = user(dimension(120, 100, 1000), dimension(1, 0, 0));
        assert!(!silent.leading_limit.as_ref().unwrap().at_limit);

        // Exactly at a soft limit is not over it, whatever the grace says.
        let at_soft = user(expired(100, 100, 1000), dimension(1, 0, 0));
        assert!(!at_soft.leading_limit.as_ref().unwrap().at_limit);
    }

    #[test]
    fn hard_reached_counts() {
        let reached = user(dimension(100, 0, 100), dimension(1, 0, 0));
        assert!(reached.leading_limit.as_ref().unwrap().at_limit);
        let below = user(dimension(99, 0, 100), dimension(1, 0, 0));
        assert!(!below.leading_limit.as_ref().unwrap().at_limit);
    }

    // ext4 can keep counting with enforcement off, so usage can sit past a hard limit
    // with writes still succeeding. The report states the numbers: it says the limit
    // has been reached, under a name that claims nothing about writes.
    #[test]
    fn accounted_past_hard() {
        let report = user(dimension(150, 0, 100), dimension(1, 0, 0));
        let leading = report.leading_limit.as_ref().unwrap();
        assert!(leading.at_limit);
        assert_eq!(leading.headroom, 0);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["leading_limit"]["at_limit"], true);
        assert!(json["leading_limit"].get("in_force").is_none());
    }

    // Past both limits of one quantity the hard limit is named, though the soft
    // limit has the larger fraction.
    #[test]
    fn hard_beats_soft() {
        let report = user(expired(300, 100, 200), dimension(1, 0, 0));
        let leading = report.leading_limit.as_ref().unwrap();
        assert_eq!(leading.limit_kind, "hard");
        assert!(leading.at_limit);
        assert_eq!(leading.headroom, 0);
    }
}
