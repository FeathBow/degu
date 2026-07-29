use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub(super) struct QuotaReport {
    pub(super) scope: QuotaScope,
    pub(super) subject: QuotaSubject,
    pub(super) provider: &'static str,
    pub(super) data_source: &'static str,
    pub(super) state: &'static str,
    pub(super) space: QuotaDimension,
    pub(super) inodes: QuotaDimension,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaReport {
    pub(super) fn active(scope: QuotaScope, subject_id: u32, quota: ActiveQuota) -> Self {
        Self {
            scope,
            subject: QuotaSubject::user(subject_id),
            provider: quota.provider,
            data_source: quota.data_source,
            state: "active",
            space: quota.space,
            inodes: quota.inodes,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct ActiveQuota {
    pub(super) provider: &'static str,
    pub(super) data_source: &'static str,
    pub(super) space: QuotaDimension,
    pub(super) inodes: QuotaDimension,
}

#[derive(Debug, Serialize)]
pub(super) struct QuotaScope {
    pub(super) path: PathBuf,
    pub(super) mount_point: PathBuf,
    pub(super) filesystem: String,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaScope {
    pub(super) fn new(path: PathBuf, mount_point: PathBuf, filesystem: String) -> Self {
        Self {
            path,
            mount_point,
            filesystem,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct QuotaSubject {
    pub(super) kind: &'static str,
    pub(super) id: u32,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaSubject {
    fn user(id: u32) -> Self {
        Self { kind: "user", id }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct QuotaDimension {
    pub(super) used: u64,
    pub(super) soft_limit: Option<u64>,
    pub(super) hard_limit: Option<u64>,
    pub(super) headroom_to_soft_limit: Option<u64>,
    pub(super) headroom_to_hard_limit: Option<u64>,
    pub(super) grace: Option<QuotaGrace>,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaDimension {
    pub(super) fn new(used: u64, limits: QuotaLimits, grace: Option<QuotaGrace>) -> Self {
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
pub(super) struct QuotaGrace {
    pub(super) state: QuotaGraceState,
    /// `None` means the provider reported an expired grace period without a
    /// deadline (Lustre prints `none` or `expired`); degu never synthesizes
    /// one. Serialized as an explicit `null`: the key is part of the frozen
    /// JSON contract and must never be omitted.
    pub(super) expires_at_unix: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaGrace {
    pub(super) fn from_kernel_deadline(deadline: u64, observed_at_unix: u64) -> Option<Self> {
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
pub(super) enum QuotaGraceState {
    #[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
    Active,
    #[cfg_attr(all(not(target_os = "linux"), not(test)), allow(dead_code))]
    Expired,
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct QuotaLimits {
    pub(super) soft: u64,
    pub(super) hard: u64,
}

#[cfg(any(target_os = "linux", test))]
impl QuotaLimits {
    pub(super) fn new(soft: u64, hard: u64) -> Self {
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
        ActiveQuota, QuotaDimension, QuotaGrace, QuotaGraceState, QuotaLimits, QuotaReport,
        QuotaScope,
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
        );
        let report = QuotaReport::active(
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
    }
}
