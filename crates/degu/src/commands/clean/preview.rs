use crate::presentation::escape_terminal_text;
use degu_core::backend::{
    CertificationError, HeldTreeAssessmentFailure, HeldTreeAssessmentFailureCategory,
    HeldTreeAssessmentFailureKind, HeldTreePolicyAssessmentOutcome,
    HeldTreeRegularHardLinkTopology, HeldTreeRegularXattrTopology,
    assess_held_tree_policy_metadata, certify_held_fd,
};
use degu_core::finding::Finding;
use rustix::fs::{Mode, OFlags};
use serde_json::{Map, Value};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

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

    pub(super) fn has_ordinary_regular_xattrs(&self) -> bool {
        matches!(
            self.status,
            PreviewStagingStatus::TreePolicyAssessed { regular_xattrs, .. }
                if regular_xattrs.contains_xattrs()
        )
    }

    pub(super) fn purge_supported(&self) -> bool {
        !self.has_internal_hard_links() && !self.has_ordinary_regular_xattrs()
    }

    pub(super) fn is_blocked(&self) -> bool {
        matches!(self.status, PreviewStagingStatus::Blocked { .. })
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
            } => {
                let has_hardlinks = regular_hard_links.contains_multi_link_group();
                let has_xattrs = regular_xattrs.contains_xattrs();
                let limitation = match (has_hardlinks, has_xattrs) {
                    (true, true) => Some(
                        "multi-link regular-file groups and ordinary regular-file xattrs may be staged and undone, but sealed purge is unsupported",
                    ),
                    (true, false) => Some(
                        "multi-link regular-file groups may be staged and undone, but sealed purge is unsupported",
                    ),
                    (false, true) => Some(
                        "ordinary regular-file xattrs may be staged and undone, but sealed purge is unsupported",
                    ),
                    (false, false) => None,
                };
                serde_json::json!({
                    "path": path,
                    "status": "tree_policy_assessed",
                    "requested_action": if self.purge_requested { "purge" } else { "stage" },
                    "contains_internal_hardlinks": has_hardlinks,
                    "contains_ordinary_regular_xattrs": has_xattrs,
                    "regular_hard_links": {
                        "multi_link_groups": regular_hard_links.multi_link_groups,
                        "linked_entries": regular_hard_links.linked_entries,
                        "topology": if has_hardlinks { "internal_complete" } else { "single_link_only" },
                    },
                    "regular_xattrs": {
                        "entries": regular_xattrs.entries,
                        "attributes": regular_xattrs.attributes,
                        "value_bytes": regular_xattrs.value_bytes,
                        "proof_schema": 3,
                    },
                    "purge_admission": {
                        "supported": !has_hardlinks && !has_xattrs,
                        "limitation": limitation,
                    },
                    "pending_validation": {
                        "source_parent_seal": "requires_execution",
                        "regular_file_content_read_and_proof": "requires_execution",
                        "runtime_revalidation": "requires_execution",
                    },
                })
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
    let source_parent = match rustix::fs::open(&canonical_parent, OPEN_DIRECTORY, Mode::empty()) {
        Ok(parent) => parent,
        Err(error) => {
            return unavailable(
                "source_parent_unavailable",
                "race_or_io",
                &format!("failed to hold sealed staging source parent: {error}"),
            );
        }
    };
    let evidence = match certify_held_fd(source_parent) {
        Ok(evidence) => evidence,
        Err(error) => return certification_unavailable(error),
    };
    match assess_held_tree_policy_metadata(evidence, basename) {
        Ok(HeldTreePolicyAssessmentOutcome::TreePolicyAssessed { tree, .. }) => {
            PreviewStagingStatus::TreePolicyAssessed {
                regular_hard_links: tree.regular_hard_links,
                regular_xattrs: tree.regular_xattrs,
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
        Err(error) => assessment_failure_status(error),
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

    #[test]
    fn json_status_labels_are_stable() {
        let path = PathBuf::from("/preview/item");
        for (status, expected) in [
            (
                PreviewStagingStatus::TreePolicyAssessed {
                    regular_hard_links: HeldTreeRegularHardLinkTopology::default(),
                    regular_xattrs: HeldTreeRegularXattrTopology::default(),
                },
                "tree_policy_assessed",
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
