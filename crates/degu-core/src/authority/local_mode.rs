//! Pure POSIX mode-bit exposure evaluation.
//!
//! This module is intentionally disconnected from planning, staging, cleanup,
//! and purge. Its output is descriptive evidence only and can never construct
//! `MutationUnitAuthority` or `PurgeAuthority`.

use super::{
    AuthorityBackend, AuthorityControlRights, AuthorityControllerExposure, CapabilityAcquisition,
    CapabilityAssessment, CapabilityEvidence, CapabilityReason, EvidenceCertainty, NamespaceRights,
    Principal, WriterExposure,
};
use std::collections::BTreeSet;

const OWNER_WRITE: u32 = 0o200;
const OWNER_EXECUTE: u32 = 0o100;
const GROUP_WRITE: u32 = 0o020;
const GROUP_EXECUTE: u32 = 0o010;
const OTHER_WRITE: u32 = 0o002;
const OTHER_EXECUTE: u32 = 0o001;
const STICKY: u32 = 0o1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessClass {
    Owner,
    Group,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixSubject {
    pub uid: u32,
    pub groups: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryModeFacts {
    pub mode: u32,
    pub owner_uid: u32,
    pub group_gid: u32,
}

/// POSIX class selection is precedence-based, never a union of classes.
pub fn effective_access_class(facts: DirectoryModeFacts, subject: &PosixSubject) -> AccessClass {
    if subject.uid == facts.owner_uid {
        AccessClass::Owner
    } else if subject.groups.contains(&facts.group_gid) {
        AccessClass::Group
    } else {
        AccessClass::Other
    }
}

/// Evaluate namespace rights for one subject and one existing child binding.
///
/// Write and execute/search are both required. Sticky permits creation of new
/// siblings but confines delete/replace of an existing binding to its owner or
/// the directory owner. Privileged capabilities are outside this mode backend.
pub fn evaluate_namespace_rights(
    facts: DirectoryModeFacts,
    subject: &PosixSubject,
    binding_owner_uid: Option<u32>,
) -> NamespaceRights {
    let (write, search) = match effective_access_class(facts, subject) {
        AccessClass::Owner => (
            facts.mode & OWNER_WRITE != 0,
            facts.mode & OWNER_EXECUTE != 0,
        ),
        AccessClass::Group => (
            facts.mode & GROUP_WRITE != 0,
            facts.mode & GROUP_EXECUTE != 0,
        ),
        AccessClass::Other => (
            facts.mode & OTHER_WRITE != 0,
            facts.mode & OTHER_EXECUTE != 0,
        ),
    };
    let can_write_namespace = write && search;
    let can_mutate_existing = facts.mode & STICKY == 0
        || subject.uid == facts.owner_uid
        || binding_owner_uid.is_some_and(|owner| subject.uid == owner);
    NamespaceRights {
        create_file: can_write_namespace,
        create_dir: can_write_namespace,
        delete_child: can_write_namespace && can_mutate_existing,
        replace_child: can_write_namespace && can_mutate_existing,
        traverse: search,
    }
}

/// Conservatively expose foreign writer classes and the foreign directory
/// owner as a policy controller. Abstract group/everyone classes do not claim a
/// sticky existing-binding right because that depends on a concrete entry UID.
pub fn foreign_mode_exposure(
    facts: DirectoryModeFacts,
    effective_uid: u32,
) -> (Vec<WriterExposure>, Vec<AuthorityControllerExposure>) {
    let sticky = facts.mode & STICKY != 0;
    let class_rights = |write: u32, execute: u32, sticky_owner: bool| {
        let traverse = facts.mode & execute != 0;
        let write_and_search = facts.mode & write != 0 && traverse;
        NamespaceRights {
            create_file: write_and_search,
            create_dir: write_and_search,
            delete_child: write_and_search && (!sticky || sticky_owner),
            replace_child: write_and_search && (!sticky || sticky_owner),
            traverse,
        }
    };

    let mut writers = Vec::new();
    if facts.owner_uid != effective_uid {
        let rights = class_rights(OWNER_WRITE, OWNER_EXECUTE, true);
        if rights.create_file || rights.delete_child || rights.traverse {
            writers.push(WriterExposure {
                principal: Principal::PosixUid(facts.owner_uid),
                rights,
                source: AuthorityBackend::PosixMode,
                inherited: false,
                certainty: EvidenceCertainty::Verified,
            });
        }
    }
    for (principal, rights) in [
        (
            Principal::PosixGid(facts.group_gid),
            class_rights(GROUP_WRITE, GROUP_EXECUTE, false),
        ),
        (
            Principal::Everyone,
            class_rights(OTHER_WRITE, OTHER_EXECUTE, false),
        ),
    ] {
        if rights.create_file || rights.delete_child {
            writers.push(WriterExposure {
                principal,
                rights,
                source: AuthorityBackend::PosixMode,
                inherited: false,
                certainty: EvidenceCertainty::Verified,
            });
        }
    }

    let controllers = (facts.owner_uid != effective_uid)
        .then_some(AuthorityControllerExposure {
            principal: Principal::PosixUid(facts.owner_uid),
            rights: AuthorityControlRights {
                change_mode: true,
                change_acl: true,
                // A foreign directory owner controls policy and can first
                // chmod before replacing a child binding. This controller
                // exposure is intentionally wider than its current direct
                // mode-bit rights.
                replace_binding: true,
            },
        })
        .into_iter()
        .collect();
    (writers, controllers)
}

/// Strip only non-owner write bits which currently combine with search.
/// Owner/read/search and all special bits are preserved.
pub fn minimal_sealed_mode(mode: u32) -> u32 {
    let mut sealed = mode;
    if mode & (GROUP_WRITE | GROUP_EXECUTE) == GROUP_WRITE | GROUP_EXECUTE {
        sealed &= !GROUP_WRITE;
    }
    if mode & (OTHER_WRITE | OTHER_EXECUTE) == OTHER_WRITE | OTHER_EXECUTE {
        sealed &= !OTHER_WRITE;
    }
    sealed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSealAssessment {
    /// Descriptive candidate only; no capability, execution, or purge authority.
    Candidate {
        original_mode: u32,
        sealed_mode: u32,
    },
    Denied(ModeSealDenial),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSealDenial {
    NotOwner,
}

fn mode_facts(evidence: &degu_walk::local_backend::HeldLocalBackendEvidence) -> DirectoryModeFacts {
    DirectoryModeFacts {
        mode: evidence.mode(),
        owner_uid: evidence.owner_uid(),
        group_gid: evidence.group_gid(),
    }
}

/// Assess only evidence produced by degu-walk's strict held-FD backend probe.
/// The token constructor is private to that probe, so callers cannot assert
/// certification, ACL absence, or process credentials themselves.
pub fn assess_mode_seal(
    evidence: &degu_walk::local_backend::HeldLocalBackendEvidence,
) -> ModeSealAssessment {
    let facts = mode_facts(evidence);
    if facts.owner_uid != evidence.effective_uid() {
        return ModeSealAssessment::Denied(ModeSealDenial::NotOwner);
    }
    ModeSealAssessment::Candidate {
        original_mode: facts.mode,
        sealed_mode: minimal_sealed_mode(facts.mode),
    }
}

/// Evaluate the current process's ability to rename/delete one existing child
/// binding. This remains a pure capability dimension: it creates no mutation
/// unit, staging, or purge authority.
pub fn assess_process_capability(
    evidence: &degu_walk::local_backend::HeldLocalBackendEvidence,
    binding_owner_uid: Option<u32>,
) -> CapabilityAssessment {
    assess_capability_facts(
        mode_facts(evidence),
        &PosixSubject {
            uid: evidence.effective_uid(),
            groups: evidence.effective_groups().clone(),
        },
        binding_owner_uid,
    )
}

fn assess_capability_facts(
    facts: DirectoryModeFacts,
    subject: &PosixSubject,
    binding_owner_uid: Option<u32>,
) -> CapabilityAssessment {
    let rights = evaluate_namespace_rights(facts, subject, binding_owner_uid);
    if rights.replace_child {
        return CapabilityAssessment::Present(
            CapabilityEvidence::new(AuthorityBackend::PosixMode)
                .expect("the POSIX mode backend is known"),
        );
    }
    if subject.uid == facts.owner_uid {
        let required = minimal_sealed_mode(facts.mode | OWNER_WRITE | OWNER_EXECUTE);
        return CapabilityAssessment::Acquirable(CapabilityAcquisition::OwnerModeTransform {
            original: facts.mode,
            required,
        });
    }
    CapabilityAssessment::Missing(CapabilityReason::PermissionDenied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(uid: u32, groups: &[u32]) -> PosixSubject {
        PosixSubject {
            uid,
            groups: groups.iter().copied().collect(),
        }
    }

    #[test]
    fn owner_group_other_precedence_never_unions_classes() {
        let facts = DirectoryModeFacts {
            mode: 0o027,
            owner_uid: 10,
            group_gid: 20,
        };
        assert_eq!(
            effective_access_class(facts, &subject(10, &[20])),
            AccessClass::Owner
        );
        assert_eq!(
            evaluate_namespace_rights(facts, &subject(10, &[20]), Some(99)),
            NamespaceRights::default()
        );
        assert_eq!(
            effective_access_class(facts, &subject(11, &[20])),
            AccessClass::Group
        );
        assert!(!evaluate_namespace_rights(facts, &subject(11, &[20]), Some(99)).create_file);
        assert!(evaluate_namespace_rights(facts, &subject(12, &[]), Some(99)).create_file);
    }

    #[test]
    fn write_and_search_are_both_required() {
        let facts = |mode| DirectoryModeFacts {
            mode,
            owner_uid: 1,
            group_gid: 2,
        };
        assert!(!evaluate_namespace_rights(facts(0o720), &subject(3, &[2]), Some(9)).create_file);
        assert!(!evaluate_namespace_rights(facts(0o702), &subject(3, &[]), Some(9)).create_file);
        assert!(evaluate_namespace_rights(facts(0o730), &subject(3, &[2]), Some(9)).create_file);
        assert!(evaluate_namespace_rights(facts(0o703), &subject(3, &[]), Some(9)).create_file);
    }

    #[test]
    fn sticky_separates_create_from_existing_binding_mutation() {
        let facts = DirectoryModeFacts {
            mode: 0o1777,
            owner_uid: 1,
            group_gid: 2,
        };
        let foreign = evaluate_namespace_rights(facts, &subject(3, &[]), Some(4));
        assert!(foreign.create_file && foreign.create_dir && foreign.traverse);
        assert!(!foreign.delete_child && !foreign.replace_child);
        let entry_owner = evaluate_namespace_rights(facts, &subject(4, &[]), Some(4));
        assert!(entry_owner.delete_child && entry_owner.replace_child);
        let directory_owner = evaluate_namespace_rights(facts, &subject(1, &[]), Some(4));
        assert!(directory_owner.delete_child && directory_owner.replace_child);
        let unknown_binding_owner = evaluate_namespace_rights(facts, &subject(4, &[]), None);
        assert!(unknown_binding_owner.create_file);
        assert!(!unknown_binding_owner.delete_child && !unknown_binding_owner.replace_child);
    }

    #[test]
    fn foreign_owner_is_always_a_controller() {
        let facts = DirectoryModeFacts {
            mode: 0o1400,
            owner_uid: 8,
            group_gid: 9,
        };
        let (_, controllers) = foreign_mode_exposure(facts, 7);
        assert_eq!(controllers.len(), 1);
        assert_eq!(controllers[0].principal, Principal::PosixUid(8));
        assert!(controllers[0].rights.change_mode && controllers[0].rights.change_acl);
        assert!(controllers[0].rights.replace_binding);
    }

    #[test]
    fn minimal_transform_preserves_special_read_and_search_bits() {
        for (mode, expected) in [
            (0o775, 0o755),
            (0o770, 0o750),
            (0o777, 0o755),
            (0o720, 0o720),
            (0o702, 0o702),
            (0o6777, 0o6755),
            (0o4775, 0o4755),
            (0o1777, 0o1755),
        ] {
            assert_eq!(minimal_sealed_mode(mode), expected, "mode {mode:o}");
        }
    }

    #[test]
    fn current_owner_capability_is_present() {
        let facts = DirectoryModeFacts {
            mode: 0o775,
            owner_uid: 7,
            group_gid: 8,
        };
        let capability = assess_capability_facts(facts, &subject(7, &[]), None);
        assert!(matches!(capability, CapabilityAssessment::Present(_)));
    }

    #[test]
    fn owner_capability_is_acquirable_with_reversible_minimal_transform() {
        let facts = DirectoryModeFacts {
            mode: 0o550,
            owner_uid: 7,
            group_gid: 8,
        };
        assert_eq!(
            assess_capability_facts(facts, &subject(7, &[]), None),
            CapabilityAssessment::Acquirable(CapabilityAcquisition::OwnerModeTransform {
                original: 0o550,
                required: 0o750,
            })
        );
    }

    #[test]
    fn foreign_process_without_current_rights_is_permission_denied() {
        let facts = DirectoryModeFacts {
            mode: 0o700,
            owner_uid: 7,
            group_gid: 8,
        };
        assert_eq!(
            assess_capability_facts(facts, &subject(9, &[]), Some(9)),
            CapabilityAssessment::Missing(CapabilityReason::PermissionDenied)
        );
    }

    #[test]
    fn owner_class_precedence_cannot_borrow_group_capability() {
        let facts = DirectoryModeFacts {
            mode: 0o470,
            owner_uid: 7,
            group_gid: 8,
        };
        assert_eq!(
            assess_capability_facts(facts, &subject(7, &[8]), None),
            CapabilityAssessment::Acquirable(CapabilityAcquisition::OwnerModeTransform {
                original: 0o470,
                required: 0o750,
            })
        );
        assert!(matches!(
            assess_capability_facts(facts, &subject(9, &[8]), Some(9)),
            CapabilityAssessment::Present(_)
        ));
    }

    #[test]
    fn acquisition_preserves_special_bits_and_records_restore_mode() {
        let facts = DirectoryModeFacts {
            mode: 0o4577,
            owner_uid: 7,
            group_gid: 8,
        };
        assert_eq!(
            assess_capability_facts(facts, &subject(7, &[8]), None),
            CapabilityAssessment::Acquirable(CapabilityAcquisition::OwnerModeTransform {
                original: 0o4577,
                required: 0o4755,
            })
        );
    }

    #[test]
    fn sticky_unknown_binding_owner_is_missing_for_a_foreign_writer() {
        let facts = DirectoryModeFacts {
            mode: 0o1770,
            owner_uid: 7,
            group_gid: 8,
        };
        assert_eq!(
            assess_capability_facts(facts, &subject(9, &[8]), None),
            CapabilityAssessment::Missing(CapabilityReason::PermissionDenied)
        );
        assert!(matches!(
            assess_capability_facts(facts, &subject(9, &[8]), Some(9)),
            CapabilityAssessment::Present(_)
        ));
    }
}
