//! Pure policy for deciding whether entry content has enough evidence to be
//! admitted to a held-tree content proof.
//!
//! This module deliberately owns no filesystem handles and grants no mutation
//! authority. Callers collect facts; this module only explains whether the
//! current content-proof format can represent them. Hard-link topology and
//! xattr value digests remain future schema work.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Directory,
    Regular,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Evidence {
    Absent,
    Present,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XattrPlatform {
    #[cfg(any(target_os = "linux", test))]
    Linux,
    #[cfg(any(target_os = "macos", test))]
    MacOs,
    #[cfg(any(not(any(target_os = "linux", target_os = "macos")), test))]
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)] // A platform build retains only that platform taxonomy.
pub(crate) enum XattrNameClass {
    #[cfg(any(target_os = "linux", test))]
    LinuxUser,
    #[cfg(any(target_os = "linux", test))]
    LinuxSystem,
    #[cfg(any(target_os = "linux", test))]
    LinuxTrusted,
    #[cfg(any(target_os = "linux", test))]
    LinuxSecurityCapability,
    #[cfg(any(target_os = "linux", test))]
    LinuxSecurity,
    #[cfg(any(target_os = "linux", test))]
    LinuxOther,
    #[cfg(any(target_os = "macos", test))]
    MacOsQuarantine,
    #[cfg(any(target_os = "macos", test))]
    MacOsProvenance,
    #[cfg(any(target_os = "macos", test))]
    MacOsMetadata,
    #[cfg(any(target_os = "macos", test))]
    MacOsLastUsedDate,
    #[cfg(any(target_os = "macos", test))]
    MacOsFinderInfo,
    #[cfg(any(target_os = "macos", test))]
    MacOsResourceFork,
    #[cfg(any(target_os = "macos", test))]
    MacOsOther,
    #[cfg(any(not(any(target_os = "linux", target_os = "macos")), test))]
    OtherPlatform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Xattrs<'a> {
    /// The complete name list is known. An empty slice proves absence.
    Names(&'a [&'a [u8]]),
    /// Listing failed, was truncated, or is unsupported.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryFacts<'a> {
    pub(crate) kind: EntryKind,
    pub(crate) acl: Evidence,
    pub(crate) xattr_platform: XattrPlatform,
    pub(crate) xattrs: Xattrs<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectReason<'a> {
    UnsupportedEntryKind,
    AclPresent,
    AclUnknown,
    ExtendedAttributePresent {
        name: &'a [u8],
        class: XattrNameClass,
    },
    ExtendedAttributesUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission<'a> {
    Admit,
    Reject(RejectReason<'a>),
}

/// Apply the current, deliberately conservative content-proof policy.
///
/// Directory metadata is outside this policy's scope: held-tree directory
/// authority is certified separately. Regular-file link topology is classified
/// only after the bounded traversal has a complete stable set of per-entry
/// observations. Non-directory ACL and xattr uncertainty fails closed here.
pub(crate) fn assess_content<'a>(facts: &EntryFacts<'a>) -> Admission<'a> {
    match facts.kind {
        EntryKind::Directory => Admission::Admit,
        EntryKind::Other => Admission::Reject(RejectReason::UnsupportedEntryKind),
        EntryKind::Regular | EntryKind::Symlink => assess_non_directory_metadata(facts),
    }
}

fn assess_non_directory_metadata<'a>(facts: &EntryFacts<'a>) -> Admission<'a> {
    let xattr_admission = match facts.xattrs {
        Xattrs::Names([]) => None,
        Xattrs::Names(names) => {
            let name = names
                .iter()
                .copied()
                .min()
                .expect("a non-empty xattr name list has a minimum");
            Some(Admission::Reject(RejectReason::ExtendedAttributePresent {
                name,
                class: classify_xattr(facts.xattr_platform, name),
            }))
        }
        Xattrs::Unknown => Some(Admission::Reject(RejectReason::ExtendedAttributesUnknown)),
    };
    if let Some(admission) = xattr_admission {
        return admission;
    }

    match facts.acl {
        Evidence::Absent => Admission::Admit,
        Evidence::Present => Admission::Reject(RejectReason::AclPresent),
        Evidence::Unknown => Admission::Reject(RejectReason::AclUnknown),
    }
}

/// Classify names now so future policy can admit selected digest-backed xattrs
/// without collapsing security-bearing and unknown namespaces together.
pub(crate) fn classify_xattr(platform: XattrPlatform, name: &[u8]) -> XattrNameClass {
    match platform {
        #[cfg(any(target_os = "linux", test))]
        XattrPlatform::Linux => classify_linux_xattr(name),
        #[cfg(any(target_os = "macos", test))]
        XattrPlatform::MacOs => classify_macos_xattr(name),
        #[cfg(any(not(any(target_os = "linux", target_os = "macos")), test))]
        XattrPlatform::Other => XattrNameClass::OtherPlatform,
    }
}

#[cfg(any(target_os = "linux", test))]
fn classify_linux_xattr(name: &[u8]) -> XattrNameClass {
    if name == b"security.capability" {
        XattrNameClass::LinuxSecurityCapability
    } else if name.starts_with(b"user.") {
        XattrNameClass::LinuxUser
    } else if name.starts_with(b"system.") {
        XattrNameClass::LinuxSystem
    } else if name.starts_with(b"trusted.") {
        XattrNameClass::LinuxTrusted
    } else if name.starts_with(b"security.") {
        XattrNameClass::LinuxSecurity
    } else {
        XattrNameClass::LinuxOther
    }
}

#[cfg(any(target_os = "macos", test))]
fn classify_macos_xattr(name: &[u8]) -> XattrNameClass {
    match name {
        b"com.apple.quarantine" => XattrNameClass::MacOsQuarantine,
        b"com.apple.provenance" => XattrNameClass::MacOsProvenance,
        b"com.apple.lastuseddate#PS" => XattrNameClass::MacOsLastUsedDate,
        b"com.apple.FinderInfo" => XattrNameClass::MacOsFinderInfo,
        b"com.apple.ResourceFork" => XattrNameClass::MacOsResourceFork,
        _ if name.starts_with(b"com.apple.metadata:") => XattrNameClass::MacOsMetadata,
        _ => XattrNameClass::MacOsOther,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_XATTR: &[&[u8]] = &[b"user.example"];
    const NO_XATTRS: &[&[u8]] = &[];

    #[test]
    fn policy_matrix_is_exhaustive_and_fail_closed() {
        let kinds = [
            EntryKind::Directory,
            EntryKind::Regular,
            EntryKind::Symlink,
            EntryKind::Other,
        ];
        let acls = [Evidence::Absent, Evidence::Present, Evidence::Unknown];
        let xattrs = [
            Xattrs::Names(NO_XATTRS),
            Xattrs::Names(ONE_XATTR),
            Xattrs::Unknown,
        ];

        let mut cases = 0;
        for kind in kinds {
            for acl in acls {
                for xattrs in xattrs {
                    cases += 1;
                    let facts = EntryFacts {
                        kind,
                        acl,
                        xattr_platform: XattrPlatform::Linux,
                        xattrs,
                    };
                    assert_eq!(
                        assess_content(&facts),
                        expected(kind, acl, xattrs),
                        "{facts:?}"
                    );
                }
            }
        }
        assert_eq!(cases, 36);
    }

    fn expected<'a>(kind: EntryKind, acl: Evidence, xattrs: Xattrs<'a>) -> Admission<'a> {
        if kind == EntryKind::Directory {
            return Admission::Admit;
        }
        if kind == EntryKind::Other {
            return Admission::Reject(RejectReason::UnsupportedEntryKind);
        }
        match xattrs {
            Xattrs::Names([]) => {}
            Xattrs::Names(names) => {
                return Admission::Reject(RejectReason::ExtendedAttributePresent {
                    name: names[0],
                    class: XattrNameClass::LinuxUser,
                });
            }
            Xattrs::Unknown => {
                return Admission::Reject(RejectReason::ExtendedAttributesUnknown);
            }
        }
        match acl {
            Evidence::Present => Admission::Reject(RejectReason::AclPresent),
            Evidence::Unknown => Admission::Reject(RejectReason::AclUnknown),
            Evidence::Absent => Admission::Admit,
        }
    }

    #[test]
    fn linux_namespace_taxonomy_is_table_driven() {
        let cases: &[(&[u8], XattrNameClass)] = &[
            (b"user.comment", XattrNameClass::LinuxUser),
            (b"system.posix_acl_access", XattrNameClass::LinuxSystem),
            (b"trusted.overlay.opaque", XattrNameClass::LinuxTrusted),
            (
                b"security.capability",
                XattrNameClass::LinuxSecurityCapability,
            ),
            (b"security.selinux", XattrNameClass::LinuxSecurity),
            (b"security.unknown", XattrNameClass::LinuxSecurity),
            (b"vendor.attribute", XattrNameClass::LinuxOther),
            (b"\xffnon-utf8", XattrNameClass::LinuxOther),
        ];
        for &(name, expected) in cases {
            assert_eq!(
                classify_xattr(XattrPlatform::Linux, name),
                expected,
                "{name:?}"
            );
        }
    }

    #[test]
    fn macos_namespace_taxonomy_is_table_driven() {
        let cases: &[(&[u8], XattrNameClass)] = &[
            (b"com.apple.quarantine", XattrNameClass::MacOsQuarantine),
            (b"com.apple.provenance", XattrNameClass::MacOsProvenance),
            (
                b"com.apple.metadata:kMDItemWhereFroms",
                XattrNameClass::MacOsMetadata,
            ),
            (
                b"com.apple.lastuseddate#PS",
                XattrNameClass::MacOsLastUsedDate,
            ),
            (b"com.apple.FinderInfo", XattrNameClass::MacOsFinderInfo),
            (b"com.apple.ResourceFork", XattrNameClass::MacOsResourceFork),
            (b"com.apple.unknown", XattrNameClass::MacOsOther),
            (b"vendor.attribute", XattrNameClass::MacOsOther),
        ];
        for &(name, expected) in cases {
            assert_eq!(
                classify_xattr(XattrPlatform::MacOs, name),
                expected,
                "{name:?}"
            );
        }
    }

    #[test]
    fn every_named_xattr_class_is_rejected_by_the_current_policy() {
        let cases: &[(XattrPlatform, &[u8], XattrNameClass)] = &[
            (
                XattrPlatform::Linux,
                b"user.comment",
                XattrNameClass::LinuxUser,
            ),
            (
                XattrPlatform::Linux,
                b"system.posix_acl_access",
                XattrNameClass::LinuxSystem,
            ),
            (
                XattrPlatform::Linux,
                b"trusted.overlay.opaque",
                XattrNameClass::LinuxTrusted,
            ),
            (
                XattrPlatform::Linux,
                b"security.capability",
                XattrNameClass::LinuxSecurityCapability,
            ),
            (
                XattrPlatform::Linux,
                b"security.selinux",
                XattrNameClass::LinuxSecurity,
            ),
            (
                XattrPlatform::Linux,
                b"vendor.attribute",
                XattrNameClass::LinuxOther,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.quarantine",
                XattrNameClass::MacOsQuarantine,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.provenance",
                XattrNameClass::MacOsProvenance,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.metadata:kMDItemWhereFroms",
                XattrNameClass::MacOsMetadata,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.lastuseddate#PS",
                XattrNameClass::MacOsLastUsedDate,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.FinderInfo",
                XattrNameClass::MacOsFinderInfo,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.ResourceFork",
                XattrNameClass::MacOsResourceFork,
            ),
            (
                XattrPlatform::MacOs,
                b"com.apple.unknown",
                XattrNameClass::MacOsOther,
            ),
            (
                XattrPlatform::Other,
                b"user.comment",
                XattrNameClass::OtherPlatform,
            ),
        ];

        for &(platform, name, class) in cases {
            let names = [name];
            let facts = EntryFacts {
                kind: EntryKind::Symlink,
                acl: Evidence::Absent,
                xattr_platform: platform,
                xattrs: Xattrs::Names(&names),
            };
            assert_eq!(
                assess_content(&facts),
                Admission::Reject(RejectReason::ExtendedAttributePresent { name, class }),
                "{platform:?} {name:?}",
            );
        }
    }

    #[test]
    fn unsupported_platform_xattrs_remain_distinct_and_rejected() {
        assert_eq!(
            classify_xattr(XattrPlatform::Other, b"user.example"),
            XattrNameClass::OtherPlatform
        );
        let facts = EntryFacts {
            kind: EntryKind::Regular,
            acl: Evidence::Absent,
            xattr_platform: XattrPlatform::Other,
            xattrs: Xattrs::Names(&[b"user.example"]),
        };
        assert_eq!(
            assess_content(&facts),
            Admission::Reject(RejectReason::ExtendedAttributePresent {
                name: b"user.example",
                class: XattrNameClass::OtherPlatform,
            })
        );
    }

    #[test]
    fn rejection_precedence_is_stable() {
        let facts = EntryFacts {
            kind: EntryKind::Regular,
            acl: Evidence::Unknown,
            xattr_platform: XattrPlatform::Linux,
            xattrs: Xattrs::Unknown,
        };
        assert_eq!(
            assess_content(&facts),
            Admission::Reject(RejectReason::ExtendedAttributesUnknown)
        );
    }

    #[test]
    fn xattr_rejection_is_independent_of_enumeration_order() {
        let first = [b"user.comment".as_slice(), b"security.selinux".as_slice()];
        let reversed = [b"security.selinux".as_slice(), b"user.comment".as_slice()];
        let facts = |names| EntryFacts {
            kind: EntryKind::Symlink,
            acl: Evidence::Absent,
            xattr_platform: XattrPlatform::Linux,
            xattrs: Xattrs::Names(names),
        };
        let expected = Admission::Reject(RejectReason::ExtendedAttributePresent {
            name: b"security.selinux",
            class: XattrNameClass::LinuxSecurity,
        });
        assert_eq!(assess_content(&facts(&first)), expected);
        assert_eq!(assess_content(&facts(&reversed)), expected);
    }

    #[test]
    fn directory_metadata_is_deliberately_outside_content_admission() {
        let facts = EntryFacts {
            kind: EntryKind::Directory,
            acl: Evidence::Present,
            xattr_platform: XattrPlatform::Other,
            xattrs: Xattrs::Unknown,
        };
        assert_eq!(assess_content(&facts), Admission::Admit);
    }

    #[test]
    fn xattr_rejection_precedes_acl_rejection() {
        let names = [b"user.example".as_slice()];
        let facts = EntryFacts {
            kind: EntryKind::Regular,
            acl: Evidence::Present,
            xattr_platform: XattrPlatform::Linux,
            xattrs: Xattrs::Names(&names),
        };
        assert_eq!(
            assess_content(&facts),
            Admission::Reject(RejectReason::ExtendedAttributePresent {
                name: b"user.example",
                class: XattrNameClass::LinuxUser,
            })
        );
    }
}
