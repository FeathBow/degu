use crate::ecosystem::ScanPriority;
use crate::finding::{
    Confidence, Disposition, DispositionMode, FindingCandidate, FindingFacts, Hazard, Ownership,
    Recovery, RegenCost,
};

pub const UNKNOWN_RECOVERY: &str = "recovery requirements are unknown";
pub const USER_ASSET: &str = "user asset: degu cannot recreate it";
pub const TOOL_MANAGED: &str = "managed by the owning tool; delete through it";
pub const UNKNOWN_OWNERSHIP: &str = "ownership and coordination requirements are unknown";
pub const UNVERIFIED_REDIRECT: &str = "relocated via an environment variable degu cannot verify";
pub const INCOMPLETE_MEASUREMENT: &str = "measurement incomplete: some paths were not measured";
pub const BREAKS_CONSUMERS: &str = "deletion can break software that links into this data";
pub const ACTIVE_USE: &str = "deletion can disrupt active sessions using this data";
pub const COSTLY_REGEN: &str = "costly to regenerate";

/// Every reason `derive` can attach, strictest-first. The order is load-bearing
/// for `authority_rank` (and lets presentation prove exhaustiveness) — do not reorder.
pub const STATIC_REASONS: [&str; 9] = [
    UNKNOWN_RECOVERY,
    USER_ASSET,
    TOOL_MANAGED,
    UNKNOWN_OWNERSHIP,
    UNVERIFIED_REDIRECT,
    INCOMPLETE_MEASUREMENT,
    BREAKS_CONSUMERS,
    ACTIVE_USE,
    COSTLY_REGEN,
];

/// Safety rank for consolidating same-path findings: `(mode, reason strictness)`
/// so fact priority, never ecosystem name, decides which facts survive a merge.
pub(crate) fn authority_rank(disposition: &Disposition) -> (u8, u8) {
    let mode_rank = match disposition.mode {
        DispositionMode::Eligible => 0,
        DispositionMode::OptIn => 1,
        DispositionMode::ReportOnly => 2,
    };
    (
        mode_rank,
        disposition.reason.as_deref().map_or(0, reason_rank),
    )
}

/// Constraint reasons outrank every `derive` reason (credential above AI-tool,
/// matching finalize's precedence); within `derive`, strictest-first order wins.
fn reason_rank(reason: &str) -> u8 {
    let derived = STATIC_REASONS.len() as u8;
    if reason == crate::safety::PROTECTED_CREDENTIAL_REASON {
        return derived + 2;
    }
    if reason == crate::safety::MIXED_STATE_AI_TOOL_REASON {
        return derived + 1;
    }
    STATIC_REASONS
        .iter()
        .position(|r| *r == reason)
        .map_or(0, |index| derived - index as u8)
}

/// Immutable policy evidence captured from a candidate before finalization.
#[derive(Clone, Copy)]
pub(crate) struct DispositionFacts<'a> {
    recovery: &'a Recovery,
    ownership: Ownership,
    hazard: Option<Hazard>,
    confidence: Confidence,
    measurement_complete: bool,
}

impl<'a> DispositionFacts<'a> {
    pub(crate) fn from_candidate(candidate: &'a FindingCandidate, confidence: Confidence) -> Self {
        Self {
            recovery: &candidate.recovery,
            ownership: candidate.ownership,
            hazard: candidate.hazard,
            confidence,
            measurement_complete: candidate.skipped == 0
                && !candidate.truncated
                && candidate.unvisited_dirs == 0,
        }
    }
}

/// The only place deletion authority is derived. Precedence: recovery (what
/// the data IS) > ownership > confidence > measurement > hazard > cost.
pub(crate) fn derive(facts: DispositionFacts<'_>) -> Disposition {
    let (mode, reason) = if let Some(reason) = report_only_reason(facts) {
        (DispositionMode::ReportOnly, Some(reason))
    } else if let Some(reason) = opt_in_reason(facts) {
        (DispositionMode::OptIn, Some(reason))
    } else {
        (DispositionMode::Eligible, None)
    };
    Disposition {
        mode,
        reason: reason.map(str::to_owned),
    }
}

/// Facts deriving to report-only defer the root. Static facts only:
/// confidence and measurement are runtime evidence the collector layers on
/// separately.
pub fn scan_priority(facts: FindingFacts) -> ScanPriority {
    let (recovery, ownership, hazard) = facts;
    let disposition = derive(DispositionFacts {
        recovery: &recovery,
        ownership,
        hazard,
        confidence: Confidence::Verified,
        measurement_complete: true,
    });
    match disposition.mode {
        DispositionMode::ReportOnly => ScanPriority::Deferred,
        DispositionMode::OptIn | DispositionMode::Eligible => ScanPriority::Preferred,
    }
}

fn report_only_reason(facts: DispositionFacts<'_>) -> Option<&'static str> {
    let stronger_reason = match (facts.recovery, facts.ownership, facts.confidence) {
        (Recovery::Unknown, _, _) => Some(UNKNOWN_RECOVERY),
        (Recovery::UserAsset, _, _) => Some(USER_ASSET),
        (_, Ownership::ToolCoordinated, _) => Some(TOOL_MANAGED),
        (_, Ownership::Unknown, _) => Some(UNKNOWN_OWNERSHIP),
        (_, _, Confidence::Unverified) => Some(UNVERIFIED_REDIRECT),
        _ => None,
    };
    if stronger_reason.is_some() {
        return stronger_reason;
    }
    (!facts.measurement_complete).then_some(INCOMPLETE_MEASUREMENT)
}

fn opt_in_reason(facts: DispositionFacts<'_>) -> Option<&'static str> {
    match (facts.hazard, facts.recovery) {
        (Some(Hazard::BreaksConsumers), _) => Some(BREAKS_CONSUMERS),
        (Some(Hazard::ActiveUse), _) => Some(ACTIVE_USE),
        (
            None,
            Recovery::Regenerable {
                cost: RegenCost::Costly,
            },
        ) => Some(COSTLY_REGEN),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERIES: [Recovery; 3] = [
        Recovery::UserAsset,
        Recovery::Regenerable {
            cost: RegenCost::Cheap,
        },
        Recovery::Regenerable {
            cost: RegenCost::Costly,
        },
    ];
    const OWNERSHIPS: [Ownership; 2] = [Ownership::Standalone, Ownership::ToolCoordinated];
    const HAZARDS: [Option<Hazard>; 3] =
        [None, Some(Hazard::BreaksConsumers), Some(Hazard::ActiveUse)];
    const CONFIDENCES: [Confidence; 2] = [Confidence::Verified, Confidence::Unverified];
    const CASE_COUNT: usize = 36;

    #[derive(Clone, Copy)]
    enum ExpectedRule {
        UserAsset,
        ToolCoordinated,
        Unverified,
        BreaksConsumers,
        ActiveUse,
        Costly,
        Eligible,
    }

    use ExpectedRule::*;

    const EXPECTED: [ExpectedRule; CASE_COUNT] = [
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        UserAsset,
        Eligible,
        Unverified,
        BreaksConsumers,
        Unverified,
        ActiveUse,
        Unverified,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        Costly,
        Unverified,
        BreaksConsumers,
        Unverified,
        ActiveUse,
        Unverified,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
        ToolCoordinated,
    ];

    impl ExpectedRule {
        fn disposition(self) -> Disposition {
            let (mode, reason) = match self {
                Self::UserAsset => (
                    DispositionMode::ReportOnly,
                    Some("user asset: degu cannot recreate it"),
                ),
                Self::ToolCoordinated => (
                    DispositionMode::ReportOnly,
                    Some("managed by the owning tool; delete through it"),
                ),
                Self::Unverified => (
                    DispositionMode::ReportOnly,
                    Some("relocated via an environment variable degu cannot verify"),
                ),
                Self::BreaksConsumers => (
                    DispositionMode::OptIn,
                    Some("deletion can break software that links into this data"),
                ),
                Self::ActiveUse => (
                    DispositionMode::OptIn,
                    Some("deletion can disrupt active sessions using this data"),
                ),
                Self::Costly => (DispositionMode::OptIn, Some("costly to regenerate")),
                Self::Eligible => (DispositionMode::Eligible, None),
            };
            Disposition {
                mode,
                reason: reason.map(str::to_string),
            }
        }
    }

    #[test]
    fn scan_priority_defers_exactly_the_static_report_only_classes() {
        let cheap = Recovery::Regenerable {
            cost: RegenCost::Cheap,
        };
        let costly = Recovery::Regenerable {
            cost: RegenCost::Costly,
        };
        let preferred = [
            (cheap, Ownership::Standalone, None),
            (costly, Ownership::Standalone, None),
            (cheap, Ownership::Standalone, Some(Hazard::BreaksConsumers)),
            (cheap, Ownership::Standalone, Some(Hazard::ActiveUse)),
        ];
        let deferred = [
            (Recovery::Unknown, Ownership::Standalone, None),
            (Recovery::UserAsset, Ownership::Standalone, None),
            (cheap, Ownership::ToolCoordinated, None),
            (costly, Ownership::Unknown, None),
            (
                Recovery::UserAsset,
                Ownership::ToolCoordinated,
                Some(Hazard::ActiveUse),
            ),
        ];
        for facts in preferred {
            assert_eq!(scan_priority(facts), ScanPriority::Preferred, "{facts:?}");
        }
        for facts in deferred {
            assert_eq!(scan_priority(facts), ScanPriority::Deferred, "{facts:?}");
        }
    }

    #[test]
    fn derive_exhaustive_known_fact_table() {
        let mut actual = Vec::with_capacity(CASE_COUNT);
        for recovery in RECOVERIES {
            for ownership in OWNERSHIPS {
                for hazard in HAZARDS {
                    actual.extend(CONFIDENCES.map(|confidence| {
                        derive(DispositionFacts {
                            recovery: &recovery,
                            ownership,
                            hazard,
                            confidence,
                            measurement_complete: true,
                        })
                    }));
                }
            }
        }

        let expected = EXPECTED.map(ExpectedRule::disposition);
        assert_eq!(actual, expected);
        for disposition in &actual {
            if let Some(reason) = &disposition.reason {
                assert!(STATIC_REASONS.contains(&reason.as_str()), "{reason}");
            }
        }
    }

    #[test]
    fn unknown_recovery_precedes_other_facts() {
        for ownership in [
            Ownership::Unknown,
            Ownership::Standalone,
            Ownership::ToolCoordinated,
        ] {
            for hazard in HAZARDS {
                for confidence in CONFIDENCES {
                    let disposition = derive(DispositionFacts {
                        recovery: &Recovery::Unknown,
                        ownership,
                        hazard,
                        confidence,
                        measurement_complete: true,
                    });
                    assert_eq!(disposition.mode, DispositionMode::ReportOnly);
                    assert_eq!(
                        disposition.reason.as_deref(),
                        Some("recovery requirements are unknown")
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_ownership_yields_only_to_recovery_facts() {
        for recovery in RECOVERIES {
            let expected = match recovery {
                Recovery::UserAsset => "user asset: degu cannot recreate it",
                _ => "ownership and coordination requirements are unknown",
            };
            for hazard in HAZARDS {
                for confidence in CONFIDENCES {
                    let disposition = derive(DispositionFacts {
                        recovery: &recovery,
                        ownership: Ownership::Unknown,
                        hazard,
                        confidence,
                        measurement_complete: true,
                    });
                    assert_eq!(disposition.mode, DispositionMode::ReportOnly);
                    assert_eq!(disposition.reason.as_deref(), Some(expected));
                }
            }
        }
    }

    #[test]
    fn incomplete_measurement_is_report_only_without_masking_stronger_facts() {
        let cases = [
            (
                Recovery::Regenerable {
                    cost: RegenCost::Cheap,
                },
                Ownership::Standalone,
                "measurement incomplete: some paths were not measured",
            ),
            (
                Recovery::Regenerable {
                    cost: RegenCost::Costly,
                },
                Ownership::Standalone,
                "measurement incomplete: some paths were not measured",
            ),
            (
                Recovery::UserAsset,
                Ownership::Standalone,
                "user asset: degu cannot recreate it",
            ),
            (
                Recovery::Regenerable {
                    cost: RegenCost::Cheap,
                },
                Ownership::ToolCoordinated,
                "managed by the owning tool; delete through it",
            ),
        ];
        for (recovery, ownership, reason) in cases {
            let disposition = derive(DispositionFacts {
                recovery: &recovery,
                ownership,
                hazard: None,
                confidence: Confidence::Verified,
                measurement_complete: false,
            });
            assert_eq!(disposition.mode, DispositionMode::ReportOnly);
            assert_eq!(disposition.reason.as_deref(), Some(reason));
            assert!(STATIC_REASONS.contains(&reason), "{reason}");
        }
    }

    #[test]
    fn authority_rank_orders_stricter_reasons_above_weaker_ones() {
        let stricter = authority_rank(&Disposition {
            mode: DispositionMode::OptIn,
            reason: Some(BREAKS_CONSUMERS.to_owned()),
        });
        let weaker = authority_rank(&Disposition {
            mode: DispositionMode::OptIn,
            reason: Some(COSTLY_REGEN.to_owned()),
        });
        assert!(stricter > weaker);
        let eligible = authority_rank(&Disposition {
            mode: DispositionMode::Eligible,
            reason: None,
        });
        assert_eq!(eligible, (0, 0));
    }
}
