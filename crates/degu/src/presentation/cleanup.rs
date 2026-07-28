use super::lower_bound_bytes;
use crate::runtime::{Glyphs, Headline, HeadlineLead, Ui};
use degu_core::disposition::{
    ACTIVE_USE, BREAKS_CONSUMERS, COSTLY_REGEN, INCOMPLETE_MEASUREMENT, TOOL_MANAGED,
    UNKNOWN_OWNERSHIP, UNKNOWN_RECOVERY, UNVERIFIED_REDIRECT, USER_ASSET,
};
use degu_core::finding::{DispositionMode, Finding};
use degu_core::safety::{MIXED_STATE_AI_TOOL_REASON, PROTECTED_CREDENTIAL_REASON};

const REVIEW_EXPLANATION: &str = "Excluded by default; preview a path before including it.";
const UNMANAGED_EXPLANATION: &str = "Reported only; degu never cleans these locations.";

pub(crate) fn label(mode: DispositionMode) -> &'static str {
    match mode {
        DispositionMode::Eligible => "Ready to clean",
        DispositionMode::OptIn => "Needs review",
        DispositionMode::ReportOnly => "Not managed",
    }
}

/// Safety-contract sentence under a group header. "Ready to clean" carries
/// its whole contract in the label, so it takes none.
pub(crate) fn explanation(mode: DispositionMode) -> Option<&'static str> {
    match mode {
        DispositionMode::Eligible => None,
        DispositionMode::OptIn => Some(REVIEW_EXPLANATION),
        DispositionMode::ReportOnly => Some(UNMANAGED_EXPLANATION),
    }
}

/// Short table-cell phrase for an authority reason sentence; `ecosystem`
/// names the owning tool for tool-managed findings. JSON and detail views
/// keep the full sentence.
pub(crate) fn short_reason(reason: &str, ecosystem: &str) -> Option<String> {
    let phrase = match reason {
        USER_ASSET => "user asset",
        TOOL_MANAGED => return Some(format!("managed by {ecosystem}")),
        UNVERIFIED_REDIRECT => "unverified redirect",
        UNKNOWN_RECOVERY => "no verified recovery",
        UNKNOWN_OWNERSHIP => "unknown ownership",
        INCOMPLETE_MEASUREMENT => "incomplete measurement",
        BREAKS_CONSUMERS => "breaks consumers",
        ACTIVE_USE => "active use",
        COSTLY_REGEN => "costly to regenerate",
        MIXED_STATE_AI_TOOL_REASON => "contains protected AI tool state",
        PROTECTED_CREDENTIAL_REASON => "contains protected credentials",
        _ => return None,
    };
    Some(phrase.to_owned())
}

/// One group of findings as the group header renders it: the disposition
/// label plus the count/size stats that follow it, under an outer indent
/// when the group nests inside another block.
pub(crate) struct Group<'a> {
    pub(crate) label: &'a str,
    pub(crate) mode: DispositionMode,
    pub(crate) stats: FindingStats,
    pub(crate) scan_lower_bound: bool,
    pub(crate) indent: u16,
}

/// Shared "<label> · <count> locations · <size>" header for the scan sections
/// and clean plan/exclusion summaries. Bytes are the decision datum: they keep
/// the header tone while the count stays dimmed; layout follows [`Ui::headline`].
pub(crate) fn group_header(ui: Ui, group: Group<'_>) -> String {
    ui.headline(
        Headline::new(group.label, HeadlineLead::Separator)
            .label_tone(super::semantic::disposition_tone(group.mode))
            .indent(group.indent)
            .stat(group.stats.locations_label())
            .stat_toned(
                group.stats.bytes_label(group.scan_lower_bound, ui.glyphs),
                super::semantic::disposition_tone(group.mode),
            ),
    )
}

pub(crate) fn inode_count_label(lower_bound: bool, inodes: u64, glyphs: Glyphs) -> String {
    if lower_bound {
        format!("{} {inodes}", glyphs.lower_bound)
    } else {
        inodes.to_string()
    }
}

pub(crate) fn inode_total_label(lower_bound: bool, inodes: u64, glyphs: Glyphs) -> String {
    let noun = if inodes == 1 { "inode" } else { "inodes" };
    format!("{} {noun}", inode_count_label(lower_bound, inodes, glyphs))
}

#[derive(Clone, Copy, Default)]
pub(crate) struct FindingStats {
    bytes: u64,
    inodes: u64,
    locations: usize,
    lower_bound: bool,
}

impl FindingStats {
    pub(crate) fn from_findings(findings: &[Finding]) -> Self {
        Self::collect(findings.iter())
    }

    pub(crate) fn collect<'a>(findings: impl Iterator<Item = &'a Finding>) -> Self {
        findings.fold(Self::default(), |mut stats, finding| {
            stats.add(finding);
            stats
        })
    }

    pub(crate) fn has_bytes(self) -> bool {
        self.bytes > 0
    }

    pub(crate) fn bytes_label(self, scan_lower_bound: bool, glyphs: Glyphs) -> String {
        lower_bound_bytes(scan_lower_bound || self.lower_bound, self.bytes, glyphs)
    }

    pub(crate) fn locations_label(self) -> String {
        count_label(self.locations, "location", "locations")
    }

    pub(crate) fn inodes_label(self, scan_lower_bound: bool, glyphs: Glyphs) -> String {
        inode_total_label(scan_lower_bound || self.lower_bound, self.inodes, glyphs)
    }

    fn add(&mut self, finding: &Finding) {
        self.bytes = self.bytes.saturating_add(finding.bytes_allocated());
        self.inodes = self.inodes.saturating_add(finding.inodes());
        self.locations = self.locations.saturating_add(1);
        self.lower_bound |= finding.measurement_incomplete();
    }
}

pub(crate) fn count_label(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

pub(crate) fn lower_bound_count_label(
    lower_bound: bool,
    count: usize,
    singular: &str,
    plural: &str,
    glyphs: Glyphs,
) -> String {
    let label = count_label(count, singular, plural);
    if lower_bound {
        format!("{} {label}", glyphs.lower_bound)
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    use super::{FindingStats, Group, group_header, short_reason};
    use crate::runtime::Ui;
    use degu_core::finding::DispositionMode;

    const READY_BYTES: u64 = 3_355_443;

    fn ready_group() -> Group<'static> {
        Group {
            label: "Ready to clean",
            mode: DispositionMode::Eligible,
            stats: FindingStats {
                bytes: READY_BYTES,
                inodes: 4,
                locations: 2,
                lower_bound: false,
            },
            scan_lower_bound: false,
            indent: 0,
        }
    }

    #[test]
    fn group_header_fits_one_line_on_a_wide_terminal() {
        assert_eq!(
            group_header(Ui::test_terminal(80), ready_group()),
            "Ready to clean · 2 locations · 3.2 MiB"
        );
    }

    #[test]
    fn group_header_keeps_the_outer_indent_on_every_line() {
        let group = Group {
            indent: 2,
            ..ready_group()
        };
        assert_eq!(
            group_header(Ui::test_terminal(24), group),
            "  Ready to clean\n    2 locations\n    3.2 MiB"
        );
        let group = Group {
            indent: 2,
            ..ready_group()
        };
        assert_eq!(
            group_header(Ui::test_pipe(24), group),
            "  Ready to clean - 2 locations - 3.2 MiB"
        );
    }

    #[test]
    fn every_exported_reason_has_a_short_phrase() {
        let reasons = degu_core::disposition::STATIC_REASONS.into_iter().chain([
            degu_core::safety::MIXED_STATE_AI_TOOL_REASON,
            degu_core::safety::PROTECTED_CREDENTIAL_REASON,
        ]);
        for reason in reasons {
            assert!(
                short_reason(reason, "uv").is_some(),
                "reason {reason:?} has no short phrase"
            );
        }
        assert_eq!(short_reason("some future reason", "uv"), None);
    }

    #[test]
    fn short_reasons_read_as_human_phrases() {
        for (reason, ecosystem, expected) in [
            (degu_core::disposition::TOOL_MANAGED, "uv", "managed by uv"),
            (
                degu_core::disposition::TOOL_MANAGED,
                "conda",
                "managed by conda",
            ),
            (
                degu_core::disposition::UNKNOWN_RECOVERY,
                "uv",
                "no verified recovery",
            ),
            (
                degu_core::safety::MIXED_STATE_AI_TOOL_REASON,
                "uv",
                "contains protected AI tool state",
            ),
        ] {
            assert_eq!(short_reason(reason, ecosystem).as_deref(), Some(expected));
        }
    }
}
