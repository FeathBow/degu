use std::path::Path;

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::presentation::escape_terminal_text;
use crate::tui::report::{Class, Finding, Section};

use super::format;

use super::text::{columns, elide, wrapped};
use super::theme::{CAUTION, SECONDARY, class_style, panel};

/// Only the selected record is formatted, and reflow happens only on resize.
#[derive(Default)]
pub struct Document {
    label: String,
    summary: String,
    source: Vec<Line<'static>>,
    preview: Vec<Line<'static>>,
    lines: Vec<Line<'static>>,
    preview_lines: Vec<Line<'static>>,
    width: u16,
    offset: usize,
    page_size: usize,
}

impl Document {
    pub fn new(
        finding: &Finding,
        section: Section,
        home: &Path,
        advisories: &crate::advisory::Advisories,
    ) -> Self {
        let introduction = introduction(finding, section, home);
        let source = content(finding, &introduction, advisories);
        let preview = preview(finding, section, home, advisories);
        Self {
            label: escape_terminal_text(finding.ecosystem()),
            summary: preview_summary(finding),
            source,
            preview,
            ..Self::default()
        }
    }

    fn prepare(&mut self, size: Size) {
        if self.width != size.width {
            self.width = size.width;
            self.lines = reflow(&self.source, size.width);
            self.preview_lines = preview_lines(&self.preview, &self.summary, size.width);
        }
        self.page_size = usize::from(size.height);
        self.offset = self.offset.min(self.last_offset());
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    fn last_offset(&self) -> usize {
        self.lines.len().saturating_sub(self.page_size)
    }

    pub fn move_by(&mut self, delta: isize) {
        self.offset = self
            .offset
            .saturating_add_signed(delta)
            .min(self.last_offset());
    }

    pub fn first(&mut self) {
        self.offset = 0;
    }

    pub fn last(&mut self) {
        self.offset = self.last_offset();
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, expanded: bool) {
        let inner = panel("").inner(area);
        self.prepare(inner.as_size());
        let offset = if expanded { self.offset } else { 0 };
        let end = (offset + self.page_size).min(self.lines.len());
        let title = if expanded {
            format!(
                "Details · lines {}–{} / {}",
                offset + 1,
                end,
                self.lines.len()
            )
        } else {
            let prefix = "3 Selected · ";
            let budget = usize::from(inner.width).saturating_sub(columns(prefix));
            format!("{prefix}{}", elide(&self.label, budget))
        };
        let mut block = panel(title);
        if !expanded {
            block = block.title_bottom(
                Line::from(" Enter for full record ")
                    .fg(SECONDARY)
                    .right_aligned(),
            );
        }
        let source = if expanded {
            &self.lines
        } else {
            &self.preview_lines
        };
        let lines = source
            .iter()
            .skip(offset)
            .take(self.page_size)
            .cloned()
            .collect::<Vec<_>>();
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }
}

fn preview_summary(finding: &Finding) -> String {
    let bound = if finding.skipped() > 0 { "≥" } else { "" };
    let age = finding
        .age_days()
        .map_or_else(|| "unknown".to_owned(), |days| format!("{days}d"));
    format!(
        "allocated {bound}{} · age {age}",
        format::bytes(finding.bytes_allocated())
    )
}

fn preview_lines(source: &[Line<'static>], summary: &str, width: u16) -> Vec<Line<'static>> {
    const MIN_METADATA_WIDTH: u16 = 75;
    const MIN_GAP: usize = 3;
    let mut lines = reflow(source, width);
    let Some(first) = lines.first_mut() else {
        return lines;
    };
    let used = columns(&first.to_string()) + columns(summary);
    if width >= MIN_METADATA_WIDTH && usize::from(width) >= used + MIN_GAP {
        first.spans.push(Span::styled(
            format!("{}{summary}", " ".repeat(usize::from(width) - used)),
            Style::new().fg(SECONDARY),
        ));
    }
    lines
}

fn preview(
    finding: &Finding,
    section: Section,
    home: &Path,
    advisories: &crate::advisory::Advisories,
) -> Vec<Line<'static>> {
    let class = Class::of(finding, section);
    let mut lines = vec![
        Line::from(class.label()).style(class_style(class)),
        Line::from(escape_terminal_text(&crate::presentation::display_path(
            finding.path(),
            home,
        )))
        .bold(),
    ];
    if finding.skipped() > 0 {
        lines.push(
            Line::from(format!(
                "! {} skipped · allocated ≥{}",
                format::count(finding.skipped()),
                format::bytes(finding.bytes_allocated())
            ))
            .fg(CAUTION),
        );
    }
    let reason = finding
        .disposition()
        .reason
        .as_deref()
        .unwrap_or_else(|| finding.rationale());
    lines.push(Line::from(escape_terminal_text(reason)).fg(SECONDARY));
    // A pointer, not the advisory. Browsing a list is where a reader decides
    // which record to open, and an advisory nobody knows about is one nobody
    // reads; putting its text here instead would let a sentence degu does not
    // stand behind sit in the same column as the classifications it does.
    if !advisories.disabled()
        && crate::advisory::is_unrecognized(finding)
        && advisories.for_path(finding.path()).is_some()
    {
        lines.push(
            Line::from("an AI advisory is available - Enter for the full record").fg(CAUTION),
        );
    }
    lines
}

fn reflow(source: &[Line<'static>], width: u16) -> Vec<Line<'static>> {
    source
        .iter()
        .flat_map(|line| {
            let text = line.to_string();
            match text.strip_prefix(ADVISORY_MARK) {
                Some(body) => marked(body, line.style, width),
                None => wrapped(&text, usize::from(width))
                    .into_iter()
                    .map(|text| Line::from(text).style(line.style))
                    .collect(),
            }
        })
        .collect()
}

/// Re-marks every line a wrap produces.
///
/// The mark says a foreign program wrote these characters, so it has to reach
/// every line those characters land on, and a wrapped continuation is one of
/// them. Colour survives reflow on its own; a captured pane, a `--color never`
/// transcript and a reader who cannot see colour have only the mark.
fn marked(body: &str, style: Style, width: u16) -> Vec<Line<'static>> {
    let inner = usize::from(width)
        .saturating_sub(columns(ADVISORY_MARK))
        .max(1);
    wrapped(body, inner)
        .into_iter()
        .map(|text| Line::from(format!("{ADVISORY_MARK}{text}")).style(style))
        .collect()
}

fn introduction(finding: &Finding, section: Section, home: &Path) -> Vec<Line<'static>> {
    let class = Class::of(finding, section);
    let reason = finding
        .disposition()
        .reason
        .as_deref()
        .map(escape_terminal_text)
        .unwrap_or_default();
    let status = if reason.is_empty() {
        class.label().to_owned()
    } else {
        format!("{} · {reason}", class.label())
    };
    vec![
        Line::from(escape_terminal_text(&crate::presentation::display_path(
            finding.path(),
            home,
        )))
        .bold(),
        Line::from(status).style(class_style(class)),
    ]
}

fn content(
    finding: &Finding,
    introduction: &[Line<'static>],
    advisories: &crate::advisory::Advisories,
) -> Vec<Line<'static>> {
    let mut lines = introduction.to_vec();
    lines.extend([
        Line::default(),
        heading("Measured by degu"),
        Line::from(sizes(finding)),
        Line::from(other_measurements(finding)),
        Line::default(),
        heading("Why this status - degu"),
        Line::from(escape_terminal_text(finding.rationale())),
        Line::default(),
        heading("Classification"),
    ]);
    lines.extend(metadata(finding).into_iter().map(Line::from));
    lines.extend(advisory(finding, advisories));
    lines
}

/// How much of the advisor's path the attribution line may spend.
///
/// An advisor under the account home reads as `~/.config/degu/advisor` and fits
/// anywhere. One named somewhere deeper would otherwise wrap the attribution
/// across three lines of a small pane, which buys nothing: the tail identifies
/// the file, and the whole path is one `degu config` away.
const ADVISOR_NAME_BUDGET: usize = 48;

/// Marks characters a foreign program wrote, and nothing else.
///
/// A pane scrolls and a heading does not travel with the text under it, so the
/// mark repeats on every line the advisor produced. degu's own lines inside the
/// same block — who answered, that nobody did, that an answer came without a way
/// to check it — never carry it: a mark that sometimes means "degu wrote this
/// about an advisor" stops distinguishing anything.
const ADVISORY_MARK: &str = "~ ";

/// The advisory block, which appears only where a reader is actually stuck.
///
/// degu classified everything else, so an advisory there would be a second
/// opinion about a settled question. Here there is no degu answer, which is why
/// the section exists and why its heading has to say that what follows is not
/// one.
fn advisory(finding: &Finding, advisories: &crate::advisory::Advisories) -> Vec<Line<'static>> {
    use crate::advisory::Unavailable;

    if advisories.disabled() || !crate::advisory::is_unrecognized(finding) {
        return Vec::new();
    }
    let mut lines = vec![
        Line::default(),
        Line::from("AI advisory - unverified, not a degu classification")
            .fg(CAUTION)
            .bold(),
    ];
    match (
        advisories.for_path(finding.path()),
        advisories.unavailable(),
    ) {
        (Some(advice), _) => {
            if let Some(source) = advisories.source() {
                lines.push(
                    Line::from(format!(
                        "answered by {}",
                        elide(&escape_terminal_text(source), ADVISOR_NAME_BUDGET)
                    ))
                    .fg(SECONDARY),
                );
            }
            lines.push(Line::from(format!("{ADVISORY_MARK}{}", advice.summary)).fg(CAUTION));
            match advice.check.as_deref() {
                Some(check) => lines
                    .push(Line::from(format!("{ADVISORY_MARK}to check, run: {check}")).fg(CAUTION)),
                // Without one the reader has only the advisor's confidence,
                // which is not evidence and is not presented as any.
                None => lines.push(
                    Line::from(format!(
                        "{ADVISORY_MARK}no way to check this was offered; treat it as a hint"
                    ))
                    .fg(SECONDARY),
                ),
            }
        }
        // Where a script goes, rather than which key to set: the answer to
        // "can something tell me what this is" is an executable the reader
        // already trusts, and naming the place is the whole instruction.
        (None, Some(Unavailable::Absent(convention))) => lines.push(
            Line::from(format!(
                "no advisor here; put an executable at {} and it is used",
                escape_terminal_text(&convention.display().to_string())
            ))
            .fg(SECONDARY),
        ),
        (None, Some(Unavailable::Refused(reason))) => {
            lines.push(Line::from(escape_terminal_text(reason)).fg(CAUTION))
        }
        (None, Some(Unavailable::Failed(reason))) => lines.push(
            Line::from(format!(
                "the advisor produced nothing: {}",
                escape_terminal_text(reason)
            ))
            .fg(SECONDARY),
        ),
        (None, None) => {
            lines.push(Line::from("the advisor said nothing about this location").fg(SECONDARY));
        }
    }
    lines
}

fn heading(label: &'static str) -> Line<'static> {
    Line::from(label).fg(SECONDARY).bold()
}

fn sizes(finding: &Finding) -> String {
    let floor = if finding.skipped() > 0 { "≥" } else { "" };
    format!(
        "Allocated {floor}{} · Inodes {}",
        format::bytes(finding.bytes_allocated()),
        format::count(finding.inodes()),
    )
}

fn other_measurements(finding: &Finding) -> String {
    let age = finding
        .age_days()
        .map_or_else(|| "unknown".to_owned(), |days| format!("{days}d"));
    format!(
        "Hardlinked {} · age {age} · {} skipped",
        format::bytes(finding.bytes_hardlinked()),
        format::count(finding.skipped())
    )
}

fn metadata(finding: &Finding) -> Vec<String> {
    [
        ("Source", finding.ecosystem()),
        ("Kind", crate::findings::kind_label(finding.kind())),
        (
            "Cleanup reason",
            finding.disposition().reason.as_deref().unwrap_or("-"),
        ),
    ]
    .into_iter()
    .map(|(label, value)| format!("{label}: {}", escape_terminal_text(value)))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{Advice, Advisories, Unavailable};
    use degu_core::finding::{
        FindingCandidate, FindingKind, FindingSource, Ownership, Recovery, RegenCost,
        finalize_findings,
    };
    use std::path::PathBuf;

    const SUBJECT: &str = "/home/account/.cache/mystery";

    fn finding(recovery: Recovery, ownership: Ownership) -> Finding {
        finalize_findings(
            vec![FindingCandidate {
                ecosystem: "artifacts".to_owned(),
                path: PathBuf::from(SUBJECT),
                kind: FindingKind::Other,
                bytes_apparent: 4096,
                bytes_allocated: 4096,
                age_days: Some(30),
                bytes_hardlinked: 0,
                inodes: 1,
                skipped: 0,
                truncated: false,
                unvisited_dirs: 0,
                shared_writable_dirs: 0,
                parent_grants_foreign_mutation: false,
                protected_boundaries: 0,
                protected_credential_boundaries: 0,
                recovery,
                ownership,
                hazard: None,
                rationale: "degu recognized nothing here".to_owned(),
            }],
            FindingSource::WellKnownRoot,
        )
        .pop()
        .expect("one finalized finding")
    }

    fn unrecognized() -> Finding {
        finding(Recovery::Unknown, Ownership::Standalone)
    }

    fn classified() -> Finding {
        finding(
            Recovery::Regenerable {
                cost: RegenCost::Cheap,
            },
            Ownership::Standalone,
        )
    }

    fn advised() -> Advisories {
        Advisories::for_test(
            [(
                PathBuf::from(SUBJECT),
                Advice {
                    summary: "a build cache for some tool".to_owned(),
                    check: Some("tool cache dir".to_owned()),
                },
            )],
            None,
            Some("/opt/bin/advise"),
        )
    }

    fn rendered(finding: &Finding, advisories: &Advisories) -> Vec<String> {
        let introduction = introduction(finding, Section::Cache, Path::new("/home/account"));
        content(finding, &introduction, advisories)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn block(finding: &Finding, advisories: &Advisories) -> Vec<String> {
        advisory(finding, advisories)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The heading is the whole point: a reader scanning the pane has to be able
    /// to tell a sentence degu stands behind from one it is only relaying.
    #[test]
    fn an_advisory_says_it_is_neither_verified_nor_a_classification() {
        let lines = block(&unrecognized(), &advised());
        assert!(
            lines
                .iter()
                .any(|line| line == "AI advisory - unverified, not a degu classification"),
            "{lines:#?}"
        );
    }

    /// A pane scrolls and a heading does not travel with the text under it, so
    /// the mark repeats on every line the advisor produced.
    #[test]
    fn every_line_an_advisor_produced_is_marked() {
        let lines = block(&unrecognized(), &advised());
        assert!(
            lines
                .iter()
                .any(|line| line.contains("a build cache for some tool")
                    && line.starts_with(ADVISORY_MARK)),
            "{lines:#?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("tool cache dir") && line.starts_with(ADVISORY_MARK)),
            "{lines:#?}"
        );
    }

    /// The advisor is named, because "a model said so" and "this program of mine
    /// said so" are different things to the reader deciding.
    /// A deep path is cut to its tail rather than wrapped across the pane; the
    /// whole of it is one `degu config` away.
    #[test]
    fn a_long_advisor_path_is_cut_to_one_line() {
        let deep = format!("/opt/{}/advise", "segment/".repeat(12));
        let advisories = Advisories::for_test(
            [(
                PathBuf::from(SUBJECT),
                Advice {
                    summary: "a cache".to_owned(),
                    check: None,
                },
            )],
            None,
            Some(&deep),
        );
        let attribution = block(&unrecognized(), &advisories)
            .into_iter()
            .find(|line| line.starts_with("answered by"))
            .expect("an attribution line");
        assert!(attribution.contains("advise"), "{attribution}");
        assert!(attribution.contains('…'), "{attribution}");
        assert!(
            super::super::text::columns(&attribution) <= 12 + ADVISOR_NAME_BUDGET,
            "{attribution}"
        );
    }

    /// Naming the advisor is degu reporting who spoke, so it is degu's own line
    /// and must not wear the mark that means an advisor wrote the characters.
    #[test]
    fn the_program_that_answered_is_named_in_degus_voice() {
        let lines = block(&unrecognized(), &advised());
        let attribution = lines
            .iter()
            .find(|line| line.contains("/opt/bin/advise"))
            .expect("the advisor is named");
        assert!(
            !attribution.starts_with(ADVISORY_MARK),
            "degu's attribution wore the advisory mark: {attribution}"
        );
    }

    /// The mark means "a foreign program wrote this". Degu's own measurements and
    /// its own reason must never carry it, or the mark stops meaning anything.
    #[test]
    fn degu_never_marks_its_own_words() {
        let finding = unrecognized();
        // Exactly the two strings the advisor produced in this fixture. Spelled
        // out rather than taken from the advisory, so a line that picks up the
        // mark without being the advisor's words fails here.
        for line in rendered(&finding, &advised()) {
            if line.starts_with(ADVISORY_MARK) {
                assert!(
                    line.contains("a build cache for some tool") || line.contains("tool cache dir"),
                    "degu marked a line it wrote itself: {line}"
                );
            }
        }
        let lines = rendered(&finding, &advised());
        assert!(
            lines.iter().any(|line| line == "Measured by degu"),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|line| line == "Why this status - degu"),
            "{lines:#?}"
        );
    }

    /// degu classified this one. A second opinion about a settled question is
    /// noise at best, and at worst reads as a competing verdict.
    #[test]
    fn a_classified_finding_gets_no_advisory_at_all() {
        assert!(block(&classified(), &advised()).is_empty());
        let lines = rendered(&classified(), &advised());
        assert!(
            !lines.iter().any(|line| line.contains("AI advisory")),
            "{lines:#?}"
        );
    }

    /// Silence would read as "degu has nothing to say", which is not what no
    /// advisor means. The reader is told where one goes, in degu's own voice.
    #[test]
    fn no_advisor_names_the_place_one_would_go() {
        let convention = PathBuf::from("/home/account/.config/degu/advisor");
        let advisories =
            Advisories::for_test([], Some(Unavailable::Absent(convention.clone())), None);
        let lines = block(&unrecognized(), &advisories);
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&convention.display().to_string())),
            "{lines:#?}"
        );
        assert!(
            !lines.iter().any(|line| line.starts_with(ADVISORY_MARK)),
            "degu marked its own explanation as an advisory: {lines:#?}"
        );
    }

    /// A file the reader put there and degu declined to run is not the same as
    /// no file. Skipping it silently would leave them waiting for an advisory
    /// that is never coming.
    #[test]
    fn an_advisor_degu_declined_to_run_is_named_with_its_reason() {
        let advisories = Advisories::for_test(
            [],
            Some(Unavailable::Refused(
                "/home/account/.config/degu/advisor was not run because it is not executable"
                    .to_owned(),
            )),
            None,
        );
        let lines = block(&unrecognized(), &advisories);
        assert!(
            lines.iter().any(|line| line.contains("not executable")),
            "{lines:#?}"
        );
    }

    #[test]
    fn an_advisor_that_failed_is_reported_rather_than_hidden() {
        let advisories = Advisories::for_test(
            [],
            Some(Unavailable::Failed("exceeded its 20s bound".to_owned())),
            Some("/opt/bin/advise"),
        );
        let lines = block(&unrecognized(), &advisories);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("exceeded its 20s bound")),
            "{lines:#?}"
        );
    }

    /// The mark has to reach every line the advisor's characters land on. A
    /// heading does not travel when the pane scrolls, and it does not travel
    /// across a wrap either; colour survives reflow on its own, but a captured
    /// pane, a `--color never` transcript and a reader who cannot see colour
    /// have only the mark.
    #[test]
    fn a_wrapped_advisory_carries_the_mark_on_every_line() {
        let advisories = Advisories::for_test(
            [(
                PathBuf::from(SUBJECT),
                Advice {
                    summary: "layout matches a compile cache that the owning tool regenerates \
                              on its next run, at the cost of recompilation time"
                        .to_owned(),
                    check: None,
                },
            )],
            None,
            Some("~/.config/degu/advisor"),
        );
        let wrapped: Vec<String> = reflow(&advisory(&unrecognized(), &advisories), 40)
            .iter()
            .map(ToString::to_string)
            .collect();
        let body: Vec<&String> = wrapped
            .iter()
            .filter(|line| line.contains("compile cache") || line.contains("recompilation"))
            .collect();
        assert!(body.len() > 1, "the fixture did not wrap: {wrapped:#?}");
        for line in body {
            assert!(
                line.starts_with(ADVISORY_MARK),
                "a wrapped continuation lost the mark: {line:?}"
            );
        }
    }

    /// Browsing is where a reader decides which record to open. An advisory
    /// nobody knows about is one nobody reads.
    #[test]
    fn the_browser_says_an_advisory_is_there_without_quoting_it() {
        let lines: Vec<String> = preview(
            &unrecognized(),
            Section::Cache,
            Path::new("/home/account"),
            &advised(),
        )
        .iter()
        .map(ToString::to_string)
        .collect();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("an AI advisory is available")),
            "{lines:#?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("a build cache for some tool")),
            "the browser quoted the advisory instead of pointing at it: {lines:#?}"
        );
    }

    /// No advisory, no pointer: the row must not promise something the record
    /// does not hold.
    #[test]
    fn the_browser_points_at_nothing_when_there_is_no_advisory() {
        let none = Advisories::for_test([], Some(Unavailable::Absent(PathBuf::from("/x"))), None);
        for (finding, advisories) in [(unrecognized(), &none), (classified(), &advised())] {
            let lines: Vec<String> = preview(
                &finding,
                Section::Cache,
                Path::new("/home/account"),
                advisories,
            )
            .iter()
            .map(ToString::to_string)
            .collect();
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains("advisory is available")),
                "{lines:#?}"
            );
        }
    }

    /// Turning the pane off removes it. A reader who said "not this" must not
    /// keep getting a heading telling them an advisor said nothing — that is a
    /// different statement, and it is the one they turned off.
    #[test]
    fn a_disabled_advisory_draws_no_block() {
        assert!(block(&unrecognized(), &Advisories::disabled_for_test()).is_empty());
    }

    /// An answer with no way to check it is an appeal to the advisor's
    /// confidence. The pane says so rather than letting it read as settled.
    #[test]
    fn an_answer_without_a_check_is_named_a_hint() {
        let advisories = Advisories::for_test(
            [(
                PathBuf::from(SUBJECT),
                Advice {
                    summary: "probably a cache".to_owned(),
                    check: None,
                },
            )],
            None,
            Some("/opt/bin/advise"),
        );
        let lines = block(&unrecognized(), &advisories);
        assert!(
            lines.iter().any(|line| line.contains("treat it as a hint")),
            "{lines:#?}"
        );
    }
}
