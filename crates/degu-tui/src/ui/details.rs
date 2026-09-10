use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::escape;
use crate::report::{Class, Finding, Section};

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
    pub fn new(finding: &Finding, section: Section) -> Self {
        let introduction = introduction(finding, section);
        let source = content(finding, &introduction);
        let preview = preview(finding, section);
        Self {
            label: escape::text(&finding.ecosystem),
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
    let bound = if finding.skipped > 0 { "≥" } else { "" };
    let age = finding
        .age_days
        .map_or_else(|| "unknown".to_owned(), |days| format!("{days}d"));
    format!(
        "allocated {bound}{} · age {age}",
        format::bytes(finding.bytes_allocated)
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

fn preview(finding: &Finding, section: Section) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Class::of(finding, section).label())
            .style(class_style(Class::of(finding, section))),
        Line::from(escape::text(&finding.path)).bold(),
    ];
    if finding.skipped > 0 {
        lines.push(
            Line::from(format!(
                "! {} skipped · allocated ≥{}",
                format::count(finding.skipped),
                format::bytes(finding.bytes_allocated)
            ))
            .fg(CAUTION),
        );
    }
    let reason = if finding.disposition.reason.is_empty() {
        &finding.rationale
    } else {
        &finding.disposition.reason
    };
    lines.push(Line::from(escape::text(reason)).fg(SECONDARY));
    lines
}

fn reflow(source: &[Line<'static>], width: u16) -> Vec<Line<'static>> {
    source
        .iter()
        .flat_map(|line| {
            wrapped(&line.to_string(), usize::from(width))
                .into_iter()
                .map(|text| Line::from(text).style(line.style))
        })
        .collect()
}

fn introduction(finding: &Finding, section: Section) -> Vec<Line<'static>> {
    let class = Class::of(finding, section);
    let reason = escape::text(&finding.disposition.reason);
    let status = if reason.is_empty() {
        class.label().to_owned()
    } else {
        format!("{} · {reason}", class.label())
    };
    vec![
        Line::from(escape::text(&finding.path)).bold(),
        Line::from(status).style(class_style(class)),
    ]
}

fn content(finding: &Finding, introduction: &[Line<'static>]) -> Vec<Line<'static>> {
    let mut lines = introduction.to_vec();
    lines.extend([
        Line::default(),
        heading("Storage"),
        Line::from(sizes(finding)),
        Line::from(other_measurements(finding)),
        Line::default(),
        heading("Why this status"),
        Line::from(escape::text(&finding.rationale)),
        Line::default(),
        heading("Classification"),
    ]);
    lines.extend(metadata(finding).into_iter().map(Line::from));
    lines
}

fn heading(label: &'static str) -> Line<'static> {
    Line::from(label).fg(SECONDARY).bold()
}

fn sizes(finding: &Finding) -> String {
    let floor = if finding.skipped > 0 { "≥" } else { "" };
    format!(
        "Allocated {floor}{} · Apparent {} · Inodes {}",
        format::bytes(finding.bytes_allocated),
        format::bytes(finding.bytes_apparent),
        format::count(finding.inodes),
    )
}

fn other_measurements(finding: &Finding) -> String {
    let age = finding
        .age_days
        .map_or_else(|| "unknown".to_owned(), |days| format!("{days}d"));
    format!(
        "Hardlinked {} · age {age} · {} skipped",
        format::bytes(finding.bytes_hardlinked),
        format::count(finding.skipped)
    )
}

fn metadata(finding: &Finding) -> Vec<String> {
    let recovery = finding
        .recovery
        .as_ref()
        .map_or("unknown", |recovery| recovery.kind.as_str());
    [
        ("Ecosystem", finding.ecosystem.as_str()),
        ("Kind", finding.kind.as_str()),
        ("Disposition", finding.disposition.mode.as_str()),
        ("Recovery", recovery),
        ("Ownership", finding.ownership.as_str()),
        ("Confidence", finding.confidence.as_str()),
    ]
    .into_iter()
    .map(|(label, value)| format!("{label}: {}", escape::text(value)))
    .collect()
}
