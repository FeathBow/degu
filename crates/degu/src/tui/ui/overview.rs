use ratatui::prelude::*;
use ratatui::widgets::{Paragraph, Wrap};

use super::format::{self, bytes_total, count_total, coverage_label, coverage_warning};
use super::text::columns;
use super::theme::{CAUTION, REVIEW, SECONDARY, panel};
use super::{App, allocation, brand};

pub const WIDE_HEIGHT: u16 = 9;
pub const COMPACT_HEIGHT: u16 = 5;
const WIDE_MIN_WIDTH: u16 = 98;
const WIDE_MIN_HEIGHT: u16 = 28;
const TOTAL_WIDTH: u16 = 25;
const SCOPE_WIDTH: u16 = 31;
const GAP: u16 = 1;
const SUMMARY_HEIGHT: u16 = 2;
const SHARE_HEIGHT: u16 = 3;

pub fn is_wide(area: Rect) -> bool {
    area.width >= WIDE_MIN_WIDTH && area.height >= WIDE_MIN_HEIGHT
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    if area.height < WIDE_HEIGHT {
        compact(frame, area, app);
        return;
    }
    let columns = Layout::horizontal([
        Constraint::Length(TOTAL_WIDTH),
        Constraint::Length(GAP),
        Constraint::Min(0),
        Constraint::Length(GAP),
        Constraint::Length(SCOPE_WIDTH),
    ])
    .split(area);
    measured(frame, columns[0], app);
    if browser.coverage().is_requested() {
        allocation::draw(frame, columns[2], app);
    } else {
        frame.render_widget(
            Paragraph::new("No allocation measurements.\nThis section was not scanned.")
                .wrap(Wrap { trim: false })
                .block(panel("reported allocation")),
            columns[2],
        );
    }
    scope(frame, columns[4], app);
}

fn measured(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let block = panel("measured").border_style(Style::new().fg(REVIEW));
    if !browser.coverage().is_requested() {
        frame.render_widget(
            Paragraph::new("Not scanned\nNo measurements").block(block),
            area,
        );
        return;
    }
    let (value, unit) = format::byte_parts(browser.allocated().value);
    let bound = if browser.allocated().saturated {
        "over"
    } else if browser.coverage().is_lower_bound() {
        "≥"
    } else {
        ""
    };
    let mut lines = vec![Line::default()];
    lines.extend(
        brand::number(&value)
            .into_iter()
            .enumerate()
            .map(|(row, line)| {
                let prefix = if row == 1 {
                    format!("{bound:>4} ")
                } else {
                    "     ".to_owned()
                };
                let mut spans = vec![Span::raw(prefix)];
                spans.extend(line.spans);
                Line::from(spans).fg(REVIEW)
            }),
    );
    lines
        .push(Line::from(format!("    {unit} · {} findings", browser.section_len())).fg(SECONDARY));
    lines.push(Line::default());
    lines.push(Line::from(format!("{} inodes", count_total(browser.inodes()))).fg(SECONDARY));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn scope(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let mut lines = vec![Line::default()];
    let coverage = browser.coverage();
    if coverage.is_lower_bound() {
        lines.push(Line::from(format!("! {}", coverage_label(coverage))).fg(CAUTION));
        lines.push(Line::from("totals are a floor"));
    } else {
        lines.extend([Line::from(coverage_label(coverage)), Line::default()]);
    }
    lines.push(Line::default());
    if app.blocked() {
        // Saying "no file moves until you confirm" would be a promise this
        // account cannot keep: nothing moves at all until setup is done. The
        // header names the command that explains which setup is missing.
        lines.push(Line::from("Account setup is needed first.").fg(CAUTION));
    } else {
        lines.push(Line::from("No file moves until you confirm the plan.").fg(SECONDARY));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("report scope")),
        area,
    );
}

fn compact(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let rows = Layout::vertical([
        Constraint::Length(SUMMARY_HEIGHT),
        Constraint::Length(SHARE_HEIGHT),
    ])
    .split(area);
    let mut lines = vec![summary(app, usize::from(area.width))];
    if app.blocked() {
        // The wide layout says this in the scope panel, which this one does
        // not draw. Without it a narrow terminal shows only a missing key.
        lines.push(Line::from(vec![
            Span::styled("! ", Style::new().fg(CAUTION)),
            Span::raw("account setup needed - run 'degu doctor'"),
        ]));
    }
    if let Some(warning) = coverage_warning(browser.coverage()) {
        lines.push(Line::from(vec![
            Span::styled("! ", Style::new().fg(CAUTION)),
            Span::raw(warning),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), rows[0]);
    if browser.coverage().is_requested() {
        allocation::selected_share(frame, rows[1], app);
    }
}

pub fn summary(app: &App, width: usize) -> Line<'static> {
    let browser = app.browser();
    if !browser.coverage().is_requested() {
        return Line::from("Not scanned · no measurements in this report").fg(SECONDARY);
    }
    let bound = if browser.coverage().is_lower_bound() && !browser.allocated().saturated {
        "≥"
    } else {
        ""
    };
    let total = format!("{bound}{}", bytes_total(browser.allocated()));
    let findings = format!(" · {} findings", browser.section_len());
    let inodes = format!(" · {} inodes", count_total(browser.inodes()));
    let show_inodes = columns(&total) + columns(&findings) + columns(&inodes) <= width;
    let mut spans = vec![
        Span::styled(total, Style::new().fg(REVIEW).bold()),
        Span::styled(findings, Style::new().fg(SECONDARY)),
    ];
    if show_inodes {
        spans.push(Span::styled(inodes, Style::new().fg(SECONDARY)));
    }
    Line::from(spans)
}
