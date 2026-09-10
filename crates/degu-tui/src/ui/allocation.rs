use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::browser::Browser;
use crate::escape;
use crate::report::Total;

use super::App;
use super::format::bytes_total;
use super::text::{columns, pad};
use super::theme::{self, panel};

const NAMED_SEGMENTS: usize = 4;
const COLORS: [Color; NAMED_SEGMENTS + 1] = [
    theme::ACCENT,
    theme::REVIEW,
    theme::READY,
    theme::ROSE,
    theme::UNMANAGED,
];
const LEGEND_GAP: usize = 3;
const PERCENT_WIDTH: usize = 8;
const PERCENT_SCALE: f64 = 100.0;

pub struct Segment {
    pub name: String,
    pub total: Total,
}

pub fn segments(browser: &Browser) -> Vec<Segment> {
    let groups = browser.ecosystem_groups();
    let mut segments = groups
        .iter()
        .take(NAMED_SEGMENTS)
        .map(|group| Segment {
            name: escape::text(&group.name),
            total: group.allocated,
        })
        .collect::<Vec<_>>();
    let remaining = &groups[groups.len().min(NAMED_SEGMENTS)..];
    if !remaining.is_empty() {
        let mut total = Total::of(remaining.iter().map(|group| group.allocated.value));
        total.saturated |= remaining.iter().any(|group| group.allocated.saturated);
        segments.push(Segment {
            name: format!("other ({} ecosystems)", remaining.len()),
            total,
        });
    }
    segments
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let block = panel("reported allocation").border_style(Style::new().fg(theme::READY));
    let width = usize::from(block.inner(area).width);
    let mut lines = vec![stack(app, width), Line::default()];
    lines.extend(app.allocation().iter().enumerate().map(|(index, segment)| {
        let value = bytes_total(segment.total);
        let name_width = width.saturating_sub(columns(&value) + LEGEND_GAP);
        Line::from(vec![
            Span::styled(
                format!("▪ {}", pad(&segment.name, name_width)),
                Style::new().fg(COLORS[index]),
            ),
            Span::raw(format!(" {value}")),
        ])
    }));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn stack(app: &App, width: usize) -> Line<'static> {
    let browser = app.browser();
    if browser.allocated().saturated {
        return Line::from("Share unavailable: total overflow").fg(theme::SECONDARY);
    }
    if browser.allocated().value == 0 {
        return Line::from("No allocated bytes measured").fg(theme::SECONDARY);
    }
    let mut cumulative = 0_u128;
    let mut previous = 0;
    let spans = app
        .allocation()
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            cumulative += u128::from(segment.total.value);
            let end = (cumulative * width as u128 / u128::from(browser.allocated().value)) as usize;
            let span = Span::styled("█".repeat(end - previous), Style::new().fg(COLORS[index]));
            previous = end;
            span
        })
        .collect::<Vec<_>>();
    Line::from(spans)
}

pub fn selected_share(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let Some(finding) = browser.selected_finding() else {
        return;
    };
    let block = panel("selected / share within report");
    let width = usize::from(block.inner(area).width);
    let line = if browser.allocated().saturated || browser.allocated().value == 0 {
        let message = if browser.allocated().saturated {
            "Share unavailable: total overflow"
        } else {
            "No allocated bytes measured"
        };
        Line::from(message).fg(theme::SECONDARY)
    } else {
        let ratio = finding.bytes_allocated as f64 / browser.allocated().value as f64;
        let bar_width = width.saturating_sub(PERCENT_WIDTH);
        let filled = (ratio * bar_width as f64).round() as usize;
        Line::from(vec![
            Span::styled("━".repeat(filled), Style::new().fg(theme::ACCENT)),
            Span::styled("─".repeat(bar_width - filled), Style::new().fg(theme::EDGE)),
            Span::styled(
                format!(" {:>5.1}%", ratio * PERCENT_SCALE),
                Style::new().fg(theme::ACCENT),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(line).block(block), area);
}
