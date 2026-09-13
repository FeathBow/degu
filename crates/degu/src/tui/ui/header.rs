use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::report::Section;

use super::format::coverage_warning;
use super::overview;
use super::text::columns;
use super::theme::{ACCENT, CAUTION, READY, SECONDARY};
use super::{App, View};

const MASTHEAD_PREFIX: &str = "degu  / storage report";
const HEADER_GAP: usize = 3;
const BROWSER_HEIGHT: u16 = 2;
const DETAIL_HEIGHT: u16 = 4;

pub fn height(app: &App) -> u16 {
    if app.view() == View::Browser {
        BROWSER_HEIGHT
    } else {
        DETAIL_HEIGHT
    }
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let mut lines = vec![masthead(app, usize::from(area.width)), sections(app)];
    if app.view() == View::Details {
        lines.push(overview::summary(app, usize::from(area.width)));
        if let Some(warning) = coverage_warning(browser.coverage()) {
            lines.push(Line::from(vec![
                Span::styled("! ", Style::new().fg(CAUTION)),
                Span::raw(warning),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The masthead carries the plan rather than a fixed label, so the size of a
/// decision is visible from whichever row the reader is standing on.
fn masthead(app: &App, width: usize) -> Line<'static> {
    let plan = plan_label(app);
    let gap = width
        .saturating_sub(columns(MASTHEAD_PREFIX) + columns(&plan) + HEADER_GAP)
        .max(1);
    Line::from(vec![
        Span::styled("degu", Style::new().fg(READY).bold()),
        Span::styled("  / storage report", Style::new().fg(SECONDARY)),
        Span::raw(" ".repeat(gap)),
        Span::styled(
            plan,
            Style::new().fg(if app.decisions().is_empty() {
                SECONDARY
            } else {
                READY
            }),
        ),
    ])
}

fn plan_label(app: &App) -> String {
    let plan = app.decisions().plan();
    if plan.locations == 0 {
        return "Nothing in the plan".to_owned();
    }
    format!(
        "In the plan: {} · {}",
        pluralize(plan.locations, "location"),
        super::format::bytes(plan.bytes)
    )
}

fn pluralize(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn sections(app: &App) -> Line<'static> {
    let browser = app.browser();
    Line::from(
        [Section::Cache, Section::Runtime]
            .into_iter()
            .map(|section| {
                let suffix = if browser.coverage_of(section).is_requested() {
                    ""
                } else {
                    " (not scanned)"
                };
                let style = if browser.section() == section {
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new().fg(SECONDARY)
                };
                let name = format!("{}{suffix}", section.label());
                Span::styled(
                    if browser.section() == section {
                        format!("[{name}]  ")
                    } else {
                        format!(" {name}   ")
                    },
                    style,
                )
            })
            .collect::<Vec<_>>(),
    )
}
