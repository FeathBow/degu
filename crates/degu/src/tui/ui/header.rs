use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::report::Section;

use super::format::coverage_warning;
use super::overview;
use super::text::{columns, pad};
use super::theme::{ACCENT, CAUTION, READY, SECONDARY};
use super::{App, View};

const SNAPSHOT_LABEL: &str = "Read-only snapshot";
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

fn masthead(app: &App, width: usize) -> Line<'static> {
    let fixed = columns(MASTHEAD_PREFIX) + columns(SNAPSHOT_LABEL) + HEADER_GAP * 2;
    let source = pad(app.source(), width.saturating_sub(fixed));
    Line::from(vec![
        Span::styled("degu", Style::new().fg(READY).bold()),
        Span::styled("  / storage report", Style::new().fg(SECONDARY)),
        Span::raw(" ".repeat(HEADER_GAP)),
        Span::styled(source, Style::new().fg(SECONDARY)),
        Span::raw(" ".repeat(HEADER_GAP)),
        Span::styled(SNAPSHOT_LABEL, Style::new().fg(SECONDARY)),
    ])
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
