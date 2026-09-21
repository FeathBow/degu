use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::report::Section;

use super::format::coverage_warning;
use super::overview;
use super::text::columns;
use super::theme::{ACCENT, CAUTION, READY, ROSE, SECONDARY};
use super::{App, View};

const MASTHEAD_PREFIX: &str = "degu  / storage report";
const HEADER_GAP: usize = 3;
const BROWSER_HEIGHT: u16 = 2;
const DETAIL_HEIGHT: u16 = 4;

pub fn height(app: &App) -> u16 {
    if app.view() == View::Details {
        DETAIL_HEIGHT
    } else {
        BROWSER_HEIGHT
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
    let plan = plan_label(app);
    let gap = width
        .saturating_sub(columns(MASTHEAD_PREFIX) + columns(&plan) + HEADER_GAP)
        .max(1);
    Line::from(vec![
        Span::styled("degu", Style::new().fg(READY).bold()),
        Span::styled("  / storage report", Style::new().fg(SECONDARY)),
        Span::raw(" ".repeat(gap)),
        Span::styled(plan, Style::new().fg(plan_tone(app))),
    ])
}

fn plan_label(app: &App) -> String {
    // A plan total answers "what would running do", which is not the question
    // when running is unavailable. This line is the width the remedy needs.
    if app.blocked() {
        return "Cleanup unavailable - run 'degu doctor'".to_owned();
    }
    let (plan, verb) = if app.view() == View::Staged {
        (app.staged().summary(true).chosen, "To delete permanently")
    } else {
        (app.decisions().plan(), "In the plan")
    };
    if plan.locations == 0 {
        return if app.view() == View::Staged {
            "Nothing chosen for deletion".to_owned()
        } else {
            "Nothing in the plan".to_owned()
        };
    }
    format!(
        "{verb}: {} · {}",
        super::format::locations(plan.locations),
        super::format::plan_size(plan)
    )
}

fn plan_tone(app: &App) -> Color {
    if app.view() == View::Staged {
        if app.staged().nothing_chosen() {
            SECONDARY
        } else {
            ROSE
        }
    } else if app.decisions().is_empty() {
        SECONDARY
    } else {
        READY
    }
}

fn sections(app: &App) -> Line<'static> {
    if app.view() == View::Staged {
        return Line::from(vec![
            Span::styled("[staged trash]  ", Style::new().fg(ACCENT).bold()),
            Span::styled(
                "t or Esc returns to the findings",
                Style::new().fg(SECONDARY),
            ),
        ]);
    }
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
