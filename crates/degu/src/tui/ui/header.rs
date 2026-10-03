use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::report::Section;

use super::format::coverage_warning;
use super::overview;
use super::text::columns;
use super::theme::{ACCENT, CAUTION, READY, ROSE, SECONDARY};
use super::{App, View};

const MASTHEAD_NAME: &str = "degu";
const MASTHEAD_SUFFIX: &str = "  / storage report";
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
    masthead_line(plan_label(app), plan_tone(app), width)
}

fn masthead_line(plan: String, tone: Color, width: usize) -> Line<'static> {
    let layout = masthead_layout(&plan, width);
    let mut spans = vec![Span::styled(MASTHEAD_NAME, Style::new().fg(READY).bold())];
    if layout.suffix {
        spans.push(Span::styled(MASTHEAD_SUFFIX, Style::new().fg(SECONDARY)));
    }
    spans.push(Span::raw(" ".repeat(layout.gap)));
    spans.push(Span::styled(plan, Style::new().fg(tone)));
    Line::from(spans)
}

struct MastheadLayout {
    suffix: bool,
    gap: usize,
}

/// Which parts of the masthead a row of this width can hold.
///
/// The suffix is decoration; the label beside it can be a command the reader has
/// to type, and the row is truncated from the right, so a row too narrow for both
/// loses exactly the part that was worth keeping. Dropping the suffix first is
/// the only ordering that keeps the remedy whole.
///
/// The threshold is derived from the label it has to fit rather than written down
/// as a width: a reworded label would otherwise be truncated at every size with
/// nothing to notice, which is how #166 happened.
fn masthead_layout(plan: &str, width: usize) -> MastheadLayout {
    let compact = columns(MASTHEAD_NAME) + columns(plan) + HEADER_GAP;
    let full = compact + columns(MASTHEAD_SUFFIX);
    let suffix = full <= width;
    let used = if suffix { full } else { compact };
    MastheadLayout {
        suffix,
        gap: width.saturating_sub(used).max(1),
    }
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
    // A plan that cannot run is not ready, whatever its size.
    if app.blocked() {
        return CAUTION;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const REMEDY: &str = "Cleanup unavailable - run 'degu doctor'";

    /// What a terminal of this many columns actually gives the header: the screen is
    /// drawn inside a one-column margin on each side.
    fn header_width(terminal: usize) -> usize {
        terminal - 2
    }

    fn drawn(plan: &str, terminal: usize) -> String {
        masthead_line(plan.to_owned(), READY, header_width(terminal))
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// 60 columns is the narrowest terminal the findings screen is tested at, and the
    /// remedy is the one thing on this row a reader may have to type.
    #[test]
    fn a_narrow_masthead_keeps_the_whole_remedy() {
        let line = drawn(REMEDY, 60);
        assert!(
            columns(&line) <= header_width(60),
            "the masthead overflows its row: {line:?}"
        );
        assert!(line.contains(REMEDY), "the remedy was cut: {line:?}");
        assert!(
            !line.contains(MASTHEAD_SUFFIX),
            "the suffix is what should have gone: {line:?}"
        );
    }

    /// A width that can hold both keeps both: the remedy is not a reason to spend every
    /// row of every terminal without the report's name on it.
    #[test]
    fn a_wide_masthead_keeps_both() {
        let line = drawn(REMEDY, 120);
        assert!(columns(&line) <= header_width(120), "{line:?}");
        assert!(line.contains(REMEDY), "{line:?}");
        assert!(line.contains(MASTHEAD_SUFFIX), "{line:?}");
    }
}
