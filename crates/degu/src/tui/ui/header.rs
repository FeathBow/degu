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
    let plan = plan_label(app);
    let layout = masthead_layout(&plan, width);
    let mut spans = vec![Span::styled(MASTHEAD_NAME, Style::new().fg(READY).bold())];
    if layout.suffix {
        spans.push(Span::styled(MASTHEAD_SUFFIX, Style::new().fg(SECONDARY)));
    }
    spans.push(Span::raw(" ".repeat(layout.gap)));
    spans.push(Span::styled(plan, Style::new().fg(plan_tone(app))));
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

    /// The one label on this row that a reader may have to type. If the row cannot
    /// hold it beside the suffix, the suffix is what has to go: the row truncates
    /// from the right, so keeping the suffix would cut the command instead.
    const REMEDY: &str = "Cleanup unavailable - run 'degu doctor'";

    #[test]
    fn the_masthead_drops_its_suffix_before_it_cuts_the_label() {
        // 60 columns is the narrowest terminal the findings screen is tested at.
        for width in [60, 80, 120] {
            let layout = masthead_layout(REMEDY, width);
            let drawn = columns(MASTHEAD_NAME)
                + if layout.suffix {
                    columns(MASTHEAD_SUFFIX)
                } else {
                    0
                }
                + layout.gap
                + columns(REMEDY);
            assert!(
                drawn <= width,
                "the masthead draws {drawn} columns into {width}: suffix={}",
                layout.suffix
            );
        }
    }

    /// A width that can hold both keeps both: the remedy is not a reason to spend
    /// every row of every terminal without the report's name on it.
    #[test]
    fn a_wide_masthead_keeps_the_suffix() {
        assert!(masthead_layout(REMEDY, 120).suffix);
        assert!(!masthead_layout(REMEDY, 60).suffix);
    }

    /// The gap is what separates the two, so it may never close to nothing even when
    /// the label alone is wider than the row.
    #[test]
    fn the_gap_never_closes() {
        for width in [0, 1, 20, 44, 60, 200] {
            assert!(masthead_layout(REMEDY, width).gap >= 1, "width {width}");
        }
    }
}
