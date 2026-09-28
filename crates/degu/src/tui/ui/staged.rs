use ratatui::prelude::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use crate::presentation::escape_terminal_text;
use crate::tui::decision::Plan;
use crate::tui::staged::Entry;

use super::text::{elide, wrapped};
use super::theme::{CAUTION, EDGE, ROSE, SECONDARY, panel};
use super::{App, format, window_start};

/// One space between each pair of the five columns.
const COLUMN_GAPS: usize = 4;
const TABLE_CHROME: usize = 3;
const CURSOR_WIDTH: usize = 1;
const MARK_WIDTH: usize = 1;
const AGE_WIDTH: usize = 9;
const SIZE_WIDTH: usize = 10;
const MIN_LIST_HEIGHT: u16 = 3;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let lines = notice_lines(app);
    let (notice, list) = areas(area, &lines);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), notice);
    listing(frame, list, app);
}

pub fn page_size(area: Rect, app: &App) -> usize {
    let (_, list) = areas(area, &notice_lines(app));
    usize::from(list.height).saturating_sub(TABLE_CHROME)
}

fn areas(area: Rect, lines: &[Line<'_>]) -> (Rect, Rect) {
    let height = lines
        .iter()
        .map(|line| wrapped(&line.to_string(), usize::from(area.width)).len())
        .sum::<usize>();
    let height = u16::try_from(height).unwrap_or(u16::MAX);
    let rows = Layout::vertical([Constraint::Length(height), Constraint::Min(MIN_LIST_HEIGHT)])
        .split(area);
    (rows[0], rows[1])
}

fn notice_lines(app: &App) -> Vec<Line<'static>> {
    let staged = app.staged();
    let clean = app.decisions().plan();
    let cleaning = clean.locations > 0;
    let summary = staged.summary(cleaning);
    let mut lines = vec![
        Line::from(format!(
            "Staged: {} · {}. Staged data still counts against quota.",
            format::locations(summary.total.locations),
            format::plan_size(summary.total)
        ))
        .fg(SECONDARY),
    ];
    if summary.chosen.locations > 0 {
        lines.push(plan_line("Chosen for permanent deletion", summary.chosen).fg(ROSE));
    }
    if summary.expiring.locations > 0 {
        lines.push(plan_line("Also in this clean's expiry plan", summary.expiring).fg(CAUTION));
    } else if !cleaning && staged.summary(true).expiring.locations > 0 {
        lines.push(Line::from("No clean selected; automatic expiry will not run.").fg(SECONDARY));
    }
    if summary.chosen.locations > 0 || summary.expiring.locations > 0 || cleaning {
        lines.push(
            Line::from(format!(
                "Outside both purge plans: {} · {}. This clean would stage {} · {}.",
                format::locations(summary.remaining.locations),
                format::plan_size(summary.remaining),
                format::locations(clean.locations),
                format::plan_size(clean)
            ))
            .fg(SECONDARY),
        );
    }
    if summary.chosen.locations > 0 || summary.expiring.locations > 0 {
        lines.push(
            Line::from(
                "Unsupported purge entries stay staged. The CLI rechecks and confirms each plan.",
            )
            .fg(SECONDARY),
        );
    }
    lines
}

fn plan_line(label: &str, plan: Plan) -> Line<'static> {
    Line::from(format!(
        "{label}: {} · {}.",
        format::locations(plan.locations),
        format::plan_size(plan)
    ))
}

/// What the staged screen says about itself before any rows.
///
/// The coverage note comes first and appears whether or not there are rows: a view
/// showing some entries implies it is showing all of them just as an empty one
/// implies there are none. The empty text only stands in for rows.
fn staged_prose(
    coverage: crate::lifecycle::StoreCoverage,
    empty: bool,
) -> (Option<&'static str>, Option<&'static str>) {
    let empty_text = empty.then_some(
        "The staging trash is empty. A confirmed clean puts findings here, where degu undo can still reach them.",
    );
    (coverage.note(), empty_text)
}

fn listing(frame: &mut Frame, area: Rect, app: &App) {
    let staged = app.staged();
    let (note, empty_text) = staged_prose(staged.coverage(), staged.is_empty());
    let area = match note {
        None => area,
        Some(note) => {
            let lines = wrapped(note, usize::from(area.width.saturating_sub(2))).len();
            let height = u16::try_from(lines).unwrap_or(u16::MAX).saturating_add(2);
            let [top, rest] = Layout::vertical([
                Constraint::Length(height.min(area.height)),
                Constraint::Min(0),
            ])
            .areas(area);
            frame.render_widget(
                Paragraph::new(note)
                    .style(Style::default().fg(CAUTION))
                    .wrap(Wrap { trim: false })
                    .block(panel("coverage")),
                top,
            );
            rest
        }
    };
    if let Some(empty_text) = empty_text {
        frame.render_widget(
            Paragraph::new(empty_text)
                .wrap(Wrap { trim: false })
                .block(panel("staged")),
            area,
        );
        return;
    }
    let inner = panel("").inner(area);
    let page_size = usize::from(area.height).saturating_sub(TABLE_CHROME);
    let path_width = usize::from(inner.width)
        .saturating_sub(CURSOR_WIDTH + MARK_WIDTH + AGE_WIDTH + SIZE_WIDTH + COLUMN_GAPS)
        .max(1);
    let first = window_start(staged.cursor(), staged.entries().len(), page_size);
    let rows = staged
        .entries()
        .iter()
        .enumerate()
        .skip(first)
        .take(page_size)
        .map(|(position, entry)| row((entry, position), path_width, app))
        .collect::<Vec<_>>();
    let position = format!(" {}/{} ", staged.cursor() + 1, staged.entries().len());
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(CURSOR_WIDTH as u16),
                Constraint::Length(MARK_WIDTH as u16),
                Constraint::Min(path_width as u16),
                Constraint::Length(AGE_WIDTH as u16),
                Constraint::Length(SIZE_WIDTH as u16),
            ],
        )
        .header(
            Row::new(vec![
                Cell::from(""),
                Cell::from(""),
                Cell::from("ENTRY · STAGED FROM"),
                Cell::from(Line::from("IDLE").right_aligned()),
                Cell::from(Line::from("ON DISK").right_aligned()),
            ])
            .style(Style::new().fg(SECONDARY)),
        )
        .block(
            panel("staged trash").title_bottom(Line::from(position).fg(SECONDARY).right_aligned()),
        ),
        area,
    );
}

fn row(item: (&Entry, usize), path_width: usize, app: &App) -> Row<'static> {
    let (entry, position) = item;
    let staged = app.staged();
    let chosen = staged.is_chosen(entry);
    let mark = if chosen {
        "✓"
    } else if entry.selectable() {
        "○"
    } else {
        " "
    };
    let style = if chosen {
        Style::new().fg(ROSE)
    } else if entry.selectable() {
        Style::new()
    } else {
        Style::new().fg(EDGE)
    };
    let size = format::bounded_bytes(entry.bytes, entry.lower_bound);
    Row::new(vec![
        Cell::from(if position == staged.cursor() {
            "▸"
        } else {
            " "
        })
        .style(Style::new().fg(super::theme::ACCENT)),
        Cell::from(mark),
        Cell::from(elide(
            &escape_terminal_text(&entry.label(app.home())),
            path_width,
        )),
        Cell::from(Line::from(days(entry.age_days)).right_aligned()).style(
            if entry.expiring && !app.decisions().is_empty() {
                Style::new().fg(CAUTION)
            } else {
                Style::new().fg(SECONDARY)
            },
        ),
        Cell::from(Line::from(size).right_aligned()),
    ])
    .style(style)
}

fn days(age: u64) -> String {
    match age {
        0 => "today".to_owned(),
        1 => "1 day".to_owned(),
        other => format!("{other} days"),
    }
}

#[cfg(test)]
mod tests {
    use super::staged_prose;
    use crate::lifecycle::StoreCoverage;

    /// The screen has to say which of two different things an absence of rows
    /// means, and a view that is not the whole account has to say so even when it
    /// does have rows to show.
    #[test]
    fn the_staged_screen_separates_an_empty_account_from_an_incomplete_view() {
        assert_eq!(staged_prose(StoreCoverage::Complete, false), (None, None));

        let (note, empty) = staged_prose(StoreCoverage::Complete, true);
        assert!(note.is_none());
        assert!(
            empty
                .expect("empty text")
                .contains("staging trash is empty")
        );

        for coverage in [StoreCoverage::Elsewhere, StoreCoverage::Unknown] {
            let (note, empty) = staged_prose(coverage, true);
            assert!(note.is_some(), "{coverage:?} empty screen said nothing");
            assert!(empty.is_some());

            let (note, empty) = staged_prose(coverage, false);
            assert!(note.is_some(), "{coverage:?} populated screen said nothing");
            assert!(empty.is_none());
        }
    }
}
