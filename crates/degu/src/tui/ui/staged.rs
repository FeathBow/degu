use ratatui::prelude::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use crate::tui::escape;
use crate::tui::staged::Entry;

use super::text::elide;
use super::theme::{CAUTION, EDGE, ROSE, SECONDARY, panel};
use super::{App, format, window_start};

const TABLE_OVERHEAD: usize = 3;
const CURSOR_WIDTH: usize = 1;
const MARK_WIDTH: usize = 1;
const AGE_WIDTH: usize = 9;
const SIZE_WIDTH: usize = 10;
const NOTICE_HEIGHT: u16 = 4;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows =
        Layout::vertical([Constraint::Length(NOTICE_HEIGHT), Constraint::Min(3)]).split(area);
    notice(frame, rows[0], app);
    listing(frame, rows[1], app);
}

pub fn page_size(area: Rect) -> usize {
    usize::from(area.height)
        .saturating_sub(usize::from(NOTICE_HEIGHT))
        .saturating_sub(TABLE_OVERHEAD)
}

/// Staging is why a clean does not free quota, and expiry is why some of it
/// goes without being chosen. Both belong on screen before any choice is made,
/// and the two totals stay apart so neither is read as the other.
fn notice(frame: &mut Frame, area: Rect, app: &App) {
    let staged = app.staged();
    let total = staged.total_plan();
    let chosen = staged.chosen_plan();
    let expiring = staged.expiring_plan();
    let mut lines = vec![
        Line::from(format!(
            "Staged: {} · {}. This still counts against quota until it is permanently deleted.",
            locations(total.locations),
            format::bytes(total.bytes)
        ))
        .fg(SECONDARY),
    ];
    if chosen.locations > 0 {
        lines.push(
            Line::from(format!(
                "Chosen for permanent deletion: {} · {}.",
                locations(chosen.locations),
                format::bytes(chosen.bytes)
            ))
            .fg(ROSE),
        );
    }
    if expiring.locations > 0 {
        lines.push(
            Line::from(format!(
                "A confirmed clean also removes {} · {} already past {} days, chosen or not.",
                locations(expiring.locations),
                format::bytes(expiring.bytes),
                crate::lifecycle::TRASH_RETENTION_DAYS
            ))
            .fg(CAUTION),
        );
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn listing(frame: &mut Frame, area: Rect, app: &App) {
    let staged = app.staged();
    if staged.is_empty() {
        frame.render_widget(
            Paragraph::new("The staging trash is empty. A confirmed clean puts findings here, where degu undo can still reach them.")
                .wrap(Wrap { trim: false })
                .block(panel("staged")),
            area,
        );
        return;
    }
    let inner = panel("").inner(area);
    let page_size = usize::from(inner.height).saturating_sub(2);
    let path_width = usize::from(inner.width)
        .saturating_sub(CURSOR_WIDTH + MARK_WIDTH + AGE_WIDTH + SIZE_WIDTH + TABLE_OVERHEAD)
        .max(1);
    let first = window_start(staged.cursor(), staged.entries().len(), page_size);
    let rows = staged
        .entries()
        .iter()
        .enumerate()
        .skip(first)
        .take(page_size)
        .map(|(position, entry)| row(entry, position, path_width, app))
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
                Cell::from("STAGED FROM"),
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

fn row(entry: &Entry, position: usize, path_width: usize, app: &App) -> Row<'static> {
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
    let size = format::bytes(entry.bytes);
    let size = if entry.lower_bound {
        format!("≥ {size}")
    } else {
        size
    };
    Row::new(vec![
        Cell::from(if position == staged.cursor() {
            "▸"
        } else {
            " "
        })
        .style(Style::new().fg(super::theme::ACCENT)),
        Cell::from(mark),
        Cell::from(elide(&escape::text(&entry.label(app.home())), path_width)),
        Cell::from(Line::from(days(entry.age_days)).right_aligned()).style(if entry.expiring {
            Style::new().fg(CAUTION)
        } else {
            Style::new().fg(SECONDARY)
        }),
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

fn locations(count: usize) -> String {
    if count == 1 {
        format!("{count} location")
    } else {
        format!("{count} locations")
    }
}
