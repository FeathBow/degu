use ratatui::prelude::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use crate::presentation::escape_terminal_text;
use crate::tui::report::{Class, Finding, Section};

use super::format;
use super::text::elide;
use super::theme::{ACCENT, SECONDARY, SELECTION, class_style, focused_panel, panel};
use super::{App, Focus, window_start};

/// One space between each pair of columns. Five columns without the
/// ecosystem name leaves four gaps; the ecosystem column carries its own.
const COLUMN_GAPS: usize = 4;
const TABLE_CHROME: usize = 3;
const CURSOR_WIDTH: usize = 1;
const MARK_WIDTH: usize = 1;
const STATUS_WIDTH: usize = 14;
const ECOSYSTEM_WIDTH: usize = 14;
const FULL_STATUS_MIN_WIDTH: usize = 55;
const ECOSYSTEM_MIN_WIDTH: usize = 100;

struct Columns {
    path: usize,
    status: usize,
    metric: usize,
    ecosystem: bool,
}

impl Columns {
    fn new(width: u16, metric: usize) -> Self {
        let inner = usize::from(width);
        let status = if inner >= FULL_STATUS_MIN_WIDTH {
            STATUS_WIDTH
        } else {
            1
        };
        let ecosystem = inner >= ECOSYSTEM_MIN_WIDTH;
        let ecosystem_space = if ecosystem { ECOSYSTEM_WIDTH + 1 } else { 0 };
        let fixed = CURSOR_WIDTH + MARK_WIDTH + status + metric + COLUMN_GAPS + ecosystem_space;
        Self {
            path: inner.saturating_sub(fixed).max(1),
            status,
            metric,
            ecosystem,
        }
    }

    fn widths(&self) -> Vec<Constraint> {
        let mut widths = vec![
            Constraint::Length(CURSOR_WIDTH as u16),
            Constraint::Length(MARK_WIDTH as u16),
            Constraint::Min(self.path as u16),
        ];
        if self.ecosystem {
            widths.push(Constraint::Length(ECOSYSTEM_WIDTH as u16));
        }
        widths.push(Constraint::Length(self.status as u16));
        widths.push(Constraint::Length(self.metric as u16));
        widths
    }

    fn header(&self, app: &App) -> Row<'static> {
        let status = if self.status == STATUS_WIDTH {
            "CLASSIFICATION"
        } else {
            ""
        };
        let mut cells = vec![Cell::from(""), Cell::from(""), Cell::from("PATH")];
        if self.ecosystem {
            cells.push(Cell::from("ECOSYSTEM"));
        }
        cells.push(Cell::from(status));
        cells.push(Cell::from(
            Line::from(format::metric_heading(app.browser().sort_by())).right_aligned(),
        ));
        Row::new(cells).style(Style::new().fg(SECONDARY))
    }
}

pub fn page_size(area: Rect) -> usize {
    usize::from(area.height).saturating_sub(TABLE_CHROME)
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let page_size = page_size(area);
    if browser.finding_count() == 0 {
        frame.render_widget(
            Paragraph::new(empty_message(app))
                .wrap(Wrap { trim: false })
                .block(panel("Findings")),
            area,
        );
        return;
    }
    let columns = Columns::new(panel("").inner(area).width, app.metric_width());
    let first = window_start(browser.selected(), browser.finding_count(), page_size);
    let rows = browser
        .findings()
        .enumerate()
        .skip(first)
        .take(page_size)
        .map(|(position, finding)| finding_row((finding, position), &columns, app))
        .collect::<Vec<_>>();
    let position = format!(
        " {}/{} · {} {} ",
        browser.selected() + 1,
        browser.finding_count(),
        browser.sort_by().label(),
        format::sort_direction(browser.sort_by()),
    );
    frame.render_widget(
        Table::new(rows, columns.widths())
            .header(columns.header(app))
            .block(
                focused_panel("2 locations", app.focus() == Focus::Findings)
                    .title_bottom(Line::from(position).fg(SECONDARY).right_aligned()),
            ),
        area,
    );
}

fn finding_row(item: (&Finding, usize), columns: &Columns, app: &App) -> Row<'static> {
    let (finding, position) = item;
    let class = Class::of(finding, app.browser().section());
    let status = if columns.status == STATUS_WIDTH {
        class.label()
    } else {
        symbol(class)
    };
    let selected = position == app.browser().selected();
    let mark = match (class, app.decisions().is_chosen(finding)) {
        (Class::NotManaged, _) => " ",
        (_, true) => "✓",
        (_, false) => "○",
    };
    let mut cells = vec![
        Cell::from(if selected { "▸" } else { " " }).style(Style::new().fg(ACCENT)),
        Cell::from(mark).style(class_style(class)),
        Cell::from(elide(
            &escape_terminal_text(&crate::presentation::display_path(
                finding.path(),
                app.home(),
            )),
            columns.path,
        )),
    ];
    if columns.ecosystem {
        cells.push(Cell::from(escape_terminal_text(finding.ecosystem())));
    }
    cells.push(Cell::from(status).style(class_style(class)));
    let metric_style = if selected {
        Style::new().fg(ACCENT).bold()
    } else {
        Style::new().bold()
    };
    cells.push(
        Cell::from(Line::from(format::metric(finding, app.browser().sort_by())).right_aligned())
            .style(metric_style),
    );
    let style = if selected {
        Style::new().bg(SELECTION)
    } else {
        Style::new()
    };
    Row::new(cells).style(style)
}

fn symbol(class: Class) -> &'static str {
    match class {
        Class::Ready => "+",
        Class::NeedsReview => "?",
        Class::NotManaged => "·",
    }
}

fn empty_message(app: &App) -> &'static str {
    let browser = app.browser();
    if !browser.coverage().is_requested() {
        return match browser.section() {
            Section::Runtime => "Runtime was not scanned.\nRun degu tui --runtime to include it.",
            Section::Cache => "Cache was not scanned in this report.",
        };
    }
    "No findings in this section."
}
