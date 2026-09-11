//! Responsive, read-only views of the report's aggregated findings.
mod allocation;
mod app;
mod brand;
mod derived;
mod details;
mod findings;
mod format;
mod groups;
mod header;
pub(crate) mod help;
mod overview;
mod text;
mod theme;

use ratatui::prelude::*;
use ratatui::widgets::Block;

pub use app::{App, Focus, View};

const SIDEBAR_MIN_WIDTH: u16 = 98;
const SIDEBAR_WIDTH: u16 = 25;
const PANEL_GAP: u16 = 1;
const FILTER_HEIGHT: u16 = 1;
const FOOTER_HEIGHT: u16 = 1;
const MIN_LIST_HEIGHT: u16 = 5;
const PREVIEW_HEIGHT: u16 = 6;

pub fn draw(frame: &mut Frame, app: &mut App) {
    frame.render_widget(Block::default().style(theme::canvas()), frame.area());
    let area = frame.area().inner(Margin {
        horizontal: 1,
        vertical: 0,
    });
    let rows = Layout::vertical([
        Constraint::Length(if app.view() == View::Help {
            0
        } else {
            header::height(app)
        }),
        Constraint::Min(0),
        Constraint::Length(FOOTER_HEIGHT),
    ])
    .split(area);
    header::draw(frame, rows[0], app);
    match app.view() {
        View::Browser => browser(frame, rows[1], app),
        View::Details => app.document().draw(frame, rows[1], true),
        View::Help => help::draw(frame, rows[1]),
    }
    help::footer(frame, rows[2], app);
}

fn browser(frame: &mut Frame, area: Rect, app: &mut App) {
    let overview_height = if overview::is_wide(area) {
        overview::WIDE_HEIGHT
    } else {
        overview::COMPACT_HEIGHT
    };
    // The guard counts what the layout below reserves, gap included.
    let has_preview = area.height
        >= overview_height + FILTER_HEIGHT + MIN_LIST_HEIGHT + PANEL_GAP + PREVIEW_HEIGHT;
    let preview_height = if has_preview { PREVIEW_HEIGHT } else { 0 };
    let rows = Layout::vertical([
        Constraint::Length(overview_height),
        Constraint::Length(FILTER_HEIGHT),
        Constraint::Min(MIN_LIST_HEIGHT),
        Constraint::Length(PANEL_GAP),
        Constraint::Length(preview_height),
    ])
    .split(area);
    overview::draw(frame, rows[0], app);
    groups::filter_line(frame, rows[1], app);
    listing(frame, rows[2], app);
    if has_preview && app.browser().selected_finding().is_some() {
        app.document().draw(frame, rows[4], false);
    }
}

fn listing(frame: &mut Frame, area: Rect, app: &mut App) {
    if area.width < SIDEBAR_MIN_WIDTH || app.browser().finding_count() == 0 {
        app.resize(findings::page_size(area), 1);
        findings::draw(frame, area, app);
        return;
    }
    let columns = Layout::horizontal([
        Constraint::Length(SIDEBAR_WIDTH),
        Constraint::Length(PANEL_GAP),
        Constraint::Min(0),
    ])
    .split(area);
    app.resize(
        findings::page_size(columns[2]),
        groups::page_size(columns[0], app.browser().groups().len()),
    );
    groups::draw(frame, columns[0], app);
    findings::draw(frame, columns[2], app);
}

fn window_start(selected: usize, length: usize, capacity: usize) -> usize {
    selected
        .saturating_sub(capacity.saturating_sub(1) / 2)
        .min(length.saturating_sub(capacity))
}
