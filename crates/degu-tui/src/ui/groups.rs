use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::escape;

use super::format::{bytes_total, count};
use super::text::{columns, elide, pad};
use super::theme::{ACCENT, SECONDARY, SELECTION, class_style, focused_panel, panel};
use super::{App, Focus, window_start};

const ROW_HEIGHT: usize = 2;
const ROW_PREFIX: usize = 2;
const ROW_GAP: usize = 1;

pub fn page_size(area: Rect, groups: usize) -> usize {
    let height = usize::from(panel("").inner(area).height);
    height / row_height(height, groups)
}

fn row_height(height: usize, groups: usize) -> usize {
    let roomy = height / (ROW_HEIGHT + ROW_GAP) > groups;
    ROW_HEIGHT + usize::from(roomy) * ROW_GAP
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    let inner = panel("").inner(area);
    let row_height = row_height(usize::from(inner.height), browser.groups().len());
    let capacity = page_size(area, browser.groups().len());
    let length = browser.groups().len() + 1;
    let first = window_start(browser.group_position(), length, capacity);
    let end = (first + capacity).min(length);
    let lines = (first..end)
        .flat_map(|position| {
            let mut lines = row(app, position, inner.width).to_vec();
            if row_height > ROW_HEIGHT {
                lines.push(Line::default());
            }
            lines
        })
        .collect::<Vec<_>>();
    let remaining = length - (end - first);
    let navigation = if remaining == 0 {
        " ←→ filter ".to_owned()
    } else {
        format!(" ←→ · {} more ", count(remaining as u64))
    };
    let block = focused_panel(
        format!(
            "1 by {} ({})",
            browser.group_by().label(),
            browser.groups().len()
        ),
        app.focus() == Focus::Groups,
    )
    .title_bottom(Line::from(navigation).fg(SECONDARY));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn row(app: &App, position: usize, width: u16) -> [Line<'static>; ROW_HEIGHT] {
    let browser = app.browser();
    let group = position
        .checked_sub(1)
        .and_then(|index| browser.groups().get(index));
    let (name, total, findings) = group.map_or(
        ("All findings", browser.allocated(), browser.section_len()),
        |group| (group.name.as_str(), group.allocated, group.count),
    );
    let selected = browser.group_position() == position;
    let prefix = if selected { "▸ " } else { "  " };
    let class = group.and_then(|group| group.class);
    let mut style = class.map_or(Style::new().fg(ACCENT), class_style);
    if selected {
        style = style.bg(SELECTION).bold();
    }
    let label = Line::from(format!(
        "{prefix}{}",
        pad(
            &escape::text(name),
            usize::from(width).saturating_sub(ROW_PREFIX)
        )
    ))
    .style(style);
    [
        label,
        Line::from(format!("  {} · {}", count(findings as u64), bytes_total(total)))
            .fg(SECONDARY),
    ]
}

pub fn filter_line(frame: &mut Frame, area: Rect, app: &App) {
    let browser = app.browser();
    if !browser.coverage(browser.section()).was_requested() {
        return;
    }
    let name = browser
        .active_group()
        .map_or("All findings", |group| group.name.as_str());
    let prefix = format!("by {} › ", browser.group_by().label());
    let suffix = format!(" · {} shown", browser.finding_count());
    let budget = usize::from(area.width).saturating_sub(columns(&prefix) + columns(&suffix));
    let style = if app.focus() == Focus::Groups {
        Style::new().fg(ACCENT).bg(SELECTION).bold()
    } else {
        Style::new().fg(SECONDARY)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(elide(&escape::text(name), budget), style),
            Span::styled(suffix, style),
        ])),
        area,
    );
}
