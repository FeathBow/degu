use ratatui::prelude::*;
use ratatui::widgets::{Paragraph, Wrap};

use super::brand;
use super::text::wrapped;
use super::theme::{ACCENT, SECONDARY, panel};
use super::{App, View};

pub const KEY_HELP: &str = "\
up/down, k/j   Move in the focused panel / scroll details
1 / 2         Focus groups / findings
left/right    Filter by the previous / next group
g             Group by ecosystem, disposition, or kind
s             Sort by size, inodes, age, or path
tab           Switch cache / node-runtime section
3 / enter     Open the selected record in full
PgUp/PgDn     Move by one visible page
home/end      First / last finding or detail line
Esc           Back; clear a filter; otherwise quit
?             Show / close this help
q, Ctrl-C/D   Quit

Compact status: + Ready to clean; ? Needs review; · Not managed
Runtime findings are Not managed and never join cache totals.
Browsing this saved report never changes your files.";

const FULL_FOOTER_WIDTH: u16 = 110;
const DETAIL_FOOTER_WIDTH: u16 = 64;
const COMPACT_FOOTER_WIDTH: u16 = 55;

pub fn draw(frame: &mut Frame, area: Rect) {
    const BRAND_HEIGHT: usize = 5;
    let inner = panel("").inner(area);
    let text_height = KEY_HELP
        .lines()
        .map(|line| wrapped(line, usize::from(inner.width)).len())
        .sum::<usize>();
    let mut lines = Vec::new();
    if usize::from(inner.height) >= text_height + BRAND_HEIGHT {
        lines.extend(brand::wordmark());
        lines.push(
            Line::from("Understand what occupies your space.")
                .fg(SECONDARY)
                .centered(),
        );
    }
    lines.extend(KEY_HELP.lines().map(Line::from));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("degu / field guide · ? or Esc to close")),
        area,
    );
}

pub fn footer(frame: &mut Frame, area: Rect, app: &App) {
    let keys: &[(&str, &str)] = match app.view() {
        View::Help => &[("Esc", "back"), ("q", "quit")],
        View::Details if area.width >= DETAIL_FOOTER_WIDTH => &[
            ("↑↓", "scroll"),
            ("PgUp/PgDn", "page"),
            ("Home/End", "ends"),
            ("Esc", "back"),
            ("q", "quit"),
        ],
        View::Details => &[
            ("↑↓", "scroll"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser if area.width >= FULL_FOOTER_WIDTH => &[
            ("↑↓", "move"),
            ("1/2", "focus"),
            ("←→", "filter"),
            ("g", "group"),
            ("s", "sort"),
            ("Tab", "section"),
            ("3/Enter", "details"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser if area.width >= COMPACT_FOOTER_WIDTH => &[
            ("↑↓", "move"),
            ("←→", "filter"),
            ("Enter", "details"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser => &[
            ("↑↓", "move"),
            ("Enter", "open"),
            ("?", "help"),
            ("q", "quit"),
        ],
    };
    let gap = if app.view() == View::Browser && area.width < COMPACT_FOOTER_WIDTH {
        "  "
    } else {
        "   "
    };
    let spans = keys
        .iter()
        .flat_map(|&(key, label)| {
            [
                Span::styled(key, Style::new().fg(ACCENT)),
                Span::styled(format!(" {label}{gap}"), Style::new().fg(SECONDARY)),
            ]
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
