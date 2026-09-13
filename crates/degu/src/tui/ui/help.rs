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
t             Show the staging trash, and come back
3 / enter     Open the selected record in full
space         Put the selected finding in the plan, or take it out
p             Preview the clean these choices describe
c             Run both, each with the CLI's own plan and confirmation
PgUp/PgDn     Move by one visible page
home/end      First / last finding or detail line
Esc           Back; clear a filter; otherwise quit
?             Show / close this help
q, Ctrl-C/D   Quit

Compact status: + Ready to clean; ? Needs review; · Not managed
Row marks: ✓ in the plan; ○ out of it; blank degu will not act on it
Ready to clean findings start in the plan; Needs review findings start out.
Staged entries start out of the purge; nothing is destroyed unless you choose it.
Runtime findings are Not managed and never join cache totals.
Nothing moves until you leave this screen and confirm the plan degu prints.";

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
    // A key the footer names must be a key that acts, and `c` does nothing
    // when the reader has taken everything out of both plans.
    let decided = app.has_work();
    let mut keys: Vec<(&str, &str)> = match app.view() {
        View::Help => vec![("Esc", "back"), ("q", "quit")],
        View::Staged => vec![
            ("↑↓", "move"),
            ("space", "toggle"),
            ("t", "findings"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Details if area.width >= DETAIL_FOOTER_WIDTH => vec![
            ("↑↓", "scroll"),
            ("PgUp/PgDn", "page"),
            ("Home/End", "ends"),
            ("Esc", "back"),
            ("q", "quit"),
        ],
        View::Details => vec![
            ("↑↓", "scroll"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser if area.width >= FULL_FOOTER_WIDTH => vec![
            ("↑↓", "move"),
            ("space", "toggle"),
            ("p", "preview"),
            ("1/2", "focus"),
            ("g", "group"),
            ("s", "sort"),
            ("Tab", "section"),
            ("3/Enter", "details"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser if area.width >= COMPACT_FOOTER_WIDTH => vec![
            ("↑↓", "move"),
            ("space", "toggle"),
            ("p", "preview"),
            ("Enter", "details"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Browser => vec![
            ("↑↓", "move"),
            ("space", "toggle"),
            ("?", "help"),
            ("q", "quit"),
        ],
    };
    if decided && matches!(app.view(), View::Browser | View::Staged) {
        let quit = keys.len() - 1;
        keys.insert(quit, ("c", "run"));
    }
    let keys = keys.as_slice();
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
