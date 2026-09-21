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
space         Put the selected finding or staged entry in, or take it out
p             Preview the clean these choices describe
c             Run what you decided: the purge, the clean, or both
PgUp/PgDn     Move by one visible page
home/end      First / last row, or first / last detail line
Esc           Back; clear a filter; otherwise quit
?             Show / close this help
q, Ctrl-C/D   Quit

Compact status: + Ready to clean; ? Needs review; · Not managed
Row marks: ✓ in the plan; ○ out of it; blank degu will not act on it
Ready to clean findings start in the plan; Needs review findings start out.
Staged entries start unchosen. A confirmed clean also runs its expiry plan.
Runtime findings are Not managed and never join cache totals.
Nothing moves until you leave this screen and confirm the plan degu prints.";

/// Footer key lists per view, richest first. The footer shows the first one
/// that fits, so a narrow terminal loses the least useful keys rather than
/// having its last entry clipped off the end.
const BROWSER_KEYS: &[&[(&str, &str)]] = &[
    &[
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
    &[
        ("↑↓", "move"),
        ("space", "toggle"),
        ("p", "preview"),
        ("Enter", "details"),
        ("?", "help"),
        ("q", "quit"),
    ],
    &[
        ("↑↓", "move"),
        ("space", "toggle"),
        ("?", "help"),
        ("q", "quit"),
    ],
    &[("space", "toggle"), ("q", "quit")],
    &[("q", "quit")],
];

const STAGED_KEYS: &[&[(&str, &str)]] = &[
    &[
        ("↑↓", "move"),
        ("space", "toggle"),
        ("t", "findings"),
        ("Esc", "back"),
        ("?", "help"),
        ("q", "quit"),
    ],
    &[
        ("↑↓", "move"),
        ("space", "toggle"),
        ("Esc", "back"),
        ("q", "quit"),
    ],
    &[("space", "toggle"), ("q", "quit")],
    &[("q", "quit")],
];

const DETAILS_KEYS: &[&[(&str, &str)]] = &[
    &[
        ("↑↓", "scroll"),
        ("PgUp/PgDn", "page"),
        ("Home/End", "ends"),
        ("Esc", "back"),
        ("q", "quit"),
    ],
    &[
        ("↑↓", "scroll"),
        ("Esc", "back"),
        ("?", "help"),
        ("q", "quit"),
    ],
    &[("Esc", "back"), ("q", "quit")],
    &[("q", "quit")],
];

const HELP_KEYS: &[&[(&str, &str)]] = &[&[("Esc", "back"), ("q", "quit")], &[("q", "quit")]];

/// The key list a footer draws, `c run` included, for a view at a width.
///
/// Composition happens before measurement, so what is measured is what is
/// drawn.
fn footer_keys(view: View, run: bool, width: u16) -> Vec<(&'static str, &'static str)> {
    let candidates = match view {
        View::Help => HELP_KEYS,
        View::Staged => STAGED_KEYS,
        View::Details => DETAILS_KEYS,
        View::Browser => BROWSER_KEYS,
    };
    for keys in candidates {
        // The last candidate is the way out on its own. A footer too cramped
        // for anything else keeps that rather than an action key.
        let list = if keys.len() > 1 {
            with_run(keys, run)
        } else {
            keys.to_vec()
        };
        if fits(&list, width) {
            return list;
        }
    }
    Vec::new()
}

/// `c` goes immediately before `q`, so the two decisions that end the screen
/// sit together.
fn with_run(keys: &[(&'static str, &'static str)], run: bool) -> Vec<(&'static str, &'static str)> {
    let mut all = keys.to_vec();
    if run {
        all.insert(all.len().saturating_sub(1), ("c", "run"));
    }
    all
}

/// Three spaces separate entries, so a list of n spends n - 1 gaps. Counting
/// a gap after the last one costs the reader a key at exactly the widths where
/// keys are scarcest.
fn fits(keys: &[(&'static str, &'static str)], width: u16) -> bool {
    footer_line(keys).width() <= usize::from(width)
}

/// The one place a key list becomes cells, so measuring and drawing cannot
/// disagree about what a footer costs.
fn footer_line(keys: &[(&'static str, &'static str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for &(key, label) in keys {
        if !spans.is_empty() {
            spans.push(Span::styled("   ", Style::new().fg(SECONDARY)));
        }
        spans.push(Span::styled(key, Style::new().fg(ACCENT)));
        spans.push(Span::styled(
            format!(" {label}"),
            Style::new().fg(SECONDARY),
        ));
    }
    Line::from(spans)
}

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
    let run = app.can_run() && app.view().runs_cleanup();
    let keys = footer_keys(app.view(), run, area.width);
    frame.render_widget(Paragraph::new(footer_line(&keys)), area);
}

#[cfg(test)]
mod tests {
    use super::super::text::columns;
    use super::*;
    use ratatui::buffer::Buffer;

    /// `c` is only offered where it acts, so the other views are never asked
    /// to make room for it. Taken from the view rather than restated, so this
    /// cannot drift from the key handler.
    fn runs_for(view: View) -> &'static [bool] {
        if view.runs_cleanup() {
            &[false, true]
        } else {
            &[false]
        }
    }

    fn views() -> [View; 4] {
        [View::Browser, View::Staged, View::Details, View::Help]
    }

    /// What a key list should read as, spelled out here rather than taken from
    /// the code under test, so the two can disagree.
    fn expected(keys: &[(&str, &str)]) -> String {
        keys.iter()
            .map(|(key, label)| format!("{key} {label}"))
            .collect::<Vec<_>>()
            .join("   ")
    }

    /// What ratatui actually leaves on screen, read back cell by cell. A
    /// footer that overruns its area is truncated here exactly as a terminal
    /// would truncate it, so this catches a list the arithmetic thought fit.
    fn rendered(keys: &[(&'static str, &'static str)], width: u16) -> String {
        let area = Rect::new(0, 0, width, 1);
        let mut buffer = Buffer::empty(area);
        Paragraph::new(footer_line(keys)).render(area, &mut buffer);
        (0..width)
            .map(|x| buffer[(x, 0)].symbol())
            .collect::<String>()
            .trim_end()
            .to_owned()
    }

    /// Whatever the footer chooses at a width, the terminal shows all of it.
    #[test]
    fn a_footer_is_drawn_whole_or_not_chosen() {
        for view in views() {
            for &run in runs_for(view) {
                for width in 0..=140u16 {
                    let keys = footer_keys(view, run, width);
                    assert_eq!(
                        rendered(&keys, width),
                        expected(&keys),
                        "{view:?} at {width} columns drew a clipped footer"
                    );
                }
            }
        }
    }

    /// A footer appears exactly where the exit key fits, and whatever appears
    /// names it. Leaving a reader without the key that ends the session is the
    /// worst thing a cramped footer can do — whether by clipping it, or by
    /// drawing nothing where `q quit` would have gone. The width that decides
    /// it is what the keys read as: counting the gap that separates entries
    /// after the last one as well would blank the four narrowest footers.
    #[test]
    fn a_footer_names_the_way_out_whenever_it_fits() {
        let exit_only = expected(&[("q", "quit")]);
        let narrowest = u16::try_from(columns(&exit_only)).expect("a short footer");
        for view in views() {
            for width in 0..=140u16 {
                for &run in runs_for(view) {
                    let keys = footer_keys(view, run, width);
                    assert_eq!(
                        !keys.is_empty(),
                        width >= narrowest,
                        "{view:?} at {width} columns drew {keys:?}, and {exit_only:?} needs {narrowest}"
                    );
                    assert!(
                        keys.is_empty() || keys.iter().any(|(key, _)| *key == "q"),
                        "{view:?} at {width} columns kept {keys:?} without the exit key"
                    );
                }
            }
        }
    }

    /// `c run` appears exactly where it acts, beside the exit key, and only
    /// once there is something to run.
    #[test]
    fn the_run_key_sits_beside_the_exit_key_when_there_is_work() {
        for view in [View::Browser, View::Staged] {
            let keys = footer_keys(view, true, 120);
            let run = keys
                .iter()
                .position(|(key, label)| (*key, *label) == ("c", "run"))
                .unwrap_or_else(|| panic!("{view:?} offered no run key at 120 columns"));
            let quit = keys.iter().position(|(key, _)| *key == "q").unwrap();
            assert_eq!(run + 1, quit, "the run key should sit just before quit");
            assert!(
                !footer_keys(view, false, 120)
                    .iter()
                    .any(|(key, _)| *key == "c")
            );
        }
    }

    /// The run key is counted against the width like any other, so a terminal
    /// that held the full list without it steps down to a shorter one.
    #[test]
    fn making_room_for_the_run_key_can_narrow_the_list() {
        let full = footer_keys(View::Browser, false, 200);
        let exact = u16::try_from(columns(&expected(&full))).expect("a footer narrower than u16");

        assert_eq!(footer_keys(View::Browser, false, exact), full);
        let expected_next = with_run(BROWSER_KEYS[1], true);
        assert_eq!(
            footer_keys(View::Browser, true, exact),
            expected_next,
            "the same width should step down one candidate once the run key is there"
        );
    }
}
