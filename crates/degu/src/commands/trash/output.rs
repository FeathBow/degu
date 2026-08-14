use std::path::Path;

use anyhow::Result;
use serde::Serialize;
use unicode_width::UnicodeWidthStr;

use crate::lifecycle::TrashEntry;
use crate::output::stdoutln;
use crate::presentation::cleanup::count_label;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    CELL_PADDING, PATH_BUDGET_FLOOR, WIDE_TABLE_MIN_WIDTH, display_path, dynamic_table,
    escape_terminal_text, header_cells, lower_bound_bytes, right_align_columns, semantic,
    truncate_path_middle,
};
use crate::runtime::Ui;

pub(crate) const TRASH_IS_EMPTY: &str = "Trash is empty.";
const WIDE_HEADERS: [&str; 4] = ["entry", "original", "on disk", "in trash"];
const RIGHT_ALIGNED_COLUMNS: [usize; 2] = [2, 3];
const INTERRUPTED_PURGE_NOTE: &str = "Interrupted purge claims remain in trash, cannot be undone automatically, and are never removed by automatic expiry. They are permanently deleted only after a new degu trash purge confirmation.";

#[derive(Clone, Copy)]
struct RenderOptions<'a> {
    home: &'a Path,
    ui: Ui,
}

#[derive(Serialize)]
struct TrashJsonRow<'a> {
    entry: &'a str,
    original: Option<&'a str>,
    bytes_allocated: u64,
    bytes_hardlinked: u64,
    age_days: u64,
    ambiguous: bool,
    interrupted_purge: bool,
    lower_bound: bool,
}

pub(super) fn print_json(rows: &[TrashEntry]) -> Result<()> {
    let (entries, omitted) = representable_rows(rows);
    if omitted > 0 {
        tracing::warn!(
            omitted,
            "omitted trash entries whose path is not valid UTF-8; report marked incomplete"
        );
    }
    let document = serde_json::json!({
        "entries": entries,
        "omitted": omitted,
    });
    stdoutln!("{}", serde_json::to_string_pretty(&document)?)
}

/// A non-UTF-8 entry (or original) path would fail the whole array's
/// serialization, losing every entry. Such rows are omitted and counted so the
/// rest survive; a lossy conversion is refused because two distinct byte paths
/// could collapse to one string and mislead automation acting on the output.
fn representable_rows(rows: &[TrashEntry]) -> (Vec<TrashJsonRow<'_>>, usize) {
    let mut entries = Vec::with_capacity(rows.len());
    let mut omitted = 0;
    for row in rows {
        match representable_row(row) {
            Some(row) => entries.push(row),
            None => omitted += 1,
        }
    }
    (entries, omitted)
}

fn representable_row(row: &TrashEntry) -> Option<TrashJsonRow<'_>> {
    let entry = row.entry.to_str()?;
    let original = match row.original.as_deref() {
        Some(path) => Some(path.to_str()?),
        None => None,
    };
    Some(TrashJsonRow {
        entry,
        original,
        bytes_allocated: row.bytes_allocated,
        bytes_hardlinked: row.bytes_hardlinked,
        age_days: row.age_days,
        ambiguous: row.ambiguous,
        interrupted_purge: row.interrupted_purge,
        lower_bound: row.lower_bound,
    })
}

pub(super) fn print_human(rows: &[TrashEntry], home: &Path, ui: Ui) -> Result<()> {
    stdoutln!("{}", render_human(rows, RenderOptions { home, ui }))
}

pub(super) fn print_outcomes(rows: &[TrashEntry], ui: Ui) -> Result<()> {
    stdoutln!("\n{}", render_outcomes(rows, ui))
}

fn render_outcomes(rows: &[TrashEntry], ui: Ui) -> String {
    let color_enabled = ui.colors.stdout;
    let can_restore = rows
        .iter()
        .any(|row| !row.interrupted_purge && row.original.is_some());
    let has_interrupted = rows.iter().any(|row| row.interrupted_purge);
    let mut outcomes = Vec::new();
    if can_restore {
        outcomes.push("Restore the latest clean:\n  degu undo".to_owned());
    }
    let delete_label = if has_interrupted {
        "Delete all listed entries, including legacy interrupted claims (confirm again):"
    } else {
        "Permanently delete all listed entries:"
    };
    let delete_label = ui.prose(delete_label);
    outcomes.push(format!(
        "{}\n  {}",
        semantic::paint(&delete_label, Tone::Destructive, color_enabled),
        semantic::paint("degu trash purge", Tone::Destructive, color_enabled)
    ));
    let heading = if can_restore {
        "Choose one outcome:"
    } else {
        "Available outcome:"
    };
    format!("{heading}\n\n{}", outcomes.join("\n\n"))
}

fn render_human(rows: &[TrashEntry], options: RenderOptions<'_>) -> String {
    if rows.is_empty() {
        return TRASH_IS_EMPTY.to_owned();
    }

    let mut sections = vec![render_rows(rows, options)];
    if rows.iter().any(|row| row.ambiguous) {
        sections.push(options.ui.prose(
            "ambiguous entries have an unverified operation state or recorded identity and are never auto-expired; inspect the operation history before acting",
        ));
    }
    if rows.iter().any(|row| row.interrupted_purge) {
        sections.push(options.ui.prose(INTERRUPTED_PURGE_NOTE));
    }
    let lower_bound = rows.iter().any(|row| row.lower_bound);
    let bytes_hardlinked = rows.iter().fold(0u64, |total, row| {
        total.saturating_add(row.bytes_hardlinked)
    });
    if bytes_hardlinked > 0 {
        sections.push(options.ui.prose(&format!(
            "{} is hardlink-shared; reclaimed space may be lower.",
            lower_bound_bytes(lower_bound, bytes_hardlinked, options.ui.glyphs)
        )));
    }
    let bytes_allocated = rows
        .iter()
        .fold(0u64, |total, row| total.saturating_add(row.bytes_allocated));
    sections.push(options.ui.prose(&format!(
        "Total trash: {} across {}",
        lower_bound_bytes(lower_bound, bytes_allocated, options.ui.glyphs),
        count_label(rows.len(), "entry", "entries")
    )));
    sections.join("\n")
}

fn render_rows(rows: &[TrashEntry], options: RenderOptions<'_>) -> String {
    if options.ui.width >= WIDE_TABLE_MIN_WIDTH
        && let Some(rendered) = render_wide_rows(rows, options)
    {
        return rendered;
    }
    rows.iter()
        .map(|row| render_compact_row(row, options))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn render_wide_rows(rows: &[TrashEntry], options: RenderOptions<'_>) -> Option<String> {
    let cells = rows
        .iter()
        .map(|row| table_row(row, options.home, options.ui.glyphs))
        .collect::<Vec<_>>();
    let (entry_budget, original_budget) = match options.ui.table_width() {
        Some(width) => path_budgets(&cells, width)?,
        None => (usize::MAX, usize::MAX),
    };
    let color_enabled = options.ui.colors.stdout;
    let ellipsis = options.ui.glyphs.ellipsis;
    let mut table = dynamic_table(
        color_enabled,
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.set_header(header_cells(&WIDE_HEADERS, color_enabled));
    for [entry, original, on_disk, in_trash] in cells {
        table.add_row([
            truncate_path_middle(&entry, entry_budget, ellipsis),
            truncate_path_middle(&original, original_budget, ellipsis),
            on_disk,
            in_trash,
        ]);
    }
    right_align_columns(&mut table, &RIGHT_ALIGNED_COLUMNS);
    Some(table.trim_fmt())
}

/// The wide layout has two flexible path columns; the shared budget approach
/// applies with the leftover split between them, shrinking only columns that
/// exceed their half.
fn path_budgets(cells: &[[String; 4]], width: u16) -> Option<(usize, usize)> {
    let column_width = |index: usize| {
        cells
            .iter()
            .map(|row| row[index].width())
            .chain([WIDE_HEADERS[index].width()])
            .max()
            .unwrap_or(0)
    };
    let fixed = (column_width(2) + CELL_PADDING) + (column_width(3) + CELL_PADDING);
    let total = usize::from(width).saturating_sub(fixed + 2 * CELL_PADDING);
    let (entry, original) = (column_width(0), column_width(1));
    if entry + original <= total {
        return Some((entry, original));
    }
    let half = total / 2;
    if entry <= half {
        let budget = total - entry;
        return (budget >= PATH_BUDGET_FLOOR).then_some((entry, budget));
    }
    if original <= half {
        let budget = total - original;
        return (budget >= PATH_BUDGET_FLOOR).then_some((budget, original));
    }
    let budgets = (total - half, half);
    (budgets.0 >= PATH_BUDGET_FLOOR && budgets.1 >= PATH_BUDGET_FLOOR).then_some(budgets)
}

fn table_row(row: &TrashEntry, home: &Path, glyphs: crate::runtime::Glyphs) -> [String; 4] {
    [
        entry_label(row),
        original_label(row, home),
        lower_bound_bytes(row.lower_bound, row.bytes_allocated, glyphs),
        format!("{}d", row.age_days),
    ]
}

fn render_compact_row(row: &TrashEntry, options: RenderOptions<'_>) -> String {
    let color_enabled = options.ui.colors.stdout;
    let path_budget = options.ui.compact_path_budget();
    let ellipsis = options.ui.glyphs.ellipsis;
    let mut table = dynamic_table(
        color_enabled,
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.add_row(header_cells(&["entry"], color_enabled));
    table.add_row([comfy_table::Cell::new(truncate_path_middle(
        &entry_label(row),
        path_budget,
        ellipsis,
    ))]);
    table.add_row(header_cells(&["original"], color_enabled));
    table.add_row([comfy_table::Cell::new(truncate_path_middle(
        &original_label(row, options.home),
        path_budget,
        ellipsis,
    ))]);
    table.add_row([comfy_table::Cell::new(format!(
        "{} on disk {} {}d in trash",
        lower_bound_bytes(row.lower_bound, row.bytes_allocated, options.ui.glyphs),
        options.ui.glyphs.separator,
        row.age_days
    ))]);
    table.trim_fmt()
}

fn entry_label(row: &TrashEntry) -> String {
    escape_terminal_text(&row.entry.display().to_string())
}

fn original_label(row: &TrashEntry, home: &Path) -> String {
    let mut original = row
        .original
        .as_ref()
        .map(|path| display_path(path, home))
        .map(|path| escape_terminal_text(&path))
        .unwrap_or_else(|| "-".to_string());
    if row.ambiguous {
        original.push_str(" (ambiguous)");
    }
    if row.interrupted_purge {
        original.push_str(" (interrupted purge; not undoable)");
    }
    original
}

#[cfg(test)]
mod tests {
    use super::{RenderOptions, render_human, render_outcomes};
    use crate::lifecycle::TrashEntry;
    use crate::presentation::WIDE_TABLE_MIN_WIDTH;
    use crate::runtime::Ui;
    use std::path::{Path, PathBuf};
    use unicode_width::UnicodeWidthStr;

    fn row() -> TrashEntry {
        TrashEntry {
            entry: PathBuf::from(
                "/state/degu/trash/0001-a-very-long-entry-name-for-responsive-layout",
            ),
            original: Some(PathBuf::from(
                "/home/user/a-very-long-original-cache-path-for-responsive-layout",
            )),
            bytes_allocated: 4096,
            bytes_hardlinked: 0,
            age_days: 3,
            ambiguous: false,
            interrupted_purge: false,
            lower_bound: false,
        }
    }

    fn options(width: u16) -> RenderOptions<'static> {
        RenderOptions {
            home: Path::new("/home/user"),
            ui: Ui::test_terminal(width),
        }
    }

    #[test]
    fn trash_list_respects_narrow_and_wide_terminal_widths() {
        for width in [32, 40, 80, 100, 120] {
            let rendered = render_human(&[row()], options(width));
            assert!(
                rendered
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= usize::from(width)),
                "width {width}:\n{rendered}"
            );
        }
    }

    fn incomplete_row() -> TrashEntry {
        let mut row = row();
        row.lower_bound = true;
        row.bytes_hardlinked = 2048;
        row
    }

    #[test]
    fn trash_list_marks_a_lower_bound_size_and_hardlink_caveat() {
        for width in [40, 120] {
            let rendered = render_human(&[incomplete_row()], options(width));
            assert!(rendered.contains('\u{2265}'), "width {width}:\n{rendered}");
            assert!(
                rendered.contains("hardlink-shared"),
                "width {width}:\n{rendered}"
            );
            assert!(
                rendered.contains("Total trash: \u{2265}"),
                "width {width}:\n{rendered}"
            );
        }
    }

    #[test]
    fn trash_list_switches_to_a_wide_table_at_the_wide_threshold() {
        let compact = render_human(&[row()], options(WIDE_TABLE_MIN_WIDTH - 1));
        let wide = render_human(&[row()], options(WIDE_TABLE_MIN_WIDTH));

        assert_eq!(compact.lines().next().map(str::trim), Some("entry"));
        assert!(wide.lines().next().unwrap().contains("original"));
    }

    #[test]
    fn trash_list_truncates_paths_instead_of_wrapping_them() {
        for width in [40, WIDE_TABLE_MIN_WIDTH] {
            let rendered = render_human(&[row()], options(width));
            assert!(rendered.contains('…'), "width {width}:\n{rendered}");
            assert!(
                rendered.contains("responsive-layout"),
                "width {width}:\n{rendered}"
            );
        }
    }

    #[test]
    fn outcome_guidance_fits_a_32_column_terminal() {
        let normal = row();
        let mut interrupted = row();
        interrupted.original = None;
        interrupted.interrupted_purge = true;
        let mixed = render_outcomes(&[row(), interrupted], Ui::test_terminal(32));
        assert!(mixed.contains("degu undo"));
        assert!(mixed.contains("including legacy interrupted"));
        let mut interrupted_only = row();
        interrupted_only.original = None;
        interrupted_only.interrupted_purge = true;
        let interrupted_only = render_outcomes(&[interrupted_only], Ui::test_terminal(32));
        assert!(!interrupted_only.contains("degu undo"));
        for guidance in [
            render_outcomes(&[normal], Ui::test_terminal(32)),
            mixed,
            interrupted_only,
        ] {
            assert!(
                guidance
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= 32)
            );
        }
    }
}
