use super::{SourceSummary, source_share};
use crate::output::stdoutln;
use crate::presentation::semantic::Tone;
use crate::presentation::{
    RATIO_BAR_CELLS, WIDE_TABLE_MIN_WIDTH, budget_exhausted_note, cleanup, dynamic_table,
    header_cells, lower_bound_bytes, ratio_bar, right_align_columns, semantic,
};
use crate::runtime::{Glyphs, Ui};
use anyhow::Result;

const PERCENT_SCALE: f64 = 100.0;
const SCAN_SUMMARY_CAVEAT: &str = "Caveat: this summarizes only locations detected by this scan.";
const RIGHT_ALIGNED_COLUMNS: &[usize] = &[1, 2, 3];

pub(super) fn print_summary(report: &SourceSummary, ui: Ui) -> Result<()> {
    stdoutln!("{}", render_summary(report, ui))
}

pub(super) fn print_runtime_summary(report: &SourceSummary, ui: Ui) -> Result<()> {
    stdoutln!("{}", render_runtime_report(report, ui))
}

#[derive(Clone, Copy)]
pub(super) struct CompletionNotes {
    pub(super) truncated: bool,
    pub(super) incomplete: bool,
    pub(super) unvisited_dirs: u64,
    pub(super) ui: Ui,
}

pub(super) fn print_completion_notes(notes: CompletionNotes) -> Result<()> {
    stdoutln!("{}", render_completion_notes(notes))
}

pub(super) fn render_completion_notes(notes: CompletionNotes) -> String {
    let color_enabled = notes.ui.colors.stdout;
    let mut lines = Vec::new();
    if notes.truncated {
        let budget = budget_exhausted_note(notes.unvisited_dirs);
        lines.push(semantic::paint(
            notes.ui.prose(&budget),
            Tone::Review,
            color_enabled,
        ));
    }
    if notes.incomplete {
        let note = format!(
            "scan incomplete: some paths were not fully inspected or classified; {} values are lower bounds",
            notes.ui.glyphs.lower_bound
        );
        lines.push(semantic::paint(
            notes.ui.prose(&note),
            Tone::Review,
            color_enabled,
        ));
    }
    lines.push(semantic::paint(
        notes.ui.prose(SCAN_SUMMARY_CAVEAT),
        Tone::Secondary,
        color_enabled,
    ));
    lines.join("\n")
}

pub(super) fn render_summary(report: &SourceSummary, ui: Ui) -> String {
    if report.ecosystems.is_empty() {
        return crate::commands::scan::NO_STORAGE_DETECTED.to_owned();
    }
    let mut blocks = vec![
        semantic::paint(
            ui.prose("Detected storage by source:"),
            Tone::Heading,
            ui.colors.stdout,
        ),
        render_source_table(report, ui),
    ];
    if report.total_bytes_hardlinked > 0 {
        blocks.push(semantic::paint(
            ui.prose(&hardlink_note(report, ui.glyphs)),
            Tone::Secondary,
            ui.colors.stdout,
        ));
    }
    blocks.join("\n")
}

fn render_runtime_report(report: &SourceSummary, ui: Ui) -> String {
    if report.ecosystems.is_empty() {
        return semantic::paint(
            crate::commands::scan::NO_RUNTIME_LOCATIONS_DETECTED,
            Tone::Secondary,
            ui.colors.stdout,
        );
    }
    [
        semantic::paint(
            ui.prose("node-runtime (Not managed) by source:"),
            Tone::Heading,
            ui.colors.stdout,
        ),
        render_source_table(report, ui),
    ]
    .join("\n")
}

fn hardlink_note(report: &SourceSummary, glyphs: Glyphs) -> String {
    format!(
        "Of which {} is hardlink-shared; entries sharing links may sum above physical filesystem usage",
        lower_bound_bytes(report.lower_bound, report.total_bytes_hardlinked, glyphs)
    )
}

fn render_source_table(report: &SourceSummary, ui: Ui) -> String {
    if ui.width < WIDE_TABLE_MIN_WIDTH {
        render_compact_table(report, ui)
    } else {
        render_wide_table(report, ui)
    }
}

fn render_wide_table(report: &SourceSummary, ui: Ui) -> String {
    let color_enabled = ui.colors.stdout;
    let top_share = top_share_index(report);
    let mut table = dynamic_table(
        color_enabled,
        ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.set_header(header_cells(
        &["source", "on disk", "inodes", "share"],
        color_enabled,
    ));
    for (index, row) in report.ecosystems.iter().enumerate() {
        table.add_row([
            comfy_table::Cell::new(&row.ecosystem),
            comfy_table::Cell::new(lower_bound_bytes(
                row.lower_bound,
                row.bytes_allocated,
                ui.glyphs,
            )),
            comfy_table::Cell::new(cleanup::inode_count_label(
                row.lower_bound,
                row.inodes,
                ui.glyphs,
            )),
            share_cell(ShareCell {
                share: row.share,
                accent: Some(index) == top_share,
                color_enabled,
                glyphs: ui.glyphs,
            }),
        ]);
    }
    table.add_row(total_row(report, color_enabled, ui.glyphs));
    right_align_columns(&mut table, RIGHT_ALIGNED_COLUMNS);
    table.trim_fmt()
}

fn render_compact_table(report: &SourceSummary, ui: Ui) -> String {
    let color_enabled = ui.colors.stdout;
    let separator = ui.glyphs.separator;
    let top_share = top_share_index(report);
    let mut table = dynamic_table(
        color_enabled,
        ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    for (index, row) in report.ecosystems.iter().enumerate() {
        if index > 0 {
            table.add_row([comfy_table::Cell::new("")]);
        }
        table.add_row([comfy_table::Cell::new(&row.ecosystem)]);
        table.add_row([comfy_table::Cell::new(format!(
            "{} {separator} {}",
            lower_bound_bytes(row.lower_bound, row.bytes_allocated, ui.glyphs),
            cleanup::inode_total_label(row.lower_bound, row.inodes, ui.glyphs)
        ))]);
        table.add_row([share_cell(ShareCell {
            share: row.share,
            accent: Some(index) == top_share,
            color_enabled,
            glyphs: ui.glyphs,
        })]);
    }
    table.add_row([comfy_table::Cell::new("")]);
    let mut total = comfy_table::Cell::new("Total");
    let mut values = comfy_table::Cell::new(format!(
        "{} {separator} {} {separator} {}",
        lower_bound_bytes(report.lower_bound, report.total_bytes_allocated, ui.glyphs),
        cleanup::inode_total_label(report.lower_bound, report.total_inodes, ui.glyphs),
        format_source_share(source_share(
            report.total_bytes_allocated,
            report.total_bytes_allocated,
        ))
    ));
    if color_enabled {
        total = total.add_attribute(comfy_table::Attribute::Bold);
        values = values.add_attribute(comfy_table::Attribute::Bold);
    }
    table.add_row([total]);
    table.add_row([values]);
    table.trim_fmt()
}

fn total_row(
    report: &SourceSummary,
    color_enabled: bool,
    glyphs: Glyphs,
) -> [comfy_table::Cell; 4] {
    let mut cells = [
        comfy_table::Cell::new("Total"),
        comfy_table::Cell::new(lower_bound_bytes(
            report.lower_bound,
            report.total_bytes_allocated,
            glyphs,
        )),
        comfy_table::Cell::new(cleanup::inode_count_label(
            report.lower_bound,
            report.total_inodes,
            glyphs,
        )),
    ];
    if color_enabled {
        cells = cells.map(|cell| cell.add_attribute(comfy_table::Attribute::Bold));
    }
    let [total, bytes, inodes] = cells;
    // The share cell stays unstyled: its blank-bar padding must remain
    // line-trailing whitespace so trim_fmt can drop it in every color mode.
    let share = comfy_table::Cell::new(format_total_share(source_share(
        report.total_bytes_allocated,
        report.total_bytes_allocated,
    )));
    [total, bytes, inodes, share]
}

/// The Total row carries no bar, but its percent must still land in the
/// percent column: blank padding as wide as " <bar>" keeps it right-aligned
/// with the data rows' percents instead of the bar area.
fn format_total_share(share: f64) -> String {
    format!(
        "{}{}",
        format_source_share(share),
        " ".repeat(RATIO_BAR_CELLS + 1)
    )
}

struct ShareCell {
    share: f64,
    accent: bool,
    color_enabled: bool,
    glyphs: Glyphs,
}

/// The highest-share row carries the accent tone so the eye lands on the
/// dominant source first; every other bar stays dimmed.
fn share_cell(cell: ShareCell) -> comfy_table::Cell {
    let rendered = comfy_table::Cell::new(format_source_share_bar(cell.share, cell.glyphs));
    if !cell.color_enabled {
        rendered
    } else if cell.accent {
        rendered.fg(comfy_table::Color::Cyan)
    } else {
        rendered.add_attribute(comfy_table::Attribute::Dim)
    }
}

fn top_share_index(report: &SourceSummary) -> Option<usize> {
    let top = report
        .ecosystems
        .iter()
        .map(|row| row.share)
        .max_by(f64::total_cmp)?;
    report.ecosystems.iter().position(|row| row.share == top)
}

fn format_source_share(share: f64) -> String {
    format!("{:.1}%", share * PERCENT_SCALE)
}

pub(super) fn format_source_share_bar(share: f64, glyphs: Glyphs) -> String {
    format!(
        "{} {}",
        format_source_share(share),
        ratio_bar(share, glyphs)
    )
}
