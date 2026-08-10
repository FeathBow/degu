use super::{
    FindingsTableOptions, age_label, compact_path_label, disposition_cell, secondary_cells,
};
use crate::presentation::{
    WIDE_TABLE_MIN_WIDTH, cleanup, dynamic_table, escape_terminal_controls, header_cells,
    lower_bound_bytes, path_budget, right_align_columns, truncate_path_middle,
};
use comfy_table::Cell;
use degu_core::finding::Finding;
use unicode_width::UnicodeWidthStr;

const ALLOCATED_COLUMN: usize = 1;
const WIDE_IDLE_COLUMN: usize = 2;
const WIDE_INODES_COLUMN: usize = 3;
const WIDE_NUMERIC_COLUMNS: [usize; 3] = [ALLOCATED_COLUMN, WIDE_IDLE_COLUMN, WIDE_INODES_COLUMN];
const MIXED_HEADERS: [&str; 6] = ["source", "on disk", "idle", "inodes", "cleanup", "path"];
const GROUPED_HEADERS: [&str; 5] = ["source", "on disk", "idle", "inodes", "path"];
const GROUPED_REASON_HEADERS: [&str; 6] = ["source", "on disk", "idle", "inodes", "reason", "path"];

pub(super) fn render(findings: &[Finding], options: FindingsTableOptions<'_>) -> String {
    if options.ui.width >= WIDE_TABLE_MIN_WIDTH
        && let Some(rendered) = render_table(findings, options)
    {
        return rendered;
    }
    render_compact(findings, options)
}

fn render_table(findings: &[Finding], options: FindingsTableOptions<'_>) -> Option<String> {
    let headers = table_headers(options);
    let largest = largest_row_index(findings);
    let rows = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| fixed_cells(finding, options, Some(index) == largest))
        .collect::<Vec<_>>();
    let budget = match options.ui.table_width() {
        Some(width) => path_budget(width, &fixed_widths(headers, &rows))?,
        None => usize::MAX,
    };
    let mut table = dynamic_table(
        options.color_enabled(),
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.set_header(header_cells(headers, options.color_enabled()));
    constrain_fixed_columns(&mut table, headers.len() - 1);
    for (finding, mut row) in findings.iter().zip(rows) {
        row.push(Cell::new(truncate_path_middle(
            &compact_path_label(finding.path(), options.home),
            budget,
            options.ui.glyphs.ellipsis,
        )));
        table.add_row(row);
    }
    right_align_columns(&mut table, &WIDE_NUMERIC_COLUMNS);
    Some(table.trim_fmt())
}

fn fixed_widths(headers: &[&str], rows: &[Vec<Cell>]) -> Vec<usize> {
    let fixed_count = headers.len() - 1;
    let mut widths = headers[..fixed_count]
        .iter()
        .map(|header| header.width())
        .collect::<Vec<_>>();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.content().width());
        }
    }
    widths
}

fn table_headers(options: FindingsTableOptions<'_>) -> &'static [&'static str] {
    if options.shows_reason() {
        &GROUPED_REASON_HEADERS
    } else if options.is_grouped() {
        &GROUPED_HEADERS
    } else {
        &MIXED_HEADERS
    }
}

fn constrain_fixed_columns(table: &mut comfy_table::Table, count: usize) {
    for index in 0..count {
        if let Some(column) = table.column_mut(index) {
            column.set_constraint(comfy_table::ColumnConstraint::ContentWidth);
        }
    }
}

/// The largest finding in a rendered group, whose size cell gains weight
/// (bold, never a color) so it cannot clash with the safety-class colors.
fn largest_row_index(findings: &[Finding]) -> Option<usize> {
    let largest = findings.iter().map(Finding::bytes_allocated).max()?;
    findings
        .iter()
        .position(|finding| finding.bytes_allocated() == largest)
}

fn fixed_cells(
    finding: &Finding,
    options: FindingsTableOptions<'_>,
    largest: bool,
) -> Vec<comfy_table::Cell> {
    let [age, inodes] = secondary_cells(finding, options.ui);
    let mut size = Cell::new(lower_bound_bytes(
        finding.measurement_incomplete(),
        finding.bytes_allocated(),
        options.ui.glyphs,
    ));
    if largest && options.color_enabled() {
        size = size.add_attribute(comfy_table::Attribute::Bold);
    }
    let mut row = vec![Cell::new(finding.ecosystem()), size, age, inodes];
    if !options.is_grouped() {
        row.push(disposition_cell(
            finding.disposition().mode,
            options.color_enabled(),
        ));
    }
    if options.shows_reason() {
        row.push(Cell::new(disposition_reason(finding)));
    }
    row
}

fn render_compact(findings: &[Finding], options: FindingsTableOptions<'_>) -> String {
    findings
        .iter()
        .map(|finding| compact_block(finding, options))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn compact_block(finding: &Finding, options: FindingsTableOptions<'_>) -> String {
    let summary = compact_summary(finding, options);
    let mut path = dynamic_table(
        options.color_enabled(),
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    path.add_row([Cell::new(truncate_path_middle(
        &compact_path_label(finding.path(), options.home),
        options.ui.compact_path_budget(),
        options.ui.glyphs.ellipsis,
    ))]);
    let mut lines = vec![summary, path.trim_fmt()];
    if options.shows_reason() {
        lines.push(format!("Reason: {}", disposition_reason(finding)));
    }
    lines.join("\n")
}

fn compact_summary(finding: &Finding, options: FindingsTableOptions<'_>) -> String {
    let separator = options.ui.glyphs.separator;
    let primary = vec![
        Cell::new(format!("{} {separator} ", finding.ecosystem())),
        Cell::new(lower_bound_bytes(
            finding.measurement_incomplete(),
            finding.bytes_allocated(),
            options.ui.glyphs,
        )),
    ];
    let mut metrics = vec![
        muted_cell(
            format!("{} idle {separator} ", age_label(finding.age_days())),
            options.color_enabled(),
        ),
        muted_cell(
            cleanup::inode_total_label(
                finding.measurement_incomplete(),
                finding.inodes(),
                options.ui.glyphs,
            ),
            options.color_enabled(),
        ),
    ];
    if !options.is_grouped() {
        metrics.push(Cell::new(format!(" {separator} ")));
        metrics.push(disposition_cell(
            finding.disposition().mode,
            options.color_enabled(),
        ));
    }
    format!(
        "{}\n{}",
        compact_row(primary, options),
        compact_row(metrics, options)
    )
}

fn compact_row(cells: Vec<comfy_table::Cell>, options: FindingsTableOptions<'_>) -> String {
    let mut table = dynamic_table(
        options.color_enabled(),
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    let cell_count = cells.len();
    table.add_row(cells);
    for index in 0..cell_count {
        table.column_mut(index).unwrap().set_padding((0, 0));
    }
    table.trim_fmt()
}

fn disposition_reason(finding: &Finding) -> String {
    let reason = finding.disposition().reason.as_deref().unwrap_or("-");
    let reason =
        cleanup::short_reason(reason, finding.ecosystem()).unwrap_or_else(|| reason.to_owned());
    escape_terminal_controls(&reason)
}

fn muted_cell(value: impl std::fmt::Display, color_enabled: bool) -> comfy_table::Cell {
    let cell = Cell::new(value);
    if color_enabled {
        cell.add_attribute(comfy_table::Attribute::Dim)
    } else {
        cell
    }
}
