mod view;

use crate::output::stdoutln;
use crate::presentation::{
    cleanup, display_path, dynamic_table, escape_terminal_text, lower_bound_bytes,
};
use crate::runtime::Ui;
use anyhow::Result;
use degu_core::finding::{DispositionMode, Finding, FindingKind};
use std::path::Path;
const DETAIL_LABEL_COLUMN: usize = 0;
const LOCATION_NUMBER_OFFSET: usize = 1;

#[derive(Clone, Copy)]
pub(crate) struct FindingsTableOptions<'a> {
    ui: Ui,
    details: bool,
    home: &'a Path,
    presentation: FindingsTablePresentation,
}

#[derive(Clone, Copy)]
enum FindingsTablePresentation {
    Mixed,
    Grouped(DispositionMode),
    Plan,
}

impl<'a> FindingsTableOptions<'a> {
    pub(crate) fn new(ui: Ui, details: bool, home: &'a Path) -> Self {
        Self {
            ui,
            details,
            home,
            presentation: FindingsTablePresentation::Mixed,
        }
    }

    pub(crate) fn for_disposition(mut self, mode: DispositionMode) -> Self {
        self.presentation = FindingsTablePresentation::Grouped(mode);
        self
    }

    pub(crate) fn for_plan(mut self) -> Self {
        self.presentation = FindingsTablePresentation::Plan;
        self
    }

    fn color_enabled(self) -> bool {
        self.ui.colors.stdout
    }

    fn is_grouped(self) -> bool {
        !matches!(self.presentation, FindingsTablePresentation::Mixed)
    }

    fn is_plan(self) -> bool {
        matches!(self.presentation, FindingsTablePresentation::Plan)
    }

    fn shows_reason(self) -> bool {
        matches!(
            self.presentation,
            FindingsTablePresentation::Grouped(
                DispositionMode::OptIn | DispositionMode::ReportOnly
            )
        )
    }
}

pub(crate) fn render(findings: &[Finding], options: FindingsTableOptions<'_>) -> String {
    if options.details {
        render_details(findings, options)
    } else {
        view::render(findings, options)
    }
}

pub(crate) fn print(findings: &[Finding], options: FindingsTableOptions<'_>) -> Result<()> {
    stdoutln!("{}", render(findings, options))
}

fn render_details(findings: &[Finding], options: FindingsTableOptions<'_>) -> String {
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| detail_block(index, finding, options))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn detail_block(index: usize, finding: &Finding, options: FindingsTableOptions<'_>) -> String {
    let mut table = dynamic_table(
        options.color_enabled(),
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    for row in detail_rows(finding, options) {
        table.add_row(row);
    }
    if let Some(column) = table.column_mut(DETAIL_LABEL_COLUMN) {
        column.set_constraint(comfy_table::ColumnConstraint::ContentWidth);
    }
    format!(
        "location {}\n{}",
        index + LOCATION_NUMBER_OFFSET,
        table.trim_fmt()
    )
}

fn secondary_cells(finding: &Finding, ui: Ui) -> [comfy_table::Cell; 2] {
    let mut age = comfy_table::Cell::new(age_label(finding.age_days()));
    let mut inodes = comfy_table::Cell::new(cleanup::inode_count_label(
        finding.measurement_incomplete(),
        finding.inodes(),
        ui.glyphs,
    ));
    if ui.colors.stdout {
        age = age.add_attribute(comfy_table::Attribute::Dim);
        inodes = inodes.add_attribute(comfy_table::Attribute::Dim);
    }
    [age, inodes]
}

fn detail_rows(
    finding: &Finding,
    options: FindingsTableOptions<'_>,
) -> Vec<[comfy_table::Cell; 2]> {
    let mut rows = common_detail_rows(finding, options.ui);
    if !options.is_grouped() {
        rows.push([
            comfy_table::Cell::new("cleanup"),
            disposition_cell(finding.disposition().mode, options.color_enabled()),
        ]);
    }
    rows.extend([
        detail_row("kind", kind_label(finding.kind())),
        detail_row("rationale", finding.rationale()),
    ]);
    if !options.is_plan() {
        rows.push(detail_row(
            "cleanup reason",
            finding.disposition().reason.as_deref().unwrap_or("-"),
        ));
    }
    rows
}

fn common_detail_rows(finding: &Finding, ui: Ui) -> Vec<[comfy_table::Cell; 2]> {
    let [age, inodes] = secondary_cells(finding, ui);
    vec![
        detail_row("source", finding.ecosystem()),
        detail_row("path", absolute_path_label(finding.path())),
        detail_row(
            "space on disk",
            lower_bound_bytes(
                finding.measurement_incomplete(),
                finding.bytes_allocated(),
                ui.glyphs,
            ),
        ),
        [comfy_table::Cell::new("idle"), age],
        [comfy_table::Cell::new("inodes"), inodes],
    ]
}

fn detail_row(label: &str, value: impl std::fmt::Display) -> [comfy_table::Cell; 2] {
    [comfy_table::Cell::new(label), comfy_table::Cell::new(value)]
}

fn compact_path_label(path: &Path, home: &Path) -> String {
    escape_terminal_text(&display_path(path, home))
}

fn absolute_path_label(path: &Path) -> String {
    escape_terminal_text(&path.display().to_string())
}

fn disposition_cell(mode: DispositionMode, color_enabled: bool) -> comfy_table::Cell {
    let cell = comfy_table::Cell::new(cleanup::label(mode));
    style_disposition(cell, mode, color_enabled)
}

fn style_disposition(
    cell: comfy_table::Cell,
    mode: DispositionMode,
    color_enabled: bool,
) -> comfy_table::Cell {
    if !color_enabled {
        return cell;
    }
    match mode {
        DispositionMode::Eligible => cell.fg(comfy_table::Color::Green),
        DispositionMode::OptIn => cell.fg(comfy_table::Color::Yellow),
        DispositionMode::ReportOnly => cell,
    }
}

fn kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::PackageCache => "package_cache",
        FindingKind::ModelCache => "model_cache",
        FindingKind::BuildArtifact => "build_artifact",
        FindingKind::ContainerCache => "container_cache",
        FindingKind::Checkpoint => "checkpoint",
        FindingKind::Environment => "environment",
        FindingKind::Other => "other",
    }
}

fn age_label(age_days: Option<u64>) -> String {
    match age_days {
        Some(0) => "today".to_string(),
        Some(days) => format!("{days}d"),
        None => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests;
