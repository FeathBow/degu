use crate::runtime::{Glyphs, OutputColors, Ui};
use degu_core::finding::Finding;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(crate) mod cleanup;
pub(crate) mod semantic;
pub(crate) mod shell;
mod terminal_text;

pub(crate) use terminal_text::{escape_terminal_controls, escape_terminal_text};

const BYTE_BASE: f64 = 1024.0;
/// Human layout ceiling: wider terminals keep prose and table rows readable
/// instead of stretching them across the full window.
pub(crate) const MAX_OUTPUT_WIDTH: u16 = 120;
pub(crate) const DEFAULT_OUTPUT_WIDTH: u16 = MAX_OUTPUT_WIDTH;
pub(crate) const WIDE_TABLE_MIN_WIDTH: u16 = 100;
/// comfy_table pads every column with one space on each side.
pub(crate) const CELL_PADDING: usize = 2;
/// Below this many columns a truncated path stops being recognizable, so
/// wide tables yield to their compact layouts instead.
pub(crate) const PATH_BUDGET_FLOOR: usize = 24;
const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
const BUDGET_RERUN_ACTION: &str = "Rerun without --budget or use a longer duration.";

pub(crate) fn output_width() -> u16 {
    resolve_output_width(comfy_table::Table::new().width())
}

/// A borderless output table. With a width (a terminal) cells arrange
/// dynamically inside it; without one (piped output) arrangement is
/// disabled so cells are never wrapped at an assumed width.
pub(crate) fn dynamic_table(
    color_enabled: bool,
    width: Option<u16>,
    preset: &str,
) -> comfy_table::Table {
    let mut table = comfy_table::Table::new();
    table.load_preset(preset);
    match width {
        Some(width) => {
            table
                .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
                .set_width(width);
        }
        None => {
            table.set_content_arrangement(comfy_table::ContentArrangement::Disabled);
        }
    }
    if color_enabled {
        table.enforce_styling();
        table.style_text_only();
    }
    table
}

pub(crate) fn resolve_output_width(detected: Option<u16>) -> u16 {
    detected
        .filter(|width| *width > 0)
        .map_or(DEFAULT_OUTPUT_WIDTH, |width| width.min(MAX_OUTPUT_WIDTH))
}

pub(crate) fn terminal_is_dumb() -> bool {
    term_value_is_dumb(std::env::var_os("TERM").as_deref())
}

pub(crate) fn is_safe_terminal_character(character: char) -> bool {
    !character.is_control()
        && !matches!(character, '\u{2028}' | '\u{2029}')
        && !matches!(UnicodeWidthChar::width(character), None | Some(0))
}

fn term_value_is_dumb(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("dumb"))
}

pub(crate) fn header_cells(labels: &[&str], color_enabled: bool) -> Vec<comfy_table::Cell> {
    labels
        .iter()
        .map(|label| {
            let cell = comfy_table::Cell::new(label);
            if color_enabled {
                cell.add_attribute(comfy_table::Attribute::Bold)
            } else {
                cell
            }
        })
        .collect()
}

pub(crate) fn right_align_columns(table: &mut comfy_table::Table, columns: &[usize]) {
    for &index in columns {
        if let Some(column) = table.column_mut(index) {
            column.set_cell_alignment(comfy_table::CellAlignment::Right);
        }
    }
}

pub(crate) fn display_path(path: &Path, home: &Path) -> String {
    if home == Path::new("/") {
        return path.display().to_string();
    }
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= BYTE_BASE && unit < UNITS.len() - 1 {
        value /= BYTE_BASE;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

const MILLIS_PER_SECOND: u128 = 1_000;
const TENTHS_PER_MINUTE: u128 = 600;
const SECONDS_PER_MINUTE: u64 = 60;

/// Elapsed-time phrase for command summary lines: whole milliseconds under
/// a second, tenths of a second under a minute, then minutes and seconds.
pub(crate) fn human_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < MILLIS_PER_SECOND {
        return format!("{millis}ms");
    }
    let tenths = (millis + 50) / 100;
    if tenths < TENTHS_PER_MINUTE {
        return format!("{}.{}s", tenths / 10, tenths % 10);
    }
    let seconds = u64::try_from((millis + 500) / MILLIS_PER_SECOND).unwrap_or(u64::MAX);
    format!(
        "{}m {}s",
        seconds / SECONDS_PER_MINUTE,
        seconds % SECONDS_PER_MINUTE
    )
}

#[derive(Clone, Copy)]
pub(crate) enum Severity {
    Warning,
    Error,
}

/// One lowercase rustc-style "<severity>: <text>" note on stderr; a
/// multi-line text keeps its line structure, with every continuation line
/// indented under the first. The crossterm color switch is process-global
/// and normally holds the stdout policy, so it is flipped to the stderr
/// policy for this write and restored afterwards.
pub(crate) fn print_stderr_note(severity: Severity, text: &str, colors: OutputColors) {
    let (prefix, tone) = match severity {
        Severity::Warning => ("warning:", semantic::Tone::Review),
        Severity::Error => ("error:", semantic::Tone::Destructive),
    };
    crossterm::style::force_color_output(colors.stderr);
    eprintln!(
        "{} {}",
        semantic::paint(prefix, tone, colors.stderr),
        indent_continuation_lines(text, prefix.len() + 1)
    );
    crossterm::style::force_color_output(colors.stdout);
}

/// Continuation lines sit under the note text, past the "<severity>: "
/// prefix, so a multi-line sub-error reads as one indented block.
fn indent_continuation_lines(text: &str, indent: usize) -> String {
    let margin = " ".repeat(indent);
    let mut lines = text.lines();
    let mut indented = lines.next().unwrap_or_default().to_owned();
    for line in lines {
        indented.push('\n');
        indented.push_str(&margin);
        indented.push_str(line);
    }
    indented
}

/// Deterministic budget for a table's one flexible path column: the full
/// width minus every fixed column's measured content plus padding, so
/// comfy_table never has to hard-wrap a path mid-word. `None` demands the
/// compact layout instead.
pub(crate) fn path_budget(width: u16, fixed_content_widths: &[usize]) -> Option<usize> {
    let fixed = fixed_content_widths
        .iter()
        .map(|content| content + CELL_PADDING)
        .sum::<usize>();
    let budget = usize::from(width).saturating_sub(fixed + CELL_PADDING);
    (budget >= PATH_BUDGET_FLOOR).then_some(budget)
}

/// Middle-truncates a display path to `budget` columns without breaking words:
/// middle components collapse into the ellipsis, the basename survives intact
/// whenever it fits, and only an oversized basename loses its head.
pub(crate) fn truncate_path_middle(path: &str, budget: usize, ellipsis: &str) -> String {
    if path.width() <= budget {
        return path.to_owned();
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() > 2 {
        let head = components[0];
        for dropped_until in 2..components.len() {
            let candidate = [&[head, ellipsis], &components[dropped_until..]]
                .concat()
                .join("/");
            if candidate.width() <= budget {
                return candidate;
            }
        }
    }
    let basename = components[components.len() - 1];
    let tail_only = format!("{ellipsis}/{basename}");
    if components.len() > 1 && tail_only.width() <= budget {
        return tail_only;
    }
    truncate_word_start(basename, budget, ellipsis)
}

fn truncate_word_start(word: &str, budget: usize, ellipsis: &str) -> String {
    let budget = budget.saturating_sub(ellipsis.width());
    let mut tail_width = 0;
    let mut start = word.len();
    for (index, character) in word.char_indices().rev() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if tail_width + character_width > budget {
            break;
        }
        tail_width += character_width;
        start = index;
    }
    format!("{ellipsis}{}", &word[start..])
}

pub(crate) fn lower_bound_bytes(lower_bound: bool, bytes: u64, glyphs: Glyphs) -> String {
    if lower_bound {
        format!("{} {}", glyphs.lower_bound, human_bytes(bytes))
    } else {
        human_bytes(bytes)
    }
}

pub(crate) fn wrap_words(text: &str, width: u16) -> String {
    let width = usize::from(width.max(1));
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() || current.width() + 1 + word.width() <= width {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines.join("\n")
}

pub(crate) fn print_hardlink_summary(
    findings: &[Finding],
    scan_lower_bound: bool,
    ui: Ui,
) -> anyhow::Result<()> {
    let bytes_hardlinked = findings.iter().fold(0u64, |total, finding| {
        total.saturating_add(finding.bytes_hardlinked())
    });
    if bytes_hardlinked > 0 {
        let lower_bound = scan_lower_bound || findings.iter().any(Finding::measurement_incomplete);
        let sentence = format!(
            "{} is hardlink-shared; reclaimed space may be lower.",
            lower_bound_bytes(lower_bound, bytes_hardlinked, ui.glyphs)
        );
        crate::output::stdoutln!("{}", ui.prose(&sentence))?;
    }
    Ok(())
}

/// Announces lower-bound results ahead of the totals they qualify; the
/// wording carries the meaning so the warning tone only reinforces it.
/// `marked_totals` says whether any rendered total carries the lower-bound
/// mark; without one the honest claim is missing results, not lower bounds.
pub(crate) fn print_scan_incomplete_warning(
    incomplete: bool,
    marked_totals: bool,
    ui: Ui,
) -> anyhow::Result<()> {
    if !incomplete {
        return Ok(());
    }
    let warning = if marked_totals {
        format!(
            "Scan incomplete: totals marked {} are lower bounds.",
            ui.glyphs.lower_bound
        )
    } else {
        "Scan incomplete: results may be missing.".to_owned()
    };
    crate::output::stdoutln!("{}", ui.toned_prose(0, &warning, semantic::Tone::Review))
}

pub(crate) fn any_hardlinked(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.bytes_hardlinked() > 0)
}

/// The budget note without the lower-bounds clause: the callers announce
/// lower bounds at the top of their output, so the footer keeps only the
/// facts and the rerun action.
pub(crate) fn print_scan_footer(
    truncated: bool,
    unvisited_dirs: u64,
    ui: Ui,
) -> anyhow::Result<()> {
    if truncated {
        let note = format!(
            "{}. {BUDGET_RERUN_ACTION}",
            budget_exhausted_facts(unvisited_dirs)
        );
        crate::output::stdoutln!("{}", ui.section(&ui.prose(&note)))?;
    }
    Ok(())
}

fn budget_exhausted_facts(unvisited_dirs: u64) -> String {
    match unvisited_dirs {
        0 => "budget exhausted: results are incomplete".to_owned(),
        1 => "budget exhausted: results are incomplete (1 directory unvisited)".to_owned(),
        count => {
            format!("budget exhausted: results are incomplete ({count} directories unvisited)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/user";

    #[test]
    fn display_path_renders_exact_home_as_bare_tilde() {
        assert_eq!(display_path(Path::new(HOME), Path::new(HOME)), "~");
    }

    #[test]
    fn display_path_keeps_paths_outside_home_verbatim() {
        assert_eq!(
            display_path(Path::new("/scratch/cache"), Path::new(HOME)),
            "/scratch/cache"
        );
        assert_eq!(
            display_path(Path::new("/home/user2/.cache"), Path::new(HOME)),
            "/home/user2/.cache"
        );
    }

    #[test]
    fn display_path_never_compresses_when_home_is_root() {
        assert_eq!(
            display_path(Path::new("/var/cache"), Path::new("/")),
            "/var/cache"
        );
    }

    #[test]
    fn lower_bound_bytes_prefixes_incomplete_measurements() {
        for (lower_bound, glyphs, expected) in [
            (true, Glyphs::ASCII, ">= 2.0 KiB"),
            (true, Glyphs::UNICODE, "\u{2265} 2.0 KiB"),
            (false, Glyphs::ASCII, "2.0 KiB"),
            (false, Glyphs::UNICODE, "2.0 KiB"),
        ] {
            assert_eq!(lower_bound_bytes(lower_bound, 2048, glyphs), expected);
        }
    }

    #[test]
    fn human_duration_scales_units_on_fixed_boundaries() {
        for (millis, expected) in [
            (0u64, "0ms"),
            (320, "320ms"),
            (999, "999ms"),
            (1_000, "1.0s"),
            (1_400, "1.4s"),
            (1_449, "1.4s"),
            (1_450, "1.5s"),
            (59_940, "59.9s"),
            (59_960, "1m 0s"),
            (72_000, "1m 12s"),
            (3_601_000, "60m 1s"),
        ] {
            assert_eq!(
                human_duration(Duration::from_millis(millis)),
                expected,
                "{millis}ms"
            );
        }
    }

    #[test]
    fn output_width_rejects_zero_sized_pseudo_terminals() {
        assert_eq!(resolve_output_width(None), DEFAULT_OUTPUT_WIDTH);
        assert_eq!(resolve_output_width(Some(0)), DEFAULT_OUTPUT_WIDTH);
        assert_eq!(resolve_output_width(Some(80)), 80);
    }

    #[test]
    fn output_width_caps_ultra_wide_terminals() {
        assert_eq!(
            resolve_output_width(Some(MAX_OUTPUT_WIDTH)),
            MAX_OUTPUT_WIDTH
        );
        assert_eq!(resolve_output_width(Some(121)), MAX_OUTPUT_WIDTH);
        assert_eq!(resolve_output_width(Some(240)), MAX_OUTPUT_WIDTH);
    }

    #[test]
    fn stderr_note_continuation_lines_indent_under_the_prefix() {
        assert_eq!(
            indent_continuation_lines("TOML parse error at line 1\n  |\n1 | not toml", 7),
            "TOML parse error at line 1\n         |\n       1 | not toml"
        );
        assert_eq!(indent_continuation_lines("one line", 7), "one line");
        assert_eq!(indent_continuation_lines("", 7), "");
    }

    #[test]
    fn dumb_terminal_detection_is_exact() {
        assert!(term_value_is_dumb(Some(OsStr::new("dumb"))));
        assert!(!term_value_is_dumb(Some(OsStr::new("xterm-256color"))));
        assert!(!term_value_is_dumb(None));
    }

    #[test]
    fn path_truncation_prefers_dropping_middle_components() {
        assert_eq!(
            truncate_path_middle("~/.cache/pip", 24, Glyphs::UNICODE.ellipsis),
            "~/.cache/pip"
        );
        assert_eq!(
            truncate_path_middle("~/.cache/huggingface/hub/models--org--name", 30, "…"),
            "~/…/hub/models--org--name"
        );
        assert_eq!(
            truncate_path_middle("/scratch/user/caches/torch/kernels", 26, "..."),
            "/.../caches/torch/kernels"
        );
    }

    #[test]
    fn path_truncation_keeps_the_basename_tail_when_nothing_else_fits() {
        assert_eq!(
            truncate_path_middle(
                "~/.cache/hub/models--org--very-long-checkpoint-alpha",
                24,
                "…"
            ),
            "…y-long-checkpoint-alpha"
        );
        assert_eq!(truncate_path_middle("~/.cache/研究模型", 8, "…"), "…究模型");
    }
}
