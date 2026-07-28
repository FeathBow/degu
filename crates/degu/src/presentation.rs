use crate::runtime::OutputColors;
use std::ffi::OsStr;
use unicode_width::UnicodeWidthChar;

pub(crate) mod semantic;
mod terminal_text;

pub(crate) use terminal_text::escape_terminal_controls;

const BYTE_BASE: f64 = 1024.0;
/// Human layout ceiling: wider terminals keep prose and table rows readable
/// instead of stretching them across the full window.
pub(crate) const MAX_OUTPUT_WIDTH: u16 = 120;
pub(crate) const DEFAULT_OUTPUT_WIDTH: u16 = MAX_OUTPUT_WIDTH;
const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
