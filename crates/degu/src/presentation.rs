use crate::runtime::OutputColors;
use unicode_width::UnicodeWidthChar;

pub(crate) mod semantic;
mod terminal_text;

pub(crate) use terminal_text::escape_terminal_controls;

pub(crate) fn is_safe_terminal_character(character: char) -> bool {
    !character.is_control()
        && !matches!(character, '\u{2028}' | '\u{2029}')
        && !matches!(UnicodeWidthChar::width(character), None | Some(0))
}

#[derive(Clone, Copy)]
pub(crate) enum Severity {
    Error,
}

/// One lowercase rustc-style "<severity>: <text>" note on stderr; a
/// multi-line text keeps its line structure, with every continuation line
/// indented under the first. The crossterm color switch is process-global
/// and normally holds the stdout policy, so it is flipped to the stderr
/// policy for this write and restored afterwards.
pub(crate) fn print_stderr_note(severity: Severity, text: &str, colors: OutputColors) {
    let (prefix, tone) = match severity {
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
    fn stderr_note_continuation_lines_indent_under_the_prefix() {
        assert_eq!(
            indent_continuation_lines("TOML parse error at line 1\n  |\n1 | not toml", 7),
            "TOML parse error at line 1\n         |\n       1 | not toml"
        );
        assert_eq!(indent_continuation_lines("one line", 7), "one line");
        assert_eq!(indent_continuation_lines("", 7), "");
    }
}
