use super::is_safe_terminal_character;
use std::fmt::Write as _;

pub(crate) fn escape_terminal_text(value: &str) -> String {
    escape(value, true)
}

pub(crate) fn escape_terminal_controls(value: &str) -> String {
    escape(value, false)
}

fn escape(value: &str, escape_backslash: bool) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' if escape_backslash => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if !is_safe_terminal_character(character) => {
                write!(&mut escaped, "\\u{{{:x}}}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape_terminal_text;

    #[test]
    fn escaped_controls_do_not_collide_with_literal_escape_sequences() {
        for value in ["\u{1b}", "\u{200b}", "\u{301}"] {
            let escaped = escape_terminal_text(value);
            assert_ne!(escaped, escape_terminal_text(&escaped));
        }
    }
}
