//! Escape report text before passing it to terminal widgets.

use std::fmt::Write as _;

use unicode_width::UnicodeWidthChar;

fn is_safe(character: char) -> bool {
    !character.is_control()
        && !matches!(character, '\u{2028}' | '\u{2029}')
        && !matches!(UnicodeWidthChar::width(character), None | Some(0))
}

pub fn text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if !is_safe(character) => {
                write!(&mut escaped, "\\u{{{:x}}}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}
