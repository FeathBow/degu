use unicode_width::UnicodeWidthChar;

pub(super) fn columns(value: &str) -> usize {
    value
        .chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

// Keep the path tail and measure terminal columns, not UTF-8 bytes.
pub(super) fn elide(value: &str, budget: usize) -> String {
    if columns(value) <= budget {
        return value.to_owned();
    }
    if budget <= 1 {
        return "…".repeat(budget);
    }
    let mut kept: Vec<char> = Vec::new();
    let mut used = 1; // the ellipsis itself
    for character in value.chars().rev() {
        let width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + width > budget {
            break;
        }
        used += width;
        kept.push(character);
    }
    kept.reverse();
    format!("…{}", kept.into_iter().collect::<String>())
}

pub(super) fn pad(value: &str, budget: usize) -> String {
    let mut out = elide(value, budget);
    for _ in columns(&out)..budget {
        out.push(' ');
    }
    out
}

// Keep spaces and unbroken path tails; document offsets use usize.
pub(super) fn wrapped(value: &str, width: usize) -> Vec<String> {
    if value.is_empty() || width == 0 {
        return vec![String::new()];
    }
    let mut remaining = value;
    let mut lines = Vec::new();
    while !remaining.is_empty() {
        let end = line_end(remaining, width);
        lines.push(remaining[..end].to_owned());
        remaining = &remaining[end..];
    }
    lines
}

fn line_end(value: &str, width: usize) -> usize {
    let mut used = 0;
    let mut word_end = None;
    for (index, character) in value.char_indices() {
        used += UnicodeWidthChar::width(character).unwrap_or(0);
        if used > width {
            return word_end.unwrap_or_else(|| {
                if index == 0 {
                    character.len_utf8()
                } else {
                    index
                }
            });
        }
        if character.is_whitespace() {
            word_end = Some(index + character.len_utf8());
        }
    }
    value.len()
}
