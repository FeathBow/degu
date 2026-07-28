use unicode_width::UnicodeWidthStr;

pub(super) fn assert_lines_fit(output: &str, width: u16) {
    let widest = output.lines().map(UnicodeWidthStr::width).max().unwrap();
    assert!(
        widest <= usize::from(width),
        "widest line is {widest}, limit is {width}:\n{output}"
    );
}

pub(super) fn assert_borderless(output: &str) {
    assert!(
        !output.lines().any(is_rule),
        "unexpected table rule:\n{output}"
    );
    assert!(
        output.lines().all(|line| line.trim_end() == line),
        "unexpected trailing whitespace:\n{output}"
    );
}

fn is_rule(line: &str) -> bool {
    !line.is_empty() && line.chars().all(|character| matches!(character, '-' | '='))
}

pub(super) fn assert_no_raw_controls(output: &str) {
    assert!(!output.contains("\u{1b}[2J"), "{output:?}");
    assert!(!output.contains('\t'), "{output:?}");
    assert!(!output.contains('\r'), "{output:?}");
    assert!(!output.contains('\u{202e}'), "{output:?}");
    for invisible in [
        '\u{200b}', '\u{2060}', '\u{feff}', '\u{2028}', '\u{2029}', '\u{301}',
    ] {
        assert!(!output.contains(invisible), "{output:?}");
    }
}

pub(super) fn assert_escaped_controls(output: &str) {
    assert_no_raw_controls(output);
    for escaped in [
        "\\u{1b}[2J",
        "\\n",
        "\\r",
        "\\t",
        "\\\\literal",
        "\\u{202e}",
        "\\u{200b}",
        "\\u{2060}",
        "\\u{feff}",
        "\\u{2028}",
        "\\u{2029}",
        "e\\u{301}",
    ] {
        assert_wrapped_content(output, escaped);
    }
}

pub(super) fn assert_wrapped_content(output: &str, expected: &str) {
    let compact = output
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(
        compact.contains(expected),
        "missing {expected:?}:\n{output}"
    );
}
