/// Asserts `line` carries an elapsed phrase introduced by " in " and shaped
/// like `320ms`, `1.4s`, or `1m 12s`, without pinning a wall-clock value.
/// Trailing stats after the phrase (separated by " - " or " · ") are
/// ignored.
pub fn assert_elapsed_suffix(line: &str) {
    let (_, suffix) = line
        .trim_end()
        .rsplit_once(" in ")
        .unwrap_or_else(|| panic!("missing elapsed suffix: {line:?}"));
    let phrase = suffix
        .split(" - ")
        .next()
        .unwrap()
        .split(" \u{b7} ")
        .next()
        .unwrap();
    assert!(
        is_elapsed_phrase(phrase),
        "unexpected elapsed shape {phrase:?} in {line:?}"
    );
}

pub fn assert_no_elapsed_suffix(line: &str) {
    assert!(
        !line.contains(" in "),
        "unexpected elapsed suffix: {line:?}"
    );
}

fn is_elapsed_phrase(phrase: &str) -> bool {
    if let Some(millis) = phrase.strip_suffix("ms") {
        return is_digits(millis);
    }
    let Some(value) = phrase.strip_suffix('s') else {
        return false;
    };
    if let Some((minutes, seconds)) = value.split_once("m ") {
        return is_digits(minutes) && is_digits(seconds);
    }
    matches!(
        value.split_once('.'),
        Some((whole, tenth)) if is_digits(whole) && is_digits(tenth)
    )
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}
