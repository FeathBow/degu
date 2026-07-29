use super::trash_resolution_error;
use std::path::Path;

#[test]
fn trash_resolution_failure_escapes_path_and_reason() {
    let error = trash_resolution_error(
        Path::new("/cache\u{1b}[31m"),
        "failed to inspect cache\nagain",
    );
    let rendered = format!("{error:#}");

    assert!(!rendered.chars().any(char::is_control));
    assert!(rendered.contains("/cache\\u{1b}[31m"));
    assert!(rendered.contains("cache\\nagain"));
}
