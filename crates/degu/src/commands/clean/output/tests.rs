use super::{staged_note, trash_resolution_error};
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

#[test]
fn a_run_needing_manual_recovery_never_offers_undo() {
    for sealed_authority in [false, true] {
        let note = staged_note(sealed_authority, true).unwrap_or_default();
        assert!(
            !note.contains("restore with 'degu undo'"),
            "sealed_authority={sealed_authority}: {note}"
        );
        let ordinary = staged_note(sealed_authority, false).expect("a note");
        assert!(ordinary.contains("restore with 'degu undo'"), "{ordinary}");
    }
}
