use super::render_trash_summary;
use crate::runtime::Ui;

#[test]
fn trash_summary_wraps_for_a_narrow_terminal() {
    use unicode_width::UnicodeWidthStr;

    let rendered = render_trash_summary(4096, 1, 0, false, false, Ui::test_terminal(32));

    assert!(
        rendered
            .lines()
            .all(|line| UnicodeWidthStr::width(line) <= 32),
        "{rendered}"
    );
    assert_eq!(
        rendered.replace('\n', " "),
        "Trash holds 4.0 KiB across 1 entry."
    );
}

#[test]
fn incomplete_trash_summary_reports_a_lower_bound() {
    let rendered = render_trash_summary(4096, 1, 0, false, true, Ui::test_terminal(80));

    assert_eq!(
        rendered.replace('\n', " "),
        "Trash holds \u{2265} 4.0 KiB across 1 entry."
    );
}

#[test]
fn a_truncated_entry_count_is_rendered_as_a_floor() {
    // Enumeration was cut short but the measure finished: the entry tally floors
    // to "≥ 3 entries" while the fully measured bytes stay exact.
    let rendered = render_trash_summary(4096, 3, 0, true, false, Ui::test_terminal(80));

    assert_eq!(
        rendered.replace('\n', " "),
        "Trash holds 4.0 KiB across \u{2265} 3 entries."
    );
}

#[test]
fn independent_bounds_each_floor_their_own_total() {
    let rendered = render_trash_summary(4096, 3, 0, true, true, Ui::test_terminal(80));

    assert_eq!(
        rendered.replace('\n', " "),
        "Trash holds \u{2265} 4.0 KiB across \u{2265} 3 entries."
    );
}

#[test]
fn unenumerated_trash_summary_reports_unknown_size() {
    let rendered = render_trash_summary(0, 0, 0, true, true, Ui::test_terminal(80));

    assert_eq!(
        rendered.replace('\n', " "),
        "Trash size unknown (scan budget reached)."
    );
}

#[test]
fn trash_summary_marks_a_hardlink_caveat() {
    let rendered = render_trash_summary(4096, 1, 2048, false, false, Ui::test_terminal(80));

    assert!(rendered.contains("hardlink-shared"), "{rendered}");
    assert!(rendered.contains("2.0 KiB"), "{rendered}");
}
