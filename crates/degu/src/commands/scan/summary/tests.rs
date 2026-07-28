use super::output::{
    CompletionNotes, format_source_share_bar, render_completion_notes, render_summary,
};
use super::{SourceRow, SourceSummary};
use crate::presentation::WIDE_TABLE_MIN_WIDTH;
use crate::runtime::{Glyphs, Ui};
use unicode_width::UnicodeWidthStr;

const KIBIBYTE: u64 = 1024;
const FIXTURE_BYTES: u64 = 16 * KIBIBYTE;
const FIXTURE_INODES: u64 = 7;

fn terminal_ui(width: u16) -> Ui {
    Ui::test_terminal(width)
}

fn render_at_width(report: &SourceSummary, ui: Ui) -> String {
    [
        render_summary(report, ui),
        render_completion_notes(CompletionNotes {
            truncated: report.truncated,
            incomplete: report.incomplete,
            unvisited_dirs: 0,
            ui,
        }),
    ]
    .join("\n")
}

#[test]
fn scan_summary_combines_share_percentage_and_bar() {
    assert_eq!(
        format_source_share_bar(0.667, Glyphs::UNICODE),
        "66.7% ███████░░░"
    );
    assert_eq!(
        format_source_share_bar(0.667, Glyphs::ASCII),
        "66.7% #######---"
    );
}

#[test]
fn scan_summary_human_report_fits_forty_and_fifty_columns() {
    let report = fixture_report();

    for width in [40, 50] {
        let rendered = render_at_width(&report, terminal_ui(width));
        let widest = rendered.lines().map(UnicodeWidthStr::width).max().unwrap();
        let normalized = rendered.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(widest <= usize::from(width), "width {width}:\n{rendered}");
        for expected in [
            "package-manager-with-a-long-name",
            "16.0 KiB",
            "7 inodes",
            "100.0%",
            "detected by this scan",
        ] {
            assert!(
                normalized.contains(expected),
                "missing {expected:?}:\n{rendered}"
            );
        }
    }
}

#[test]
fn scan_summary_wide_human_report_keeps_table_columns_and_share_bar() {
    let rendered = render_at_width(&fixture_report(), terminal_ui(WIDE_TABLE_MIN_WIDTH));

    for expected in ["source", "on disk", "inodes", "share", "██████████"] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?}:\n{rendered}"
        );
    }
}

// The Total row has no bar, but its percent must land in the percent
// column, aligned with the data rows, not right-aligned to the bar area.
#[test]
fn wide_summary_total_percent_aligns_with_the_data_row_percents() {
    let rendered = render_summary(&fixture_report(), terminal_ui(WIDE_TABLE_MIN_WIDTH));
    let line_for = |needle: &str| {
        rendered
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("missing {needle:?}:\n{rendered}"))
    };

    let data = line_for("package-manager-with-a-long-name");
    let total = line_for("Total");

    assert_eq!(
        data.find('%'),
        total.find('%'),
        "Total percent misaligned:\ndata:  {data}\ntotal: {total}"
    );
    assert!(
        !total.contains('█'),
        "Total row must keep its bar cells blank"
    );
    assert_eq!(total, total.trim_end(), "no trailing whitespace");
}

#[test]
fn scan_summary_human_report_switches_layout_at_wide_boundary() {
    let report = fixture_report();
    let compact_width = WIDE_TABLE_MIN_WIDTH - 1;
    let compact = render_at_width(&report, terminal_ui(compact_width));
    let wide = render_at_width(&report, terminal_ui(WIDE_TABLE_MIN_WIDTH));

    assert!(!compact.contains("on disk"));
    assert!(wide.contains("on disk"));
    assert!(
        compact
            .lines()
            .all(|line| UnicodeWidthStr::width(line) <= usize::from(compact_width))
    );
    assert!(
        wide.lines()
            .all(|line| UnicodeWidthStr::width(line) <= usize::from(WIDE_TABLE_MIN_WIDTH))
    );
}

#[test]
fn truncated_scan_summary_marks_inode_counts_as_lower_bounds() {
    let mut report = fixture_report();
    report.truncated = true;
    report.lower_bound = true;
    report.ecosystems[0].lower_bound = true;

    for width in [40, WIDE_TABLE_MIN_WIDTH] {
        let rendered = render_at_width(&report, terminal_ui(width));
        let normalized = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            normalized.matches("\u{2265} 7").count() >= 2,
            "width {width}:\n{rendered}"
        );
    }
}

fn fixture_report() -> SourceSummary {
    SourceSummary {
        total_bytes_allocated: FIXTURE_BYTES,
        total_bytes_hardlinked: 0,
        total_inodes: FIXTURE_INODES,
        ecosystems: vec![SourceRow {
            ecosystem: "package-manager-with-a-long-name".to_owned(),
            bytes_allocated: FIXTURE_BYTES,
            bytes_hardlinked: 0,
            inodes: FIXTURE_INODES,
            share: 1.0,
            lower_bound: false,
        }],
        incomplete: false,
        lower_bound: false,
        truncated: false,
    }
}
