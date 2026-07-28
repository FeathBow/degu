use super::{FindingsTableOptions, age_label, render};
use crate::presentation::{WIDE_TABLE_MIN_WIDTH, escape_terminal_text};
use crate::runtime::{OutputColors, Ui};
use assertions::{
    assert_borderless, assert_escaped_controls, assert_lines_fit, assert_no_raw_controls,
    assert_wrapped_content,
};
use degu_core::finding::{DispositionMode, Finding};
use fixtures::{
    HOME, conda_findings, control_character_finding, huggingface_findings,
    oversized_source_finding, skipped_finding, truncated_finding,
};
use std::path::Path;

mod assertions;
mod fixtures;

const COMPACT_WIDTH: u16 = 40;
const NARROW_WIDTH: u16 = 80;
const STANDARD_WIDTH: u16 = 120;

fn terminal_ui(width: u16) -> Ui {
    Ui::test_terminal(width)
}

#[test]
fn age_labels_explain_fresh_and_unknown_values() {
    assert_eq!(age_label(Some(0)), "today");
    assert_eq!(age_label(Some(42)), "42d");
    assert_eq!(age_label(None), "unknown");
}

#[test]
fn standard_terminal_uses_readable_blocks_and_keeps_hf_paths_distinct() {
    let findings = huggingface_findings();

    let output = render_default(&findings, NARROW_WIDTH);

    assert_lines_fit(&output, NARROW_WIDTH);
    assert_wrapped_content(&output, "checkpoint-alpha");
    assert_wrapped_content(&output, "checkpoint-beta");
    assert_wrapped_content(&output, "研究--模型-e\\u{301}-🧪-checkpoint-gamma");
    assert!(!output.contains("on disk"));
    assert_wrapped_content(&output, "Needsreview");
    assert_wrapped_content(&output, "42didle");
    assert_wrapped_content(&output, "7inodes");
    assert_borderless(&output);
}

#[test]
fn wide_table_is_borderless_and_keeps_conda_paths_distinct() {
    let findings = conda_findings();

    let output = render_default(&findings, STANDARD_WIDTH);

    assert_lines_fit(&output, STANDARD_WIDTH);
    assert_wrapped_content(&output, "production-alpha");
    assert_wrapped_content(&output, "production-beta");
    assert!(output.contains("Not managed"));
    assert!(output.contains(" inodes "));
    assert!(output.contains(" idle "));
    assert_borderless(&output);
}

#[test]
fn compact_view_uses_readable_blocks_at_forty_columns() {
    let output = render_default(&huggingface_findings(), COMPACT_WIDTH);

    assert_lines_fit(&output, COMPACT_WIDTH);
    assert_wrapped_content(&output, "checkpoint-alpha");
    assert_wrapped_content(&output, "checkpoint-beta");
    assert!(output.contains("huggingface"));
    assert!(output.contains("16.0 KiB"));
    assert_wrapped_content(&output, "Needsreview");
    assert_wrapped_content(&output, "42didle");
    assert_wrapped_content(&output, "7inodes");
    assert!(
        output.contains("\n\n"),
        "findings are not separated:\n{output}"
    );
    assert_borderless(&output);
}

#[test]
fn incomplete_findings_render_metrics_as_lower_bounds() {
    for finding in [truncated_finding(), skipped_finding()] {
        let findings = std::slice::from_ref(&finding);
        for output in [
            render_default(findings, COMPACT_WIDTH),
            render_default(findings, STANDARD_WIDTH),
        ] {
            assert_wrapped_content(&output, "≥16.0KiB");
            assert_wrapped_content(&output, "≥7");
        }
        let details = FindingsTableOptions::new(terminal_ui(NARROW_WIDTH), true, Path::new(HOME));
        let output = render(findings, details);
        assert_wrapped_content(&output, "spaceondisk≥16.0KiB");
        assert_wrapped_content(&output, "inodes≥7");
    }
}

#[test]
fn compact_view_colors_only_the_policy() {
    crossterm::style::force_color_output(true);
    let findings = huggingface_findings();
    let options = FindingsTableOptions::new(colored_ui(COMPACT_WIDTH), false, Path::new(HOME));

    let output = render(&findings[..1], options);

    assert!(output.contains("\x1b[38;5;11m"), "{output:?}");
    assert_wrapped_content(&output, "Needsreview");
    assert!(!output.contains("\x1b[38;5;11mhuggingface"));
    assert!(output.contains("\x1b[2m"));
    assert_wrapped_content(&output, "42didle");
}

#[test]
fn grouped_wide_view_omits_cleanup_and_explains_restricted_findings() {
    let review = render_grouped(
        &huggingface_findings(),
        STANDARD_WIDTH,
        DispositionMode::OptIn,
    );
    let unmanaged = render_grouped(
        &conda_findings(),
        STANDARD_WIDTH,
        DispositionMode::ReportOnly,
    );

    for output in [&review, &unmanaged] {
        assert!(!output.contains("cleanup"), "{output}");
        assert!(!output.contains("Needs review"), "{output}");
        assert!(!output.contains("Not managed"), "{output}");
        assert!(output.contains("reason"), "{output}");
        assert_lines_fit(output, STANDARD_WIDTH);
    }
    assert_wrapped_content(&review, "costlytoregenerate");
    assert_wrapped_content(&unmanaged, "userasset");
}

#[test]
fn grouped_compact_view_keeps_metrics_and_reason_without_repeating_status() {
    let output = render_grouped(
        &huggingface_findings()[..1],
        COMPACT_WIDTH,
        DispositionMode::OptIn,
    );

    assert_lines_fit(&output, COMPACT_WIDTH);
    assert_wrapped_content(&output, "42didle");
    assert_wrapped_content(&output, "7inodes");
    assert_wrapped_content(&output, "Reason:costlytoregenerate");
    assert!(!output.contains("Needs review"));
    assert!(!output.contains("cleanup"));
}

#[test]
fn details_view_fits_narrow_width_and_contains_absolute_paths() {
    let findings = huggingface_findings();
    let options = FindingsTableOptions::new(terminal_ui(NARROW_WIDTH), true, Path::new(HOME));

    let output = render(&findings, options);

    assert_lines_fit(&output, NARROW_WIDTH);
    for finding in &findings {
        let path = escape_terminal_text(&finding.path().display().to_string());
        assert_wrapped_content(&output, &path);
    }
    assert!(!output.contains("~/"));
}

#[test]
fn grouped_details_keep_reason_without_repeating_cleanup_status() {
    let findings = huggingface_findings();
    let options = FindingsTableOptions::new(terminal_ui(NARROW_WIDTH), true, Path::new(HOME))
        .for_disposition(DispositionMode::OptIn);

    let output = render(&findings[..1], options);

    assert!(!output.contains("Needs review"), "{output}");
    assert_wrapped_content(&output, "cleanupreasoncostlytoregenerate");
    assert_wrapped_content(&output, "rationalerealisticnarrow-terminalfixture");
}

#[test]
fn wide_table_truncates_long_paths_onto_single_rows() {
    let findings = huggingface_findings();

    let output = render_default(&findings, STANDARD_WIDTH);

    assert!(output.contains("on disk"), "{output}");
    assert!(output.contains('…'), "{output}");
    assert_lines_fit(&output, STANDARD_WIDTH);
    assert_eq!(output.lines().count(), 1 + findings.len(), "{output}");
}

#[test]
fn wide_table_yields_to_compact_when_the_path_budget_collapses() {
    let output = render_default(&[oversized_source_finding()], STANDARD_WIDTH);

    assert!(!output.contains("on disk"), "{output}");
    assert_lines_fit(&output, STANDARD_WIDTH);
    assert_wrapped_content(&output, "~/.cache/some-tool");
}

#[test]
fn default_layout_switches_at_wide_width_boundary() {
    let findings = conda_findings();
    let narrow_width = WIDE_TABLE_MIN_WIDTH - 1;

    let narrow = render_default(&findings, narrow_width);
    let wide = render_default(&findings, WIDE_TABLE_MIN_WIDTH);

    assert_lines_fit(&narrow, narrow_width);
    assert_wrapped_content(&narrow, "42didle");
    assert_wrapped_content(&narrow, "7inodes");
    assert!(!narrow.contains("on disk"));
    assert_lines_fit(&wide, WIDE_TABLE_MIN_WIDTH);
    assert!(wide.contains(" idle "));
    assert!(wide.contains(" inodes "));
    assert!(wide.contains("on disk"));
}

// The CLI e2e pins the plain default and details views; these cover the
// color and grouped branches it cannot reach.
#[test]
fn colored_and_grouped_views_escape_terminal_controls() {
    let finding = control_character_finding();
    for details in [false, true] {
        let options = FindingsTableOptions::new(colored_ui(NARROW_WIDTH), details, Path::new(HOME));
        let output = render(std::slice::from_ref(&finding), options);
        assert_lines_fit(&output, NARROW_WIDTH);
        if details {
            assert_escaped_controls(&output);
        } else {
            assert_no_raw_controls(&output);
            assert_wrapped_content(&output, "e\\u{301}txt");
        }
    }
    let grouped_options =
        FindingsTableOptions::new(terminal_ui(COMPACT_WIDTH), false, Path::new(HOME))
            .for_disposition(DispositionMode::OptIn);
    let grouped = render(std::slice::from_ref(&finding), grouped_options);
    assert_lines_fit(&grouped, COMPACT_WIDTH);
    assert_no_raw_controls(&grouped);
    assert_wrapped_content(&grouped, "e\\u{301}txt");
}

fn render_default(findings: &[Finding], width: u16) -> String {
    let options = FindingsTableOptions::new(terminal_ui(width), false, Path::new(HOME));
    render(findings, options)
}

fn render_grouped(findings: &[Finding], width: u16, mode: DispositionMode) -> String {
    let options =
        FindingsTableOptions::new(terminal_ui(width), false, Path::new(HOME)).for_disposition(mode);
    render(findings, options)
}

fn colored_ui(width: u16) -> Ui {
    Ui {
        colors: OutputColors {
            stdout: true,
            stderr: false,
        },
        ..terminal_ui(width)
    }
}
