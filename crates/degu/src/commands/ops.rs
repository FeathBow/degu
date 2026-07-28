use crate::lifecycle::Lifecycle;
use crate::output::stdoutln;
use crate::presentation::{
    WIDE_TABLE_MIN_WIDTH, display_path, dynamic_table, escape_terminal_text as escaped,
    header_cells, path_budget, truncate_path_middle,
};
use crate::runtime::Ui;
use anyhow::Result;
use degu_core::oplog::{OpAction, OpOutcome, OpRecord};
use serde::Serialize;
use std::path::Path;
use unicode_width::UnicodeWidthStr;

const WIDE_HEADERS: [&str; 5] = ["ts", "command", "action", "path", "outcome"];
const PATH_COLUMN: usize = 3;
pub(crate) const NO_OPERATIONS_RECORDED: &str = "No operations recorded.";

#[derive(Clone, Copy)]
struct RenderOptions<'a> {
    home: &'a Path,
    ui: Ui,
}

pub(crate) fn run(json: bool, ui: Ui) -> Result<()> {
    let ctx = degu_core::ecosystem::DetectCtx::from_process()?;
    let records = Lifecycle::new(&ctx).operations()?;
    if json {
        stdoutln!("{}", serde_json::to_string_pretty(&json_records(&records))?)?;
        return Ok(());
    }
    let options = RenderOptions {
        home: &ctx.home,
        ui,
    };
    stdoutln!("{}", render_human(&records, options))
}

#[derive(Serialize)]
struct OperationJson<'a> {
    ts: &'a str,
    tool_version: &'a str,
    command: &'a str,
    action: OpAction,
    path: &'a Path,
    bytes_allocated: u64,
    inodes: u64,
    trash_entry: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reclamation_id: Option<&'a str>,
    outcome: &'a OpOutcome,
}

fn json_records(records: &[OpRecord]) -> Vec<OperationJson<'_>> {
    records
        .iter()
        .map(|record| OperationJson {
            ts: &record.ts,
            tool_version: &record.tool_version,
            command: &record.command,
            action: record.action,
            path: &record.path,
            bytes_allocated: record.bytes_allocated,
            inodes: record.inodes,
            trash_entry: record.trash_entry.as_deref(),
            reclamation_id: record.reclamation_id.as_deref(),
            outcome: &record.outcome,
        })
        .collect()
}

fn render_human(records: &[OpRecord], options: RenderOptions<'_>) -> String {
    if records.is_empty() {
        return NO_OPERATIONS_RECORDED.to_owned();
    }
    if options.ui.width >= WIDE_TABLE_MIN_WIDTH
        && let Some(rendered) = render_wide(records, options)
    {
        return rendered;
    }
    render_compact(records, options)
}

fn render_wide(records: &[OpRecord], options: RenderOptions<'_>) -> Option<String> {
    let rows = (0..records.len())
        .map(|index| table_row(records, index, options.home))
        .collect::<Vec<_>>();
    let budget = match options.ui.table_width() {
        Some(width) => path_budget(width, &fixed_widths(&rows))?,
        None => usize::MAX,
    };
    let color_enabled = options.ui.colors.stdout;
    let mut table = dynamic_table(
        color_enabled,
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.set_header(header_cells(&WIDE_HEADERS, color_enabled));
    for [ts, command, action, path, outcome] in rows {
        table.add_row([
            ts,
            command,
            action,
            truncate_path_middle(&path, budget, options.ui.glyphs.ellipsis),
            outcome,
        ]);
    }
    Some(table.trim_fmt())
}

fn fixed_widths(rows: &[[String; 5]]) -> Vec<usize> {
    WIDE_HEADERS
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != PATH_COLUMN)
        .map(|(index, header)| {
            rows.iter()
                .map(|row| row[index].width())
                .chain([header.width()])
                .max()
                .unwrap_or(0)
        })
        .collect()
}

fn render_compact(records: &[OpRecord], options: RenderOptions<'_>) -> String {
    (0..records.len())
        .map(|index| compact_block(records, index, options))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn compact_block(records: &[OpRecord], index: usize, options: RenderOptions<'_>) -> String {
    let [ts, command, action, path, outcome] = table_row(records, index, options.home);
    let separator = options.ui.glyphs.separator;
    let summary = format!("{command} {separator} {action} {separator} {outcome}");
    let color_enabled = options.ui.colors.stdout;
    let mut table = dynamic_table(
        color_enabled,
        options.ui.table_width(),
        comfy_table::presets::NOTHING,
    );
    table.add_row(header_cells(&[&summary], color_enabled));
    table.add_row([ts]);
    table.add_row([truncate_path_middle(
        &path,
        options.ui.compact_path_budget(),
        options.ui.glyphs.ellipsis,
    )]);
    table.trim_fmt()
}

fn table_row(records: &[OpRecord], index: usize, home: &Path) -> [String; 5] {
    let record = &records[index];
    [
        escaped(&record.ts),
        escaped(&record.command),
        action_label(record.action).to_string(),
        escaped(&display_path(&record.path, home)),
        outcome_human(records, index),
    ]
}

fn action_label(action: OpAction) -> &'static str {
    match action {
        OpAction::Trash => "trash",
        OpAction::Purge => "purge",
        OpAction::Restore => "restore",
    }
}

fn outcome_human(records: &[OpRecord], index: usize) -> String {
    let record = &records[index];
    match &record.outcome {
        OpOutcome::Pending if pending_is_interrupted(records, index) => "interrupted".to_string(),
        OpOutcome::Pending => "pending".to_string(),
        OpOutcome::Ok => "ok".to_string(),
        OpOutcome::Failed { reason } => format!("failed: {}", escaped(reason)),
    }
}

fn pending_is_interrupted(records: &[OpRecord], index: usize) -> bool {
    let pending = &records[index];
    records.get(index + 1).is_none_or(|record| {
        record.action != pending.action
            || record.path != pending.path
            || record.trash_entry != pending.trash_entry
            || record.reclamation_id != pending.reclamation_id
            || matches!(record.outcome, OpOutcome::Pending)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Ui;
    use std::path::PathBuf;
    use unicode_width::UnicodeWidthStr;

    const HOME: &str = "/home/me";

    fn failed_record() -> OpRecord {
        OpRecord {
            ts: "time\nvalue".to_owned(),
            tool_version: "0.1.0".to_owned(),
            command: "clean\u{1b}[31m".to_owned(),
            action: OpAction::Trash,
            path: PathBuf::from("/home/me/cache\rpath"),
            bytes_allocated: 0,
            inodes: 0,
            trash_entry: None,
            reclamation_id: None,
            expected_identity: None,
            destination_parent: None,
            outcome: OpOutcome::Failed {
                reason: "failure\treason".to_owned(),
            },
        }
    }

    fn long_path_record() -> OpRecord {
        OpRecord {
            path: PathBuf::from(
                "/home/me/.cache/huggingface/hub/models--org--a-very-long-checkpoint-name-for-truncation",
            ),
            outcome: OpOutcome::Ok,
            ..failed_record()
        }
    }

    #[test]
    fn human_row_escapes_operation_log_text() {
        let records = [failed_record()];
        let row = table_row(&records, 0, Path::new(HOME));

        assert!(row.iter().all(|cell| !cell.chars().any(char::is_control)));
        assert_eq!(row[0], "time\\nvalue");
        assert_eq!(row[1], "clean\\u{1b}[31m");
        assert_eq!(row[3], "~/cache\\rpath");
        assert_eq!(row[4], "failed: failure\\treason");

        let json = serde_json::to_value(json_records(&records)).unwrap();
        let outcome = &json[0]["outcome"];
        let mut keys = outcome
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["failed"]);
        let mut failure_keys = outcome["failed"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        failure_keys.sort_unstable();
        assert_eq!(failure_keys, ["reason"]);
    }

    #[test]
    fn human_output_switches_to_compact_blocks_below_the_wide_threshold() {
        let records = [failed_record()];
        let render = |width| {
            render_human(
                &records,
                RenderOptions {
                    home: Path::new(HOME),
                    ui: Ui::test_terminal(width),
                },
            )
        };

        for width in [40, WIDE_TABLE_MIN_WIDTH - 1, WIDE_TABLE_MIN_WIDTH] {
            let output = render(width);
            assert!(
                output
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= usize::from(width)),
                "width {width}:\n{output}"
            );
        }
        let compact = render(WIDE_TABLE_MIN_WIDTH - 1);
        assert_eq!(
            compact.lines().next().map(str::trim),
            Some("clean\\u{1b}[31m · trash · failed: failure\\treason")
        );
        assert!(compact.contains("time\\nvalue"));
        assert!(compact.contains("~/cache\\rpath"));
        assert!(
            render(WIDE_TABLE_MIN_WIDTH)
                .lines()
                .next()
                .unwrap()
                .contains("ts")
        );
    }

    #[test]
    fn human_output_truncates_paths_instead_of_wrapping_them() {
        let records = [long_path_record()];
        for width in [40, WIDE_TABLE_MIN_WIDTH] {
            let output = render_human(
                &records,
                RenderOptions {
                    home: Path::new(HOME),
                    ui: Ui::test_terminal(width),
                },
            );
            assert!(
                output
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= usize::from(width)),
                "width {width}:\n{output}"
            );
            assert!(output.contains('…'), "width {width}:\n{output}");
        }
    }
}
