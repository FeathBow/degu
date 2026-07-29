use super::model::{QuotaDimension, QuotaGrace, QuotaGraceState, QuotaReport};
use crate::output::stdoutln;
use crate::presentation::{escape_terminal_text, human_bytes, ratio_bar};
use crate::runtime::{Glyphs, Ui};
use anyhow::Result;
use std::cmp::Ordering;
use std::fmt::Write as _;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const PERCENT_SCALE: f64 = 100.0;
const DETAIL_INDENT: usize = 11;

pub(super) fn print(report: &QuotaReport, json: bool, ui: Ui) -> Result<()> {
    if json {
        stdoutln!("{}", serde_json::to_string_pretty(report)?)?;
    } else {
        stdoutln!("{}", render_human(report, ui))?;
    }
    Ok(())
}

fn render_human(report: &QuotaReport, ui: Ui) -> String {
    let glyphs = ui.glyphs;
    let separator = glyphs.separator;
    let target = escape_terminal_text(&report.scope.path.display().to_string());
    let filesystem = escape_terminal_text(&report.scope.filesystem);
    let mount = escape_terminal_text(&report.scope.mount_point.display().to_string());
    let subject = escape_terminal_text(report.subject.kind);
    let provider = escape_terminal_text(report.provider);
    let data_source = escape_terminal_text(report.data_source);
    let mut output = format!(
        "Quota {separator} {target}\n\nFilesystem  {filesystem} {separator} {mount}\nSubject     {subject} {}\nProvider    {provider}\nData source {data_source}",
        report.subject.id
    );
    write!(
        output,
        "\n\n{}\n{}",
        render_dimension("Space", &report.space, human_bytes, glyphs),
        render_dimension("Inodes", &report.inodes, format_count, glyphs)
    )
    .expect("writing to a String cannot fail");
    reflow_human(&output, ui.width)
}

fn reflow_human(output: &str, width: u16) -> String {
    output
        .lines()
        .flat_map(|line| wrap_line(line, usize::from(width.max(1))))
        .collect::<Vec<_>>()
        .join("\n")
}

fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if UnicodeWidthStr::width(line) <= width {
        return vec![line.to_owned()];
    }
    let content = line.trim_start();
    let indent = &line[..line.len() - content.len()];
    let available = width.saturating_sub(UnicodeWidthStr::width(indent)).max(1);
    let mut rest = content;
    let mut lines = Vec::new();
    while !rest.is_empty() {
        let (chunk, remainder) = take_width_chunk(rest, available);
        lines.push(format!("{indent}{chunk}"));
        rest = remainder;
    }
    lines
}

fn take_width_chunk(value: &str, width: usize) -> (String, &str) {
    let mut used = 0;
    let mut last_space = None;
    for (index, character) in value.char_indices() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + character_width > width {
            let split = last_space.filter(|position| *position > 0).unwrap_or(index);
            let split = if split == 0 {
                index + character.len_utf8()
            } else {
                split
            };
            return (
                value[..split].trim_end().to_owned(),
                value[split..].trim_start(),
            );
        }
        used += character_width;
        if character.is_whitespace() {
            last_space = Some(index);
        }
    }
    (value.to_owned(), "")
}

fn render_dimension(
    label: &str,
    dimension: &QuotaDimension,
    format_value: fn(u64) -> String,
    glyphs: Glyphs,
) -> String {
    let separator = glyphs.separator;
    let soft = format_limit(dimension.soft_limit, format_value);
    let hard = format_limit(dimension.hard_limit, format_value);
    let mut lines = vec![pressure_line(label, dimension, glyphs)];
    lines.push(format!(
        "{:<DETAIL_INDENT$}{} used {separator} soft {soft} {separator} hard {hard}",
        "",
        format_value(dimension.used)
    ));
    lines.extend(boundary_lines(dimension, format_value));
    lines.join("\n")
}

#[derive(Clone, Copy)]
struct Boundary {
    kind: &'static str,
    limit: u64,
}

fn boundary_lines(dimension: &QuotaDimension, format_value: fn(u64) -> String) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(limit) = dimension.soft_limit {
        lines.push(render_boundary(
            Boundary {
                kind: "soft limit",
                limit,
            },
            dimension.used,
            format_value,
        ));
        if dimension.used > limit
            && let Some(grace) = &dimension.grace
        {
            lines.push(detail_line(format_grace(grace)));
        }
    }
    if let Some(limit) = dimension.hard_limit {
        lines.push(render_boundary(
            Boundary {
                kind: "hard limit",
                limit,
            },
            dimension.used,
            format_value,
        ));
    }
    lines
}

fn render_boundary(boundary: Boundary, used: u64, format_value: fn(u64) -> String) -> String {
    detail_line(boundary_status(boundary, used, format_value))
}

fn detail_line(value: String) -> String {
    format!("{:<DETAIL_INDENT$}{value}", "")
}

fn boundary_status(boundary: Boundary, used: u64, format_value: fn(u64) -> String) -> String {
    match used.cmp(&boundary.limit) {
        Ordering::Less => format!(
            "{} remaining to {}",
            format_value(boundary.limit - used),
            boundary.kind
        ),
        Ordering::Equal => format!("at {}", boundary.kind),
        Ordering::Greater => format!(
            "{} exceeded by {}",
            boundary.kind,
            format_value(used - boundary.limit)
        ),
    }
}

fn format_grace(grace: &QuotaGrace) -> String {
    let state = match grace.state {
        QuotaGraceState::Active => "active until",
        QuotaGraceState::Expired => "expired at",
    };
    // A missing deadline means the provider reported an expired grace period
    // without one; never synthesize a timestamp in its place.
    let Some(expires_at_unix) = grace.expires_at_unix else {
        return "grace period has expired (provider reports no deadline)".to_owned();
    };
    let timestamp = i64::try_from(expires_at_unix)
        .ok()
        .and_then(|seconds| jiff::Timestamp::from_second(seconds).ok())
        .map(|timestamp| timestamp.to_string());
    match timestamp {
        Some(timestamp) => format!("grace {state} {timestamp} (Unix {expires_at_unix})"),
        None => format!("grace {state} Unix {expires_at_unix} (UTC timestamp out of range)"),
    }
}

fn pressure_line(label: &str, dimension: &QuotaDimension, glyphs: Glyphs) -> String {
    let Some((kind, limit)) = pressure_limit(dimension) else {
        return format!("{label:<DETAIL_INDENT$}no configured limit");
    };
    let ratio = dimension.used as f64 / limit as f64;
    format!(
        "{label:<DETAIL_INDENT$}{:>5.1}% of {kind} {}",
        ratio * PERCENT_SCALE,
        ratio_bar(ratio, glyphs)
    )
}

fn pressure_limit(dimension: &QuotaDimension) -> Option<(&'static str, u64)> {
    dimension
        .hard_limit
        .map(|limit| ("hard limit", limit))
        .or_else(|| dimension.soft_limit.map(|limit| ("soft limit", limit)))
}

fn format_limit(value: Option<u64>, format_value: fn(u64) -> String) -> String {
    value
        .map(format_value)
        .unwrap_or_else(|| "unlimited".to_owned())
}

fn format_count(value: u64) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests;
