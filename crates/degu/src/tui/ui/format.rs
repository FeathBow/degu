use crate::tui::browser::SortBy;
use crate::tui::report::{Coverage, Finding, Total};

const UNIT_BASE: u64 = 1024;
const DECIMAL_BASE: f64 = 10.0;
const DIGIT_GROUP: usize = 3;

fn age(days: Option<u64>) -> String {
    match days {
        Some(days) => format!("{days}d"),
        None => "—".to_owned(),
    }
}

pub fn bytes(value: u64) -> String {
    let (number, unit) = byte_parts(value);
    format!("{number} {unit}")
}

pub fn byte_parts(value: u64) -> (String, &'static str) {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if value < UNIT_BASE {
        return (value.to_string(), UNITS[0]);
    }
    let mut size = value as f64;
    let mut unit = 0;
    while size >= UNIT_BASE as f64 && unit + 1 < UNITS.len() {
        size /= UNIT_BASE as f64;
        unit += 1;
    }
    let number = if size >= DECIMAL_BASE * DECIMAL_BASE {
        format!("{size:.0}")
    } else if size >= DECIMAL_BASE {
        format!("{size:.1}")
    } else {
        format!("{size:.2}")
    };
    (number, UNITS[unit])
}

pub fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / DIGIT_GROUP);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(DIGIT_GROUP) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn locations(count: usize) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} location{suffix}")
}

pub fn bytes_total(total: Total) -> String {
    bound(bytes(total.value), total.saturated)
}

pub fn count_total(total: Total) -> String {
    bound(count(total.value), total.saturated)
}

/// A size that is only a floor, marked as one. Rows and totals carry the
/// same mark so a truncated measurement is never read as exact anywhere.
pub fn bounded_bytes(value: u64, lower_bound: bool) -> String {
    let size = bytes(value);
    if lower_bound {
        format!("≥ {size}")
    } else {
        size
    }
}

/// A plan is a floor when any member was, or when the sum saturated.
pub fn plan_size(plan: crate::tui::decision::Plan) -> String {
    bounded_bytes(plan.bytes, plan.lower_bound)
}

fn bound(value: String, saturated: bool) -> String {
    if saturated {
        format!("over {value}")
    } else {
        value
    }
}

pub fn coverage_label(coverage: Coverage) -> &'static str {
    if !coverage.is_requested() {
        "Not scanned"
    } else if coverage.is_truncated() {
        "truncated"
    } else if coverage.is_incomplete() {
        "incomplete"
    } else {
        "Complete scan"
    }
}

pub fn coverage_warning(coverage: Coverage) -> Option<String> {
    coverage
        .is_lower_bound()
        .then(|| format!("{} — totals are a floor", coverage_label(coverage)))
}

pub fn metric_heading(sort: SortBy) -> &'static str {
    match sort {
        SortBy::Size | SortBy::Path => "SIZE",
        SortBy::Inodes => "INODES",
        SortBy::Age => "AGE",
    }
}

pub fn metric(finding: &Finding, sort: SortBy) -> String {
    match sort {
        SortBy::Size | SortBy::Path => bytes(finding.bytes_allocated()),
        SortBy::Inodes => count(finding.inodes()),
        SortBy::Age => age(finding.age_days()),
    }
}

pub fn sort_direction(sort: SortBy) -> &'static str {
    match sort {
        SortBy::Path => "↑",
        _ => "↓",
    }
}
