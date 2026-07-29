use crate::presentation::{display_path, escape_terminal_text};

mod json;
mod plan;

pub(super) use json::print as print_json;
pub(super) use plan::print as print_plan;

fn escaped_path(path: &std::path::Path, home: &std::path::Path) -> String {
    escape_terminal_text(&display_path(path, home))
}
