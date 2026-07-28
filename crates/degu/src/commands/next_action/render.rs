use super::Action;
use crate::commands::scope::ScanScope;
use crate::filters::Filters;
use crate::presentation::shell::{command_path, quote_path, quote_word};
use std::path::{Path, PathBuf};

impl Action {
    pub(super) fn render(self, home: Option<&Path>) -> Option<String> {
        match self {
            Self::CompleteScan(scope) | Self::ProjectScan(scope) => render_scan(&scope, home),
            Self::TrashList => Some("degu trash list".to_string()),
            Self::Ops => Some("degu ops".to_string()),
        }
    }
}

fn render_scan(scope: &ScanScope, home: Option<&Path>) -> Option<String> {
    let mut words = vec!["degu".to_string(), "scan".to_string()];
    push_filters(&mut words, &scope.filters)?;
    if scope.runtime {
        words.push("--runtime".to_string());
    }
    push_roots(&mut words, &scope.filters.roots, home)?;
    Some(words.join(" "))
}

fn render_path(path: &Path, home: Option<&Path>) -> Option<String> {
    match home {
        Some(home) => command_path(path, home),
        None => quote_path(path),
    }
}

fn push_filters(words: &mut Vec<String>, filters: &Filters) -> Option<()> {
    for id in &filters.only {
        words.extend(["--only".to_string(), quote_word(id)?]);
    }
    push_number(words, "--older-than", filters.older_than);
    push_number(words, "--min-size", filters.min_size);
    let top = filters.top.map(u64::try_from).transpose().ok()?;
    push_number(words, "--top", top);
    Some(())
}

fn push_number(words: &mut Vec<String>, name: &str, value: Option<u64>) {
    if let Some(value) = value {
        words.extend([name.to_string(), value.to_string()]);
    }
}

fn push_roots(words: &mut Vec<String>, roots: &[PathBuf], home: Option<&Path>) -> Option<()> {
    if roots.is_empty() {
        return Some(());
    }
    if roots.len() == 1 && roots[0] == Path::new(".") {
        words.push(".".to_string());
        return Some(());
    }
    words.push("--".to_string());
    for root in roots {
        words.push(render_path(root, home)?);
    }
    Some(())
}
