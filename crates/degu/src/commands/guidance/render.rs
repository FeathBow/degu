use super::Action;
use crate::cli::{CleanArgs, ScanLimitArgs, TrashPurgeArgs};
use crate::commands::scope::{CleanScope, ScanScope};
use crate::findings::Filters;
use crate::presentation::shell::{command_path, quote_path, quote_word};
use std::path::{Path, PathBuf};

impl Action {
    pub(super) fn render(self, home: Option<&Path>) -> Option<String> {
        match self {
            Self::Scan(scope) | Self::CompleteScan(scope) | Self::ProjectScan(scope) => {
                render_scan(&scope, home)
            }
            Self::CleanPreview(scope) => render_clean(
                &scope,
                home,
                CleanRenderOptions {
                    dry_run: true,
                    ..CleanRenderOptions::default()
                },
            ),
            Self::CleanReview(scope) => render_clean(
                &scope,
                home,
                CleanRenderOptions {
                    dry_run: true,
                    details: true,
                    ..CleanRenderOptions::default()
                },
            ),
            Self::Clean(scope) | Self::RestorableClean(scope) => {
                render_clean(&scope, home, CleanRenderOptions::default())
            }
            Self::TrashList => Some("degu trash list".to_string()),
            Self::Ops => Some("degu ops".to_string()),
        }
    }
}

#[derive(Default)]
struct CleanRenderOptions {
    dry_run: bool,
    details: bool,
    json: bool,
    yes: bool,
    purge: bool,
    limits: Option<ScanLimitArgs>,
}

pub(crate) fn clean_command(args: &CleanArgs) -> Option<String> {
    render_clean(
        &CleanScope::from_args(args),
        None,
        CleanRenderOptions {
            dry_run: args.dry_run,
            details: args.details,
            json: args.output.json,
            yes: args.yes,
            purge: args.purge,
            limits: Some(args.limits),
        },
    )
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

pub(crate) fn purge_command(args: &TrashPurgeArgs) -> Option<String> {
    let mut words = vec!["degu".to_string(), "trash".to_string(), "purge".to_string()];
    if args.output.json {
        words.push("--json".to_string());
    }
    if args.yes {
        words.push("--yes".to_string());
    }
    for (flag, paths) in [("--path", &args.path), ("--entry", &args.entry)] {
        for path in paths {
            words.extend([flag.to_string(), quote_path(path)?]);
        }
    }
    Some(words.join(" "))
}

fn render_clean(
    scope: &CleanScope,
    home: Option<&Path>,
    options: CleanRenderOptions,
) -> Option<String> {
    let mut words = vec!["degu".to_string(), "clean".to_string()];
    match (options.details, options.dry_run) {
        (true, true) => words.push("-dn".to_string()),
        (true, false) => words.push("-d".to_string()),
        (false, true) => words.push("-n".to_string()),
        (false, false) => {}
    }
    push_execution_flags(&mut words, options);
    let one_review_path = scope.exact_review && scope.paths.len() == 1;
    if scope.include_review && !one_review_path {
        words.push("--include-review".to_string());
    }
    push_filters(&mut words, &scope.filters)?;
    for path in &scope.paths {
        words.push(if one_review_path {
            "--review".to_string()
        } else {
            "--path".to_string()
        });
        words.push(render_path(path, home)?);
    }
    push_roots(&mut words, &scope.filters.roots, home)?;
    Some(words.join(" "))
}

fn push_execution_flags(words: &mut Vec<String>, options: CleanRenderOptions) {
    for (flag, enabled) in [
        ("--json", options.json),
        ("--yes", options.yes),
        ("--purge", options.purge),
    ] {
        if enabled {
            words.push(flag.to_string());
        }
    }
    if let Some(limits) = options.limits {
        if let Some(concurrency) = limits.max_concurrency {
            words.extend(["--max-concurrency".to_string(), concurrency.to_string()]);
        }
        if let Some(budget) = limits.budget {
            words.extend(["--budget".to_string(), format!("{}s", budget.as_secs())]);
        }
    }
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
