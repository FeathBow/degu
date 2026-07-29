use super::*;
use crate::filters::Filters;
use crate::runtime::Ui;
use std::path::PathBuf;

const TEST_HOME: &str = "/home/user";

fn terminal(workflow: Workflow<'_>) -> Request<'_> {
    Request {
        output: OutputMode::Human(Ui::test_terminal(80)),
        workflow,
        home: Some(Path::new(TEST_HOME)),
    }
}

fn line(request: Request<'_>) -> Option<NextLine> {
    match resolve(request).resolution {
        Resolution::Ready { line, .. } => Some(line),
        Resolution::Absent | Resolution::UnsafeScope => None,
    }
}

#[test]
fn next_action_is_suppressed_for_json_and_pipes() {
    for output in [OutputMode::Json, OutputMode::Human(Ui::test_pipe(80))] {
        assert!(
            line(Request {
                output,
                workflow: Workflow::Quota,
                home: None,
            })
            .is_none()
        );
    }
}

#[test]
fn scan_review_preview_preserves_scope_and_selects_one_path() {
    let scope = ScanScope {
        filters: Filters {
            roots: vec![PathBuf::from("first root"), PathBuf::from("second/root")],
            only: vec!["huggingface".to_string(), "pip".to_string()],
            older_than: Some(30),
            min_size: Some(4096),
            top: Some(2),
        },
        runtime: true,
    };

    let line =
        review_preview_from_scan(&scope, Path::new("review path"), Path::new(TEST_HOME)).unwrap();

    assert_eq!(
        line.as_str(),
        "degu clean --details --dry-run --include-review --only huggingface --only pip --older-than 30 --min-size 4096 --top 2 --path 'review path' -- 'first root' second/root"
    );
}

#[test]
fn next_action_clean_preserves_safe_selection_without_purge_or_yes() {
    let scope = CleanScope {
        filters: Filters {
            roots: vec![PathBuf::from("work tree")],
            only: vec!["pip".to_string()],
            older_than: Some(30),
            min_size: Some(4096),
            top: Some(2),
        },
        paths: vec![PathBuf::from("cache path")],
        include_review: true,
    };
    let line = line(terminal(Workflow::CleanPreview(CleanPreviewState {
        scope: &scope,
        planned: 1,
        direct_purge_requested: false,
    })))
    .unwrap();

    assert_eq!(
        line.as_str(),
        "degu clean --include-review --only pip --older-than 30 --min-size 4096 --top 2 --path 'cache path' -- 'work tree'"
    );
}

#[test]
fn clean_review_preview_replaces_paths_and_quotes_the_target() {
    let scope = CleanScope {
        filters: Filters {
            roots: vec![PathBuf::from("work tree")],
            only: vec!["huggingface".to_string()],
            older_than: Some(7),
            min_size: Some(1024),
            top: Some(3),
        },
        paths: vec![PathBuf::from("old one"), PathBuf::from("old two")],
        include_review: false,
    };

    let line = review_preview_from_clean(
        &scope,
        Path::new("chosen cache/it's here"),
        Path::new(TEST_HOME),
    )
    .unwrap();

    assert_eq!(
        line.as_str(),
        "degu clean --details --dry-run --include-review --only huggingface --older-than 7 --min-size 1024 --top 3 --path 'chosen cache/it'\\''s here' -- 'work tree'"
    );
}

#[test]
fn clean_details_preview_preserves_the_current_scope() {
    let scope = CleanScope {
        filters: Filters {
            roots: vec![PathBuf::from("work tree")],
            only: vec!["huggingface".to_string()],
            older_than: Some(7),
            min_size: Some(1024),
            top: Some(3),
        },
        paths: vec![PathBuf::from("chosen cache")],
        include_review: true,
    };

    let line = details_preview_from_clean(&scope, Path::new(TEST_HOME)).unwrap();

    assert_eq!(
        line.as_str(),
        "degu clean --details --dry-run --include-review --only huggingface --older-than 7 --min-size 1024 --top 3 --path 'chosen cache' -- 'work tree'"
    );
}

#[test]
fn review_preview_rejects_control_characters_in_the_target_path() {
    let scope = ScanScope::empty();

    assert!(
        review_preview_from_scan(&scope, Path::new("bad\npath"), Path::new(TEST_HOME)).is_none()
    );
}

#[test]
fn next_action_keeps_destructive_trash_decisions_manual() {
    assert!(
        line(terminal(Workflow::TrashList(TrashListState {
            ambiguous: false,
            interrupted_purge: false,
        })))
        .is_none()
    );
    let ambiguous = line(terminal(Workflow::TrashList(TrashListState {
        ambiguous: true,
        interrupted_purge: false,
    })))
    .unwrap();
    assert_eq!(ambiguous.as_str(), "degu ops");
    let interrupted = line(terminal(Workflow::TrashList(TrashListState {
        ambiguous: false,
        interrupted_purge: true,
    })))
    .unwrap();
    assert_eq!(interrupted.as_str(), "degu ops");
}

#[test]
fn next_action_undo_routes_failure_to_trash_and_success_to_scan() {
    let failed = line(terminal(Workflow::Undo(UndoState {
        restored: 1,
        failed: 1,
        ambiguous: 0,
    })))
    .unwrap();
    assert_eq!(failed.as_str(), "degu trash list");
    let restored = line(terminal(Workflow::Undo(UndoState {
        restored: 1,
        failed: 0,
        ambiguous: 0,
    })))
    .unwrap();
    assert_eq!(restored.as_str(), "degu scan");
}

#[test]
fn next_action_marks_control_characters_as_an_unsafe_scope() {
    let scope = CleanScope {
        filters: Filters {
            roots: vec![PathBuf::from("bad\nroot")],
            ..Filters::default()
        },
        paths: Vec::new(),
        include_review: false,
    };
    assert!(matches!(
        resolve(terminal(Workflow::CleanPreview(CleanPreviewState {
            scope: &scope,
            planned: 1,
            direct_purge_requested: false,
        })))
        .resolution,
        Resolution::UnsafeScope
    ));
}
