use crate::collection::ScanCompleteness;
use crate::commands::scope::{CleanScope, ScanScope};
use crate::runtime::Ui;
use std::path::Path;

mod output;
mod render;
pub(crate) use output::print;

pub(crate) const UNSAFE_PATH_REASON: &str =
    "Preview unavailable: this path cannot be represented safely as a shell command.";
pub(crate) const UNSAFE_SCOPE_REASON: &str =
    "unavailable: this scope cannot be represented safely as a shell command.";

#[derive(Clone, Copy)]
pub(crate) enum OutputMode {
    Json,
    Human(Ui),
}

pub(crate) struct Request<'a> {
    pub(crate) output: OutputMode,
    pub(crate) workflow: Workflow<'a>,
    /// Home for `~` abbreviation in suggested commands; `None` when the
    /// workflow renders no paths.
    pub(crate) home: Option<&'a Path>,
}

pub(crate) enum Workflow<'a> {
    Quota,
    Scan(ScanState<'a>),
    CleanPreview(CleanPreviewState<'a>),
    CleanResult(CleanResultState),
    TrashList(TrashListState),
    Undo(UndoState),
}

pub(crate) struct ScanState<'a> {
    pub(crate) scope: &'a ScanScope,
    pub(crate) trash_entries: usize,
    pub(crate) completeness: ScanCompleteness,
    /// The findings incompleteness ledger holds only deliberate protected
    /// prunes -- the same classification that leaves a clean plan unaffected.
    pub(crate) protected_prunes_only: bool,
    pub(crate) cleanable: bool,
    pub(crate) needs_review: bool,
    pub(crate) has_effective_project_roots: bool,
}

pub(crate) struct CleanPreviewState<'a> {
    pub(crate) scope: &'a CleanScope,
    pub(crate) planned: usize,
    pub(crate) direct_purge_requested: bool,
}

pub(crate) struct CleanResultState {
    pub(crate) trash_locations: usize,
}

pub(crate) struct TrashListState {
    pub(crate) ambiguous: bool,
    pub(crate) interrupted_purge: bool,
}

pub(crate) struct UndoState {
    pub(crate) restored: usize,
    pub(crate) failed: usize,
    pub(crate) ambiguous: usize,
}

pub(crate) struct NextLine(String);

impl NextLine {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

enum Action {
    Scan(ScanScope),
    CompleteScan(ScanScope),
    ProjectScan(ScanScope),
    CleanPreview(CleanScope),
    CleanReview(CleanScope),
    Clean(CleanScope),
    RestorableClean(CleanScope),
    TrashList,
    Ops,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GuidanceKind {
    Standard,
    CompleteScan,
    ProjectScan,
    RestorableClean,
}

enum Resolution {
    Absent,
    Ready { line: NextLine, kind: GuidanceKind },
    UnsafeScope,
}

pub(crate) struct Guidance {
    output: OutputMode,
    resolution: Resolution,
}

impl Guidance {
    pub(crate) fn project_scan_is_next(&self) -> bool {
        matches!(
            self.resolution,
            Resolution::Ready {
                kind: GuidanceKind::ProjectScan,
                ..
            }
        )
    }
}

pub(crate) fn review_preview_from_scan(
    scope: &ScanScope,
    path: &Path,
    home: &Path,
) -> Option<NextLine> {
    let clean_scope = scope.clean_scope().for_review_path(path);
    Action::CleanReview(clean_scope)
        .render(Some(home))
        .map(NextLine)
}

pub(crate) fn review_preview_from_clean(
    scope: &CleanScope,
    path: &Path,
    home: &Path,
) -> Option<NextLine> {
    let clean_scope = scope.for_review_path(path);
    Action::CleanReview(clean_scope)
        .render(Some(home))
        .map(NextLine)
}

pub(crate) fn details_preview_from_clean(scope: &CleanScope, home: &Path) -> Option<NextLine> {
    Action::CleanReview(scope.clone())
        .render(Some(home))
        .map(NextLine)
}

pub(crate) fn review_followup(stdout_is_terminal: bool) -> &'static str {
    if stdout_is_terminal {
        "If the preview looks right, run its Next command; it keeps the same path and filters."
    } else {
        "Run this preview in a terminal to receive a Next command with the same path and filters."
    }
}

pub(crate) fn resolve(request: Request<'_>) -> Guidance {
    let output = request.output;
    if !allows_next(request.output) {
        return Guidance {
            output,
            resolution: Resolution::Absent,
        };
    }
    let resolution = match action_for(request.workflow) {
        None => Resolution::Absent,
        Some(action) => resolve_action(action, request.home),
    };
    Guidance { output, resolution }
}

fn resolve_action(action: Action, home: Option<&Path>) -> Resolution {
    let kind = action.kind();
    match action.render(home).map(NextLine) {
        Some(line) => Resolution::Ready { line, kind },
        None => Resolution::UnsafeScope,
    }
}

impl Action {
    fn kind(&self) -> GuidanceKind {
        match self {
            Self::CompleteScan(_) => GuidanceKind::CompleteScan,
            Self::ProjectScan(_) => GuidanceKind::ProjectScan,
            Self::RestorableClean(_) => GuidanceKind::RestorableClean,
            _ => GuidanceKind::Standard,
        }
    }
}

fn allows_next(output: OutputMode) -> bool {
    matches!(output, OutputMode::Human(ui) if ui.stdout_is_terminal)
}

fn action_for(workflow: Workflow<'_>) -> Option<Action> {
    match workflow {
        Workflow::Quota => Some(Action::Scan(ScanScope::empty())),
        Workflow::Scan(state) => scan_action(state),
        Workflow::CleanPreview(state) => clean_preview_action(state),
        Workflow::CleanResult(state) => (state.trash_locations > 0).then_some(Action::TrashList),
        Workflow::TrashList(state) => {
            (state.ambiguous || state.interrupted_purge).then_some(Action::Ops)
        }
        Workflow::Undo(state) => undo_action(state),
    }
}

fn scan_action(state: ScanState<'_>) -> Option<Action> {
    if state.completeness.is_truncated() {
        return Some(Action::CompleteScan(state.scope.clone()));
    }
    if state.trash_entries > 0 {
        return Some(Action::TrashList);
    }
    if state.completeness.findings.is_incomplete() && !state.protected_prunes_only {
        return None;
    }
    if state.cleanable {
        return Some(Action::CleanPreview(state.scope.clean_scope()));
    }
    if state.needs_review || state.has_effective_project_roots {
        return None;
    }
    if state.completeness.runtime.is_incomplete() {
        return None;
    }
    state.scope.project_scan_scope().map(Action::ProjectScan)
}

fn clean_preview_action(state: CleanPreviewState<'_>) -> Option<Action> {
    if state.planned == 0 {
        return None;
    }
    let scope = state.scope.clone();
    if state.direct_purge_requested {
        Some(Action::RestorableClean(scope))
    } else {
        Some(Action::Clean(scope))
    }
}

fn undo_action(state: UndoState) -> Option<Action> {
    if state.failed > 0 || state.ambiguous > 0 {
        Some(Action::TrashList)
    } else if state.restored > 0 {
        Some(Action::Scan(ScanScope::empty()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
