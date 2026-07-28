use crate::collection::ScanCompleteness;
use crate::commands::scope::ScanScope;
use crate::runtime::Ui;
use std::path::Path;

mod output;
mod render;

pub(crate) const UNSAFE_SCOPE_REASON: &str =
    "unavailable: this scope cannot be represented safely as a shell command.";

#[derive(Clone, Copy)]
pub(crate) enum OutputMode {
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
    Scan(ScanState<'a>),
}

pub(crate) struct ScanState<'a> {
    pub(crate) scope: &'a ScanScope,
    pub(crate) completeness: ScanCompleteness,
    pub(crate) needs_review: bool,
    pub(crate) has_effective_project_roots: bool,
}

pub(crate) struct NextLine(String);

impl NextLine {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

enum Action {
    CompleteScan(ScanScope),
    ProjectScan(ScanScope),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GuidanceKind {
    CompleteScan,
    ProjectScan,
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
        }
    }
}

fn allows_next(output: OutputMode) -> bool {
    matches!(output, OutputMode::Human(ui) if ui.stdout_is_terminal)
}

fn action_for(workflow: Workflow<'_>) -> Option<Action> {
    match workflow {
        Workflow::Scan(state) => scan_action(state),
    }
}

fn scan_action(state: ScanState<'_>) -> Option<Action> {
    if state.completeness.is_truncated() {
        return Some(Action::CompleteScan(state.scope.clone()));
    }
    if state.completeness.findings.is_incomplete() {
        return None;
    }
    if state.needs_review || state.has_effective_project_roots {
        return None;
    }
    if state.completeness.runtime.is_incomplete() {
        return None;
    }
    state.scope.project_scan_scope().map(Action::ProjectScan)
}
