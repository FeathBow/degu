use super::*;
use crate::runtime::Ui;

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
