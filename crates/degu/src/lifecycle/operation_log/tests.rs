use std::io::Write;

use super::*;

fn purge_record(path: &Path) -> OpRecord {
    super::purge_record(PurgeRecord {
        command: "trash purge",
        entry: path,
        reclamation_id: Some("run"),
        outcome: OpOutcome::Ok,
    })
}

#[test]
fn append_isolates_a_partial_tail_from_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state/ops.jsonl");
    let log = OperationLog::at(path.clone());
    let first = purge_record(Path::new("/trash/first"));
    let second = purge_record(Path::new("/trash/second"));

    log.append(&first).unwrap();
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(b"{broken-\xe2").unwrap();
    drop(file);
    log.append(&second).unwrap();

    let records = log.read().unwrap();
    assert_eq!(records, vec![first, second]);
}
