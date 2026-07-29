use super::*;
use std::path::PathBuf;

fn assert_keys(value: &serde_json::Value, expected: &[&str]) {
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, expected);
}

#[test]
fn human_report_escapes_operation_log_text_and_freezes_failure_json() {
    let mut report = UndoReport::new(Some("run\nid".to_owned()));
    report.ambiguous.push(UndoAmbiguousEntry {
        path: PathBuf::from("/cache\u{1b}[31m"),
        trash_entry: PathBuf::from("/trash\rentry"),
        reclamation_id: Some("ambiguous\tid".to_owned()),
    });
    report.failed.push(UndoFailedEntry {
        path: PathBuf::from("/failed\npath"),
        trash_entry: PathBuf::from("/trash/failed"),
        reason: "restore\rfailed".to_owned(),
    });

    let lines = human_lines(&report);

    assert!(lines.iter().all(|line| !line.chars().any(char::is_control)));
    let output = lines.join("\n");
    for escaped in [
        "/cache\\u{1b}[31m",
        "/trash\\rentry",
        "ambiguous\\tid",
        "/failed\\npath",
        "restore\\rfailed",
        "run\\nid",
    ] {
        assert!(output.contains(escaped), "output: {output}");
    }
    let json = serde_json::to_value(json_report(&report)).unwrap();
    assert_keys(
        &json,
        &[
            "ambiguous",
            "failed",
            "gone",
            "log_failures",
            "reclamation_id",
            "restored",
        ],
    );
    assert_keys(
        &json["ambiguous"][0],
        &["path", "reclamation_id", "trash_entry"],
    );
    assert_keys(&json["failed"][0], &["path", "reason", "trash_entry"]);
}

#[test]
fn human_report_keeps_a_restored_item_visible_when_final_logging_fails() {
    let path = PathBuf::from("/cache");
    let trash_entry = PathBuf::from("/trash/0001-cache");
    let mut report = UndoReport::new(Some("run".to_owned()));
    report.restored.push(UndoEntry {
        path: path.clone(),
        trash_entry: trash_entry.clone(),
    });
    report.log_failures.push(UndoLogFailure {
        path,
        trash_entry,
        reason: "final operation log append failed: log full".to_owned(),
        restored: true,
    });

    let lines = human_lines(&report);

    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("restored /cache, but "));
    assert_eq!(lines[1], "Restored 1 of 1 from reclamation run.");
    assert!(report.has_failures());
    let json = serde_json::to_value(json_report(&report)).unwrap();
    assert_keys(
        &json["log_failures"][0],
        &["path", "reason", "restored", "trash_entry"],
    );
}

#[cfg(unix)]
#[test]
fn print_json_reports_non_utf8_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut report = UndoReport::new(None);
    report.restored.push(UndoEntry {
        path: PathBuf::from(OsString::from_vec(b"/cache/\xff".to_vec())),
        trash_entry: PathBuf::from("/trash/entry"),
    });

    let result = print_json(&report);

    assert!(result.is_err());
}
