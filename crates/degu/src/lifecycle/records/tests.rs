use super::*;

#[test]
fn accepts_exact_total_and_line_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state");
    std::fs::write(&path, b"abcd\n").unwrap();
    let mut lines = Vec::new();

    visit_bounded_state_lines(&path, StateReadLimits::new(5, 4), |number, line| {
        lines.push((number, line.to_vec()));
        Ok(())
    })
    .unwrap();

    assert_eq!(lines, vec![(1, b"abcd".to_vec())]);
}

#[test]
fn rejects_file_over_total_limit_before_visiting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state");
    std::fs::write(&path, b"abcd\nextra").unwrap();
    let mut visited = false;

    let error = visit_bounded_state_lines(&path, StateReadLimits::new(5, 5), |_, _| {
        visited = true;
        Ok(())
    })
    .unwrap_err();

    assert!(!visited);
    assert!(error.to_string().contains("state-file limit"));
}

#[test]
fn rejects_newline_free_record_over_line_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state");
    std::fs::write(&path, b"oversized").unwrap();

    let error =
        visit_bounded_state_lines(&path, StateReadLimits::new(32, 4), |_, _| Ok(())).unwrap_err();

    assert!(error.to_string().contains("record limit"));
}

#[test]
fn missing_file_is_empty_but_directory_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let mut visited = false;

    visit_bounded_state_lines(&missing, StateReadLimits::new(8, 4), |_, _| {
        visited = true;
        Ok(())
    })
    .unwrap();
    assert!(!visited);

    let error = visit_bounded_state_lines(dir.path(), StateReadLimits::new(8, 4), |_, _| Ok(()))
        .unwrap_err();
    assert!(error.to_string().contains("not a regular file"));
}
