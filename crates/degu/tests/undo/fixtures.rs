use super::{TrashStatus, trash_record, write_oplog};

pub(super) fn both_missing_pending_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let original = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(original.parent().unwrap()).unwrap();
    let entry = state.path().join("degu/trash/0001-pip");
    write_oplog(
        &state,
        &[trash_record(
            "2000-01-01T00:00:00Z",
            (&original, &entry),
            TrashStatus::Pending(Some("interrupted-run")),
        )],
    );
    (home, state)
}

pub(super) fn newest_ambiguous_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let old_original = home.path().join(".cache/old");
    std::fs::create_dir_all(old_original.parent().unwrap()).unwrap();
    let old_entry = state.path().join("degu/trash/0001-old");
    std::fs::create_dir_all(&old_entry).unwrap();
    std::fs::write(old_entry.join("data"), b"old data").unwrap();
    let ambiguous_original = home.path().join(".cache/ambiguous");
    std::fs::create_dir_all(&ambiguous_original).unwrap();
    let ambiguous_entry = state.path().join("degu/trash/0002-ambiguous");
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    let superseded_original = home.path().join(".cache/superseded");
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&old_original, &old_entry),
            TrashStatus::Ok(Some("old-run")),
        ),
        trash_record(
            "2000-01-01T12:00:00Z",
            (&superseded_original, &ambiguous_entry),
            TrashStatus::Ok(Some("superseded-run")),
        ),
        trash_record(
            "2000-01-02T00:00:00Z",
            (&ambiguous_original, &ambiguous_entry),
            TrashStatus::Pending(Some("new-run")),
        ),
    ];
    write_oplog(&state, &records);
    (home, state)
}

pub(super) fn mixed_pending_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let staged_original = home.path().join(".cache/staged");
    std::fs::create_dir_all(staged_original.parent().unwrap()).unwrap();
    let staged_entry = state.path().join("degu/trash/0001-staged");
    std::fs::create_dir_all(&staged_entry).unwrap();
    let ambiguous_original = home.path().join(".cache/ambiguous");
    std::fs::create_dir_all(&ambiguous_original).unwrap();
    let ambiguous_entry = state.path().join("degu/trash/0002-ambiguous");
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&staged_original, &staged_entry),
            TrashStatus::Pending(Some("run")),
        ),
        trash_record(
            "2000-01-01T00:00:01Z",
            (&ambiguous_original, &ambiguous_entry),
            TrashStatus::Pending(Some("run")),
        ),
    ];
    write_oplog(&state, &records);
    (home, state)
}

pub(super) fn multiple_ambiguous_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let old_original = home.path().join(".cache/old-ambiguous");
    let new_original = home.path().join(".cache/new-ambiguous");
    std::fs::create_dir_all(&old_original).unwrap();
    std::fs::create_dir_all(&new_original).unwrap();
    let old_entry = state.path().join("degu/trash/0001-old-ambiguous");
    let new_entry = state.path().join("degu/trash/0002-new-ambiguous");
    std::fs::create_dir_all(&old_entry).unwrap();
    std::fs::create_dir_all(&new_entry).unwrap();
    let records = [
        trash_record(
            "2000-01-01T00:00:00Z",
            (&old_original, &old_entry),
            TrashStatus::Pending(Some("old-run")),
        ),
        trash_record(
            "2000-01-02T00:00:00Z",
            (&new_original, &new_entry),
            TrashStatus::Pending(Some("new-run")),
        ),
    ];
    write_oplog(&state, &records);
    (home, state)
}
