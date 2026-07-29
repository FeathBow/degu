use super::*;

fn stage_for_test(trash: &Trash, source: &Path) -> PathBuf {
    let entry = trash.reserve(source).unwrap();
    std::fs::rename(source, &entry).unwrap();
    trash.release_reservation(&entry).unwrap();
    entry
}

#[test]
fn reservation_and_release_produce_the_expected_entry() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache.txt");
    std::fs::write(&source, "cached data").unwrap();

    let entry = stage_for_test(&trash, &source);

    assert_eq!(entry, dir.path().join("trash/0001-cache.txt"));
    assert!(!source.exists());
    assert_eq!(std::fs::read_to_string(entry).unwrap(), "cached data");
    assert!(!dir.path().join("trash/.claims/0001").exists());
}

#[test]
fn reserve_twice_from_distinct_instances_yields_distinct_entries() {
    let dir = tempfile::tempdir().unwrap();
    let first = Trash::new(dir.path().join("trash"));
    let second = Trash::new(dir.path().join("trash"));
    let first_source = dir.path().join("a/cache");
    let second_source = dir.path().join("b/cache");
    std::fs::create_dir_all(&first_source).unwrap();
    std::fs::create_dir_all(&second_source).unwrap();

    let first_entry = first.reserve(&first_source).unwrap();
    let second_entry = second.reserve(&second_source).unwrap();

    assert_eq!(first_entry, dir.path().join("trash/0001-cache"));
    assert_eq!(second_entry, dir.path().join("trash/0002-cache"));
}

#[test]
fn release_reservation_preserves_a_nonempty_marker() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let source = dir.path().join("cache");
    std::fs::write(&source, "cached data").unwrap();
    let entry = trash.reserve(&source).unwrap();
    let marker = dir.path().join("trash/.claims/0001");
    std::fs::write(&marker, "preserved data").unwrap();

    let error = trash.release_reservation(&entry).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "preserved data");
}

#[test]
fn reservations_order_same_named_directories_distinctly() {
    let dir = tempfile::tempdir().unwrap();
    let trash = Trash::new(dir.path().join("trash"));
    let first = dir.path().join("a/cache");
    let second = dir.path().join("b/cache");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();

    let first_entry = stage_for_test(&trash, &first);
    let second_entry = stage_for_test(&trash, &second);

    assert_eq!(first_entry, dir.path().join("trash/0001-cache"));
    assert_eq!(second_entry, dir.path().join("trash/0002-cache"));
}
