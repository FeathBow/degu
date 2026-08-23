use super::*;

#[test]
fn reads_regular_file_up_to_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data");
    std::fs::write(&path, b"hello world").unwrap();

    let read = read_regular_capped(&path, 1024).unwrap().unwrap();

    assert_eq!(read.bytes, b"hello world");
    assert!(!read.truncated);
}

#[test]
fn truncates_at_cap_and_flags_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newline-free");
    std::fs::write(&path, b"0123456789").unwrap();

    let read = read_regular_capped(&path, 4).unwrap().unwrap();

    assert_eq!(read.bytes, b"0123");
    assert!(read.truncated);
}

#[test]
fn exact_cap_length_is_not_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exact");
    std::fs::write(&path, b"abcd").unwrap();

    let read = read_regular_capped(&path, 4).unwrap().unwrap();

    assert_eq!(read.bytes, b"abcd");
    assert!(!read.truncated);
}

#[test]
fn directory_is_not_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();

    assert!(read_regular_capped(dir.path(), 1024).unwrap().is_none());
    assert!(open_regular_capped(dir.path()).unwrap().is_none());
}

#[test]
fn missing_path_surfaces_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent");

    let err = read_regular_capped(&path, 1024).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn fifo_returns_none_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipe");
    // mkfifo command because rustix::mknodat is unavailable on macOS. No writer
    // exists, so reaching the assertions at all proves the open did not block.
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo failed");

    assert!(open_regular_capped(&path).unwrap().is_none());
    assert!(read_regular_capped(&path, 1024).unwrap().is_none());
}

#[test]
fn nofollow_reads_a_real_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data");
    std::fs::write(&path, b"hello").unwrap();

    let read = read_regular_capped_nofollow(&path, 1024).unwrap().unwrap();

    assert_eq!(read.bytes, b"hello");
}

#[cfg(unix)]
#[test]
fn nofollow_refuses_a_symlinked_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"secret-from-outside").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    // The link target is a perfectly readable regular file, yet the no-follow
    // read must not resolve it -- a symlinked marker forfeits trust.
    assert!(open_regular_capped_nofollow(&link).unwrap().is_none());
    assert!(read_regular_capped_nofollow(&link, 1024).unwrap().is_none());
    // The following variant still resolves it, proving the flag is the sole cause.
    assert!(read_regular_capped(&link, 1024).unwrap().is_some());
}
