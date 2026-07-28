use super::process::{HandleProbe, process_holds_path};
use std::path::Path;

#[test]
fn process_holds_path_reports_unreadable_probe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fd"), "").unwrap();

    assert_eq!(
        process_holds_path(dir.path(), Path::new("/dev/shm/degu-test"), None),
        HandleProbe::Failed
    );
}

#[test]
#[cfg(target_os = "linux")]
fn process_holds_path_tracks_current_process_fd_lifecycle() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().canonicalize().unwrap();

    assert_eq!(
        process_holds_path(Path::new("/proc/self"), &path, None),
        HandleProbe::Held
    );

    let _guard = file.into_temp_path();
    assert_eq!(
        process_holds_path(Path::new("/proc/self"), &path, None),
        HandleProbe::Clear
    );
}

#[test]
fn elapsed_deadline_precedes_nested_proc_reads() {
    let missing = Path::new("/proc/degu-missing-process");

    assert_eq!(
        process_holds_path(
            missing,
            Path::new("/dev/shm/degu-test"),
            Some(std::time::Instant::now()),
        ),
        HandleProbe::Deadline
    );
}
