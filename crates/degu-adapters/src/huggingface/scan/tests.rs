use super::*;
use std::time::Instant;

#[test]
fn expired_deadline_stops_nested_repo_lock_probe_and_propagates() {
    let root = tempfile::tempdir().unwrap();
    let ctx = DetectCtx::from_process()
        .unwrap()
        .with_deadline(Some(Instant::now()));

    let scanner = Scanner::new(root.path(), &ctx, "huggingface");
    let outcome = scanner.repo_directory_finding(
        &root.path().join("models--owner--repo"),
        "models--owner--repo",
    );

    assert!(outcome.truncated);
    assert!(!outcome.incomplete);
    assert!(outcome.candidates.is_empty());
}

#[test]
fn lock_facts_share_the_stated_priority_class() {
    use degu_core::disposition::scan_priority;

    assert_eq!(scan_priority(cheap_facts()), scan_priority(costly_facts()));
}

// A lock whose repo dir is absent looks orphaned, but the repo can be missing
// transiently while another process still holds the download lock. A held lock
// must never be reclaimed; only a lock nobody holds is a true orphan.
#[cfg(unix)]
#[test]
fn held_lock_is_not_an_orphan_until_released() {
    use rustix::fs::{FlockOperation, flock};

    let root = tempfile::tempdir().unwrap();
    let lock_dir = root.path().join(".locks/models--x--y");
    std::fs::create_dir_all(&lock_dir).unwrap();
    std::fs::write(lock_dir.join("blob.lock"), b"").unwrap();
    let ctx = DetectCtx::from_process().unwrap();

    // Another open file description holds the lock exclusively; flock conflicts
    // across independent opens even within one process.
    let held = std::fs::File::open(lock_dir.join("blob.lock")).unwrap();
    flock(&held, FlockOperation::LockExclusive).unwrap();
    let busy = Scanner::new(root.path(), &ctx, "huggingface").orphan_locks();
    assert!(
        busy.candidates.is_empty(),
        "a held download lock must not surface as an orphan"
    );
    assert!(!busy.incomplete);
    assert!(!busy.truncated);

    drop(held);
    let cleared = Scanner::new(root.path(), &ctx, "huggingface").orphan_locks();
    assert_eq!(
        cleared.candidates.len(),
        1,
        "once released, the orphaned lock directory surfaces"
    );
    assert!(cleared.candidates[0].path.ends_with("models--x--y"));
    assert!(!cleared.incomplete);
}

// A non-regular *.lock cannot be flocked to prove nobody holds it, so the probe
// fails closed to incomplete rather than declaring a false orphan. A genuine
// flock() failure fails closed the same way.
#[cfg(unix)]
#[test]
fn non_regular_lock_is_incomplete_never_a_false_orphan() {
    let root = tempfile::tempdir().unwrap();
    let lock_dir = root.path().join(".locks/models--x--y");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lock_file = lock_dir.join("blob.lock");
    let c_path = std::ffi::CString::new(lock_file.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
    let ctx = DetectCtx::from_process().unwrap();

    let outcome = Scanner::new(root.path(), &ctx, "huggingface").orphan_locks();
    assert!(outcome.candidates.is_empty());
    assert!(outcome.incomplete);
}
