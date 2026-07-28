//! Regression tests for the untrusted-read robustness blockers (issue #246):
//! a FIFO at a probed name must not hang `degu scan`, and a huge newline-free
//! file at a probed name must not be read past the safe-read cap.
//!
//! The hang is a blocked `open`/`read` syscall that a deadline cannot interrupt,
//! so every scan here runs under an explicit wall-clock timeout: a hang trips
//! the timeout and fails the test rather than blocking the suite forever.

#![cfg(unix)]

use super::support::*;
use std::time::Duration;

/// A generous ceiling. A correct scan finishes in well under a second; only a
/// blocked syscall approaches this bound.
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

fn make_fifo(path: &std::path::Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo failed for {}", path.display());
}

#[test]
fn scan_completes_with_fifo_at_config_path() {
    // config.toml is opened on every invocation; a FIFO there is the most direct
    // hang vector. A dedicated XDG config home isolates it from the shared one.
    let config_home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config_home.path().join("degu")).unwrap();
    make_fifo(&config_home.path().join("degu/config.toml"));
    let home = tempfile::tempdir().unwrap();

    let mut command = degu();
    command
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .timeout(SCAN_TIMEOUT);

    // A non-regular config is an honest error, not a hang: the process must exit
    // (success or failure) rather than block until the timeout kills it.
    let out = command.output().unwrap();
    assert!(
        out.status.code().is_some(),
        "scan did not exit on its own with a FIFO config (likely hung)"
    );
}

#[test]
fn scan_completes_with_fifo_at_cachedir_tag() {
    // A scanned directory whose CACHEDIR.TAG is a FIFO reaches the cache-tag
    // probe, which opened the tag directly before the fix.
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("cache");
    std::fs::create_dir_all(&dir).unwrap();
    make_fifo(&dir.join("CACHEDIR.TAG"));

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(root.path())
        .arg("--json")
        .timeout(SCAN_TIMEOUT)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scan did not complete with a FIFO CACHEDIR.TAG (likely hung); status: {:?}",
        out.status
    );
    // The FIFO is not a valid tag, so no artifacts finding is produced from it.
    let findings = scan_findings(&out.stdout);
    assert!(findings.as_array().unwrap().is_empty());
}

#[test]
fn scan_completes_with_fifo_at_cmake_cache() {
    // A scanned directory whose CMakeCache.txt is a FIFO exercises the CMake
    // marker probe. The fstat-based regular-file gate must keep it from reading
    // the pipe.
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("build");
    std::fs::create_dir_all(&dir).unwrap();
    make_fifo(&dir.join("CMakeCache.txt"));

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(root.path())
        .arg("--json")
        .timeout(SCAN_TIMEOUT)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scan did not complete with a FIFO CMakeCache.txt (likely hung); status: {:?}",
        out.status
    );
}

#[test]
fn scan_completes_with_fifo_at_conda_registry() {
    let home = tempfile::tempdir().unwrap();
    let conda = home.path().join(".conda");
    std::fs::create_dir_all(&conda).unwrap();
    make_fifo(&conda.join("environments.txt"));

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "conda", "--json"])
        .timeout(SCAN_TIMEOUT)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scan did not complete with a FIFO conda registry; status: {:?}",
        out.status
    );
}

#[test]
fn scan_completes_with_fifo_at_huggingface_lock() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    let repo = hub.join("models--org--name/snapshots/main");
    let locks = hub.join(".locks/models--org--name");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&locks).unwrap();
    std::fs::write(repo.join("model.bin"), [0_u8; 1024]).unwrap();
    make_fifo(&locks.join("download.lock"));

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "huggingface", "--json"])
        .timeout(SCAN_TIMEOUT)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scan did not complete with a FIFO Hugging Face lock; status: {:?}",
        out.status
    );
}

#[test]
fn truncated_conda_registry_drops_its_partial_final_line() {
    const REGISTRY_CAP: usize = 1024 * 1024;

    let home = tempfile::tempdir().unwrap();
    let environment = home.path().join("registered-env");
    std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
    let mut registry = environment.display().to_string().into_bytes();
    registry.resize(REGISTRY_CAP, b' ');
    registry.extend_from_slice(b"not-part-of-the-path\n");
    std::fs::create_dir_all(home.path().join(".conda")).unwrap();
    std::fs::write(home.path().join(".conda/environments.txt"), registry).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "conda", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    assert!(
        findings.as_array().unwrap().iter().all(|finding| {
            finding["path"] != environment.canonicalize().unwrap().display().to_string()
        }),
        "a truncated registry tail created a false environment finding: {findings}"
    );
}

#[test]
fn scan_completes_with_huge_newline_free_cachedir_tag() {
    // A large newline-free file at CACHEDIR.TAG must be read only up to the cap,
    // never slurped whole. The scan completes and the file is not a valid tag,
    // so it yields no finding. 8 MiB is far above the tiny signature cap yet
    // small enough to stay a cheap, deterministic fixture.
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("cache");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("CACHEDIR.TAG"), vec![b'x'; 8 * 1024 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan"])
        .arg(root.path())
        .arg("--json")
        .timeout(SCAN_TIMEOUT)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    assert!(findings.as_array().unwrap().is_empty());
}
