#[path = "support/mod.rs"]
mod common;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "support/private_degu_state.rs"]
mod private_degu_state;
use common::isolated_degu as degu;

fn fake_pip_cache(home: &tempfile::TempDir) -> (std::path::PathBuf, tempfile::TempDir) {
    let state = tempfile::tempdir().unwrap();
    let cache = pip_cache::seed(home.path());
    (cache, state)
}

/// Holds the exclusive lock on `<state>/degu/lock` for the returned File's
/// lifetime, exactly like a concurrent mutating degu process would.
fn hold_mutation_lock(state: &tempfile::TempDir) -> std::fs::File {
    let dir = private_degu_state::create(state);
    let file = std::fs::File::create(dir.join("lock")).unwrap();
    file.lock().unwrap();
    file
}

#[test]
fn clean_refuses_while_lock_held_then_succeeds_after_release() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home);
    let holder = hold_mutation_lock(&state);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("holds the mutation lock"));
    assert!(cache.exists());
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());

    drop(holder);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(!cache.exists());
    assert!(state.path().join("degu/ops.jsonl").exists());
}

#[test]
fn scan_json_succeeds_while_lock_held() {
    let home = tempfile::tempdir().unwrap();
    let (cache, state) = fake_pip_cache(&home);
    let _holder = hold_mutation_lock(&state);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let cache_json = cache.canonicalize().unwrap().to_string_lossy().into_owned();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["path"] == cache_json.as_str())
    );
}

#[test]
fn trash_purge_refuses_while_mutation_lock_is_held() {
    let home = tempfile::tempdir().unwrap();
    let (_, state) = fake_pip_cache(&home);
    let staged = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(staged.status.success());
    let holder = hold_mutation_lock(&state);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["trash", "purge", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("holds the mutation lock"));
    assert!(state.path().join("degu/trash").read_dir().unwrap().count() > 0);
    drop(holder);
}
