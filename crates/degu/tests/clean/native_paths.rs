#![cfg(target_os = "linux")]

use super::support::*;

#[test]
fn clean_json_validates_native_expiry_root_before_housekeeping() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let state_parent = tempfile::tempdir().unwrap();
    let state = state_parent
        .path()
        .join(OsString::from_vec(b"state-\xff".to_vec()));
    let marker = state.join("degu/trash/.claims/1");
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    for dir in [
        state.join("degu"),
        state.join("degu/trash"),
        state.join("degu/trash/.claims"),
    ] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(&marker, []).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&marker)
        .unwrap()
        .set_modified(expired_time())
        .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", &state)
        .args(["clean", "--yes", "--json", "--only", "pip"])
        .output()
        .unwrap();

    assert_json_path_error(&out);
    assert!(marker.exists());
    assert!(!state.join("degu/ops.jsonl").exists());
}

fn assert_json_path_error(out: &std::process::Output) {
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("path contains invalid UTF-8"), "{stderr}");
    assert!(!stderr.contains("panicked at"), "{stderr}");
}
