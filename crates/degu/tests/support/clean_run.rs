use std::path::Path;

pub fn run(home: impl AsRef<Path>, state: impl AsRef<Path>) {
    let output = crate::common::isolated_degu()
        .env("HOME", home.as_ref())
        .env("XDG_STATE_HOME", state.as_ref())
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
