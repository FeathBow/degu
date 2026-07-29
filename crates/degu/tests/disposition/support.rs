pub(super) use crate::common::isolated_degu as degu;

pub(super) const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

pub(super) fn json_stdout(out: std::process::Output) -> serde_json::Value {
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

pub(super) fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub(super) fn fake_ccache_roots(home: &tempfile::TempDir) {
    // ccache probes only the current platform's cache dir now, so seed just that.
    let root = crate::common::platform_cache_dir(home.path(), "ccache");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("artifact.o"), [0u8; 4096]).unwrap();
}
