use crate::relocate_support::degu;
use std::os::unix::ffi::OsStringExt;

#[test]
fn relocate_rejects_only_non_utf8_roots_that_reach_output() {
    let home = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let pip = parent
        .path()
        .join(std::ffi::OsString::from_vec(b"pip-\xff".to_vec()));
    std::fs::create_dir(&pip).unwrap();

    for json in [false, true] {
        let mut cmd = degu();
        cmd.env("HOME", home.path())
            .env("PIP_CACHE_DIR", &pip)
            .args(["relocate", "/scratch/x"]);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("existing pip root contains invalid UTF-8"));
    }

    let tmp = parent
        .path()
        .join(std::ffi::OsString::from_vec(b"tmp-\xff".to_vec()));
    std::fs::create_dir(&tmp).unwrap();
    for json in [false, true] {
        let mut cmd = degu();
        cmd.env("HOME", home.path())
            .env("TMPDIR", &tmp)
            .args(["relocate", "/scratch/x"]);
        if json {
            cmd.arg("--json");
        }
        assert!(cmd.output().unwrap().status.success());
    }
}
