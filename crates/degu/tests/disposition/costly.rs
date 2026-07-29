use super::support::*;

#[test]
fn audited_costly_compile_caches_require_opt_in() {
    let home = tempfile::tempdir().unwrap();
    let redirects = seed_compile_caches(&home);
    let scan = json_stdout(
        degu()
            .env("HOME", home.path())
            .env("TORCHINDUCTOR_CACHE_DIR", redirects.inductor.path())
            .env("JAX_COMPILATION_CACHE_DIR", redirects.jax.path())
            .args(["scan", "--json"])
            .output()
            .unwrap(),
    );
    assert_costly_findings(&scan);
}

struct Redirects {
    inductor: tempfile::TempDir,
    jax: tempfile::TempDir,
}

fn seed_compile_caches(home: &tempfile::TempDir) -> Redirects {
    fake_ccache_roots(home);
    // sccache probes only the current platform's dir (macOS uses Mozilla.sccache).
    #[cfg(target_os = "macos")]
    let sccache = home.path().join("Library/Caches/Mozilla.sccache");
    #[cfg(not(target_os = "macos"))]
    let sccache = home.path().join(".cache/sccache");
    let torch_ext = crate::common::platform_cache_dir(home.path(), "torch_extensions")
        .join("py311_cu121/myext");
    for root in [
        sccache,
        home.path().join(".cache/vllm"),
        home.path().join(".triton/cache"),
        torch_ext,
    ] {
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("payload.bin"), [0u8; 4096]).unwrap();
    }
    let redirects = Redirects {
        inductor: tempfile::tempdir().unwrap(),
        jax: tempfile::tempdir().unwrap(),
    };
    for root in [redirects.inductor.path(), redirects.jax.path()] {
        std::fs::write(
            root.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        std::fs::write(root.join("payload.bin"), [0u8; 4096]).unwrap();
    }
    redirects
}

fn assert_costly_findings(scan: &serde_json::Value) {
    for ecosystem in [
        "ccache", "sccache", "vllm", "triton", "torchext", "inductor", "jax",
    ] {
        let findings = scan["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["ecosystem"] == ecosystem)
            .collect::<Vec<_>>();
        assert!(
            !findings.is_empty(),
            "scan must report a {ecosystem} finding"
        );
        for finding in findings {
            assert_eq!(finding["recovery"]["cost"], "costly");
            assert_eq!(finding["disposition"]["mode"], "opt_in");
        }
    }
}

#[test]
fn clean_stages_ccache_only_with_opt_in_and_leaves_uv_untouched() {
    let fixture = MixedCaches::new();
    let default = json_stdout(fixture.run(&["clean", "--yes", "--json"]));
    assert!(default["planned"].as_array().unwrap().is_empty());
    assert!(
        default["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["ecosystem"] == "ccache"
                    && finding["path"] == fixture.ccache.display().to_string()
            })
    );

    let opt_in = json_stdout(fixture.run(&["clean", "--yes", "--include-review", "--json"]));
    assert_mixed_cache_execution(&fixture, &opt_in);
}

struct MixedCaches {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    ccache: std::path::PathBuf,
    uv: std::path::PathBuf,
    uv_sentinel: std::path::PathBuf,
}

impl MixedCaches {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let ccache = crate::common::platform_cache_dir(home.path(), "ccache");
        std::fs::create_dir_all(&ccache).unwrap();
        std::fs::write(ccache.join("artifact.o"), [0u8; 4096]).unwrap();
        let uv = home.path().join(".cache/uv");
        std::fs::create_dir_all(&uv).unwrap();
        let uv_sentinel = uv.join("archive.zip");
        std::fs::write(&uv_sentinel, [0u8; 4096]).unwrap();
        Self {
            ccache: ccache.canonicalize().unwrap(),
            uv: uv.canonicalize().unwrap(),
            home,
            state,
            uv_sentinel,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        degu()
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", self.state.path())
            .args(args)
            .output()
            .unwrap()
    }
}

fn assert_mixed_cache_execution(fixture: &MixedCaches, report: &serde_json::Value) {
    let planned = report["planned"].as_array().unwrap();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0]["ecosystem"], "ccache");
    assert_eq!(planned[0]["path"], fixture.ccache.display().to_string());
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0]["path"], fixture.ccache.display().to_string());
    assert_eq!(executed[0]["outcome"], "ok");
    assert!(std::path::Path::new(executed[0]["trash_entry"].as_str().unwrap()).exists());
    assert!(
        report["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["ecosystem"] == "uv" && finding["disposition"]["mode"] == "report_only"
            })
    );
    assert!(executed.iter().all(|item| {
        !std::path::Path::new(item["path"].as_str().unwrap()).starts_with(&fixture.uv)
    }));
    assert!(fixture.uv_sentinel.is_file());
}
