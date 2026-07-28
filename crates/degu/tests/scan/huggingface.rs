use super::support::*;

#[test]
fn scan_json_reports_huggingface_hub_cache() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    let alpha = hub.join("models--org--alpha/snapshots/main");
    let beta = hub.join("models--org--beta/snapshots/main");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(alpha.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(beta.join("model.bin"), [0u8; 128 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|finding| {
        finding["ecosystem"] == "huggingface" && finding["disposition"]["mode"] == "opt_in"
    }));
    for model in ["models--org--alpha", "models--org--beta"] {
        assert!(
            arr.iter()
                .any(|finding| finding["path"].as_str().unwrap().ends_with(model))
        );
    }
}

#[test]
fn scan_json_reports_redirected_huggingface_hub_with_per_model_granularity() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join("scratch/hf-hub");
    let alpha = hub.join("models--org--alpha/snapshots/main");
    let beta = hub.join("models--org--beta/snapshots/main");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(alpha.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(beta.join("model.bin"), [0u8; 128 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("HF_HUB_CACHE", &hub)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|finding| {
        finding["ecosystem"] == "huggingface"
            && finding["disposition"]["mode"] == "report_only"
            && finding["path"].as_str().unwrap().contains("models--org--")
    }));
}

#[test]
fn hf_xet_cache_overrides_hf_home_xet() {
    let home = tempfile::tempdir().unwrap();
    let hf_home = home.path().join("huggingface");
    let fallback = hf_home.join("xet");
    let redirected = home.path().join("xet-cache");
    std::fs::create_dir_all(&fallback).unwrap();
    std::fs::create_dir_all(&redirected).unwrap();
    std::fs::write(fallback.join("fallback.bin"), [0_u8; 2048]).unwrap();
    std::fs::write(redirected.join("redirected.bin"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("HF_HOME", &hf_home)
        .env("HF_XET_CACHE", &redirected)
        .args(["scan", "--only", "huggingface", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], redirected.display().to_string());
    assert_eq!(arr[0]["confidence"], "unverified");
}

#[test]
fn scan_json_scoped_discovery_does_not_reclaim_redirected_huggingface_hub() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let hub = root.join("huggingface/hub");
    let alpha = hub.join("models--org--alpha/snapshots/main");
    let beta = hub.join("models--org--beta/snapshots/main");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(
        hub.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(alpha.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(beta.join("model.bin"), [0u8; 128 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("HF_HUB_CACHE", &hub)
        .args(["scan", "--json"])
        .arg(&root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let hf_findings = arr
        .iter()
        .filter(|finding| finding["ecosystem"] == "huggingface")
        .collect::<Vec<_>>();
    assert_eq!(hf_findings.len(), 2);
    assert!(hf_findings.iter().all(|finding| {
        finding["path"].as_str().unwrap().contains("models--org--")
            && finding["kind"] == "model_cache"
    }));
    assert!(!arr.iter().any(|finding| {
        finding["ecosystem"] == "artifacts" && finding["path"] == hub.display().to_string()
    }));

    let total_bytes = arr
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    let hf_bytes = hf_findings
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    assert!(hf_bytes >= 8192 + 128 * 1024);
    assert_eq!(total_bytes, hf_bytes);
}

#[cfg(unix)]
fn symlinked_huggingface_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let lus_scratch = root.join("lus-scratch");
    let scratch = root.join("scratch");
    let scan_root = lus_scratch.join("cache");
    let hub = scan_root.join("huggingface/hub");
    let alpha = hub.join("models--org--alpha/snapshots/main");
    let beta = hub.join("models--org--beta/snapshots/main");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::os::unix::fs::symlink(&lus_scratch, &scratch).unwrap();
    std::fs::write(
        hub.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(alpha.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(beta.join("model.bin"), [0u8; 128 * 1024]).unwrap();
    let redirected_hub = scratch.join("cache/huggingface/hub");
    (root_temp, scan_root, hub, redirected_hub)
}

#[cfg(unix)]
#[test]
fn scan_json_scoped_discovery_claims_symlinked_huggingface_hub() {
    let home = tempfile::tempdir().unwrap();
    let (_root_temp, scan_root, hub, redirected_hub) = symlinked_huggingface_fixture();
    let out = degu()
        .env("HOME", home.path())
        .env("HF_HUB_CACHE", redirected_hub)
        .args(["scan", "--json"])
        .arg(&scan_root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let hf_findings = arr
        .iter()
        .filter(|finding| finding["ecosystem"] == "huggingface")
        .collect::<Vec<_>>();
    assert_eq!(hf_findings.len(), 2);
    assert!(hf_findings.iter().all(|finding| {
        finding["path"].as_str().unwrap().contains("models--org--")
            && finding["kind"] == "model_cache"
    }));
    assert!(!arr.iter().any(|finding| {
        finding["ecosystem"] == "artifacts" && finding["path"] == hub.display().to_string()
    }));

    let total_bytes = arr
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    let hf_bytes = hf_findings
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    assert!(hf_bytes >= 8192 + 128 * 1024);
    assert_eq!(total_bytes, hf_bytes);
}

#[test]
fn scan_json_scoped_discovery_keeps_unclaimed_cachedir_tag_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let hub = root.join("huggingface/hub");
    let model = hub.join("models--org--alpha/snapshots/main");
    let tagged = root.join("standalone-cache");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::create_dir_all(&tagged).unwrap();
    std::fs::write(
        hub.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(
        tagged.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(model.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(tagged.join("payload.bin"), [0u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("HF_HUB_CACHE", &hub)
        .args(["scan", "--json"])
        .arg(&root)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert!(arr.iter().any(|finding| {
        finding["ecosystem"] == "huggingface"
            && finding["path"]
                .as_str()
                .unwrap()
                .contains("models--org--alpha")
    }));
    assert!(arr.iter().any(|finding| {
        finding["ecosystem"] == "artifacts"
            && finding["kind"] == "other"
            && finding["path"] == tagged.display().to_string()
    }));
    assert!(!arr.iter().any(|finding| {
        finding["ecosystem"] == "artifacts" && finding["path"] == hub.display().to_string()
    }));
}

#[test]
fn scan_json_reports_huggingface_orphan_locks_and_skips_busy_repos() {
    let home = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    let busy = hub.join("models--org--busy/snapshots/main");
    let gone_locks = hub.join(".locks/models--org--gone");
    let busy_locks = hub.join(".locks/models--org--busy");
    std::fs::create_dir_all(&busy).unwrap();
    std::fs::create_dir_all(&gone_locks).unwrap();
    std::fs::create_dir_all(&busy_locks).unwrap();
    std::fs::write(busy.join("model.bin"), [0u8; 8192]).unwrap();
    std::fs::write(gone_locks.join("x.lock"), []).unwrap();
    let busy_lock = std::fs::File::create(busy_locks.join("y.lock")).unwrap();
    rustix::fs::flock(
        &busy_lock,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "huggingface");
    assert_eq!(arr[0]["kind"], "other");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert!(
        arr[0]["path"]
            .as_str()
            .unwrap()
            .ends_with(".locks/models--org--gone")
    );
    assert!(arr.iter().all(|finding| {
        !finding["path"]
            .as_str()
            .unwrap()
            .contains("models--org--busy")
    }));
}
