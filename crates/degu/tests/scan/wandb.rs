use super::support::*;

fn default_artifact_cache(home: &std::path::Path) -> std::path::PathBuf {
    crate::common::platform_cache_dir(home, "wandb").join("artifacts")
}

#[test]
fn scan_reports_only_the_default_wandb_artifact_cache() {
    let home = tempfile::tempdir().unwrap();
    let cache = default_artifact_cache(home.path());
    let object = cache.join("obj/md5/aa/digest");
    let temporary = cache.join("tmp/in-progress");
    std::fs::create_dir_all(object.parent().unwrap()).unwrap();
    std::fs::create_dir_all(temporary.parent().unwrap()).unwrap();
    std::fs::write(&object, [0_u8; 8192]).unwrap();
    std::fs::write(&temporary, [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "wandb", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| {
        finding["ecosystem"] == "wandb"
            && finding["kind"] == "other"
            && finding["recovery"]["kind"] == "regenerable"
            && finding["recovery"]["cost"] == "costly"
            && finding["ownership"] == "tool_coordinated"
            && finding["disposition"]["mode"] == "report_only"
    }));
    let objects = findings
        .iter()
        .find(|finding| finding["path"].as_str().unwrap().ends_with("/obj"))
        .unwrap();
    let temporary = findings
        .iter()
        .find(|finding| finding["path"].as_str().unwrap().ends_with("/tmp"))
        .unwrap();
    assert_eq!(
        objects["path"],
        cache
            .join("obj")
            .canonicalize()
            .unwrap()
            .display()
            .to_string()
    );
    assert_eq!(
        temporary["path"],
        cache
            .join("tmp")
            .canonicalize()
            .unwrap()
            .display()
            .to_string()
    );
    assert!(objects.get("hazard").is_none());
    assert_eq!(temporary["hazard"], "active_use");
    assert!(
        objects["rationale"]
            .as_str()
            .unwrap()
            .contains("wandb artifact cache cleanup TARGET_SIZE")
    );
    assert!(
        temporary["rationale"]
            .as_str()
            .unwrap()
            .contains("--remove-temp TARGET_SIZE")
    );
    let measured = findings
        .iter()
        .map(|finding| finding["bytes_allocated"].as_u64().unwrap())
        .sum::<u64>();
    assert!(measured >= 12 * 1024);
}

#[test]
fn scan_appends_artifacts_once_to_wandb_cache_dir() {
    let home = tempfile::tempdir().unwrap();
    let base = home.path().join("scratch/wandb");
    let cache = base.join("artifacts");
    let object = cache.join("obj/etag/aa/digest");
    std::fs::create_dir_all(object.parent().unwrap()).unwrap();
    std::fs::write(&object, [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("WANDB_CACHE_DIR", &base)
        .args(["scan", "--only", "wandb", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding["path"], cache.join("obj").display().to_string());
    assert_eq!(finding["confidence"], "unverified");
    assert_eq!(finding["ownership"], "tool_coordinated");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert!(
        !finding["path"]
            .as_str()
            .unwrap()
            .ends_with("/artifacts/artifacts")
    );
}

#[test]
fn scan_does_not_claim_wandb_run_staging_download_or_config_paths() {
    let home = tempfile::tempdir().unwrap();
    let cache_root = home.path().join("cache");
    let object = cache_root.join("artifacts/obj/md5/aa/digest");
    std::fs::create_dir_all(object.parent().unwrap()).unwrap();
    std::fs::write(&object, [0_u8; 4096]).unwrap();

    let data_dir = home.path().join("data");
    let run_dir = home.path().join("runs");
    let artifact_dir = home.path().join("downloaded-artifacts");
    let config_dir = home.path().join("config");
    seed_unrelated_wandb_paths(&data_dir, &run_dir, &artifact_dir, &config_dir);

    let out = degu()
        .env("HOME", home.path())
        .env("WANDB_CACHE_DIR", &cache_root)
        .env("WANDB_DATA_DIR", &data_dir)
        .env("WANDB_DIR", &run_dir)
        .env("WANDB_ARTIFACT_DIR", &artifact_dir)
        .env("WANDB_CONFIG_DIR", &config_dir)
        .args(["scan", "--only", "wandb", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = scan_findings(&out.stdout);
    let findings = findings.as_array().unwrap();
    assert!(!findings.is_empty());

    let artifact_cache = cache_root.join("artifacts");
    let unrelated = [data_dir, run_dir, artifact_dir, config_dir];
    assert!(findings.iter().all(|finding| {
        let path = std::path::Path::new(finding["path"].as_str().unwrap());
        path.starts_with(&artifact_cache)
            && (path.ends_with("obj") || path.ends_with("tmp"))
            && unrelated.iter().all(|dir| !path.starts_with(dir))
    }));
}

fn seed_unrelated_wandb_paths(
    data_dir: &std::path::Path,
    run_dir: &std::path::Path,
    artifact_dir: &std::path::Path,
    config_dir: &std::path::Path,
) {
    for path in [
        data_dir.join("artifacts/staging"),
        run_dir.join("wandb/run-1/files"),
        artifact_dir.join("downloaded"),
        config_dir.to_path_buf(),
    ] {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("user-or-active-data"), [0_u8; 1024]).unwrap();
    }
}
