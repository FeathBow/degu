use super::support::*;

#[test]
fn scan_reports_the_default_modelscope_cache_without_cleanup_authority() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join(".cache/modelscope/hub");
    let model = cache.join("models/org/model");
    let dataset = cache.join("datasets/org/dataset");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::create_dir_all(&dataset).unwrap();
    std::fs::write(model.join("model.safetensors"), [0_u8; 8192]).unwrap();
    std::fs::write(dataset.join("data.parquet"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "modelscope", "--json"])
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
    assert_eq!(finding["ecosystem"], "modelscope");
    assert_eq!(
        finding["path"],
        cache.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(finding["kind"], "model_cache");
    assert_eq!(finding["recovery"]["kind"], "regenerable");
    assert_eq!(finding["recovery"]["cost"], "costly");
    assert_eq!(finding["ownership"], "tool_coordinated");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert!(
        finding["rationale"]
            .as_str()
            .unwrap()
            .contains("MODELSCOPE_CACHE")
    );
    assert!(finding["bytes_allocated"].as_u64().unwrap() >= 12 * 1024);
}

#[test]
fn scan_uses_modelscope_cache_as_the_exact_redirected_base() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("scratch/modelscope");
    let model = cache.join("models/org/model");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(model.join("weights.bin"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("MODELSCOPE_CACHE", &cache)
        .args(["scan", "--only", "modelscope", "--json"])
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
    assert_eq!(finding["path"], cache.display().to_string());
    assert_eq!(finding["confidence"], "unverified");
    assert_eq!(finding["ownership"], "tool_coordinated");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert!(
        !finding["path"]
            .as_str()
            .unwrap()
            .ends_with("/modelscope/modelscope")
    );
}

#[test]
fn scan_expands_a_leading_tilde_in_modelscope_cache() {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("scratch/ms");
    let model = cache.join("models/org/model");
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(model.join("weights.bin"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("MODELSCOPE_CACHE", "~/scratch/ms")
        .args(["scan", "--only", "modelscope", "--json"])
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
    assert_eq!(
        finding["path"],
        cache.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(finding["confidence"], "unverified");
    assert_eq!(finding["disposition"]["mode"], "report_only");
}
