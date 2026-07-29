use super::support::*;

const LOCAL_MODEL_BYTES: usize = 8 * 1024;
const LOCAL_MODEL_DIGEST: &str = "9f1dcbc35c350d6027f98be0f5c8b43b42ca52b7604459c0c42be3aa88913d47";
const LOCAL_CONFIG: &[u8] = b"{}";
const LOCAL_CONFIG_DIGEST: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const OCI_SCHEMA_VERSION: u8 = 2;

#[test]
fn scan_json_reports_redirected_ollama_models() {
    let (home, cache) = fake_cache("scratch/ollama-models", "model.blob", 8192);

    let out = degu()
        .env("HOME", home.path())
        .env("OLLAMA_MODELS", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "ollama");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
}

#[test]
fn clean_never_plans_locally_created_ollama_models() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = home.path().canonicalize().unwrap().join(".ollama/models");
    let (manifest, model_blob) = fake_local_ollama_model(&root);

    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args(["clean", "--yes", "--include-review", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["planned"].as_array().unwrap().is_empty());
    assert!(report["executed"].as_array().unwrap().is_empty());
    assert_eq!(report["excluded"].as_array().unwrap().len(), 1);
    let finding = &report["excluded"][0];
    assert_eq!(finding["ecosystem"], "ollama");
    assert_eq!(finding["disposition"]["mode"], "report_only");
    assert_eq!(finding["recovery"]["kind"], "user_asset");
    assert_eq!(finding["ownership"], "tool_coordinated");
    assert_eq!(finding["path"], root.display().to_string());
    assert!(
        finding["rationale"]
            .as_str()
            .unwrap()
            .contains("locally created")
    );
    assert!(manifest.exists());
    assert_eq!(
        std::fs::read(&model_blob).unwrap(),
        [0u8; LOCAL_MODEL_BYTES]
    );
    assert!(!state.path().join("degu/trash").exists());
    assert!(!state.path().join("degu/ops.jsonl").exists());
}

fn fake_local_ollama_model(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let manifest = root.join("manifests/registry.ollama.ai/library/local-model/latest");
    let model_blob = root.join(format!("blobs/sha256-{LOCAL_MODEL_DIGEST}"));
    let config_blob = root.join(format!("blobs/sha256-{LOCAL_CONFIG_DIGEST}"));
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::create_dir_all(model_blob.parent().unwrap()).unwrap();
    std::fs::write(&config_blob, LOCAL_CONFIG).unwrap();
    std::fs::write(&model_blob, [0u8; LOCAL_MODEL_BYTES]).unwrap();
    let local_manifest = serde_json::json!({
        "schemaVersion": OCI_SCHEMA_VERSION,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": format!("sha256:{LOCAL_CONFIG_DIGEST}"),
            "size": LOCAL_CONFIG.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.ollama.image.model",
            "digest": format!("sha256:{LOCAL_MODEL_DIGEST}"),
            "size": LOCAL_MODEL_BYTES,
        }],
    });
    std::fs::write(&manifest, serde_json::to_vec(&local_manifest).unwrap()).unwrap();
    (manifest, model_blob)
}

#[test]
fn scan_json_reports_legacy_singularity_cache_as_apptainer() {
    let (home, cache) = fake_cache("scratch/singularity-cache", "blob", 4096);

    let out = degu()
        .env("HOME", home.path())
        .env("SINGULARITY_CACHEDIR", &cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "apptainer");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
}

#[test]
fn scan_json_reports_cargo_registry_cache() {
    let (home, _) = fake_cache(".cargo/registry", "crate.crate", 2048);

    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "cargo");
    assert_eq!(arr[0]["disposition"]["mode"], "eligible");
    assert_eq!(arr[0]["inodes"], 2);
    assert!(arr[0]["bytes_apparent"].as_u64().unwrap() >= 2048);
    assert!(arr[0]["bytes_allocated"].as_u64().unwrap() >= 2048);
}

#[test]
fn scan_json_treats_environment_homes_as_unverified_redirects() {
    let home = tempfile::tempdir().unwrap();
    let cargo = home.path().join("scratch/cargo-home/registry");
    let model = home
        .path()
        .join("scratch/hf-home/hub/models--org--model/snapshots/main");
    std::fs::create_dir_all(&cargo).unwrap();
    std::fs::create_dir_all(&model).unwrap();
    std::fs::write(cargo.join("crate.crate"), [0_u8; 2048]).unwrap();
    std::fs::write(model.join("model.bin"), [0_u8; 4096]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("CARGO_HOME", home.path().join("scratch/cargo-home"))
        .env("HF_HOME", home.path().join("scratch/hf-home"))
        .args(["scan", "--json", "--only", "cargo", "--only", "huggingface"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let mut ecosystems = arr
        .iter()
        .map(|finding| finding["ecosystem"].as_str().unwrap())
        .collect::<Vec<_>>();
    ecosystems.sort_unstable();
    assert_eq!(ecosystems, ["cargo", "huggingface"]);
    assert!(arr.iter().all(|finding| {
        finding["confidence"] == "unverified" && finding["disposition"]["mode"] == "report_only"
    }));
}

#[test]
fn scan_json_reports_multiple_conda_package_dirs() {
    let (home, cache_one) = fake_cache("scratch/conda-pkgs-one", "pkg-one.tar.bz2", 1024);
    let cache_two = home.path().join("scratch/conda-pkgs-two");
    std::fs::create_dir_all(&cache_two).unwrap();
    std::fs::write(cache_two.join("pkg-two.conda"), vec![0u8; 2048]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env(
            "CONDA_PKGS_DIRS",
            format!("{}, {}", cache_one.display(), cache_two.display()),
        )
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|finding| finding["ecosystem"] == "conda"));
    assert!(
        arr.iter()
            .all(|finding| finding["disposition"]["mode"] == "report_only")
    );
}

fn conda_package_and_environment_fixture()
-> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("miniconda3/pkgs");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("pkg-one.tar.bz2"), vec![0u8; 1024]).unwrap();
    let env = home.path().join("miniconda3/envs/myenv");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
    let conda_home = home.path().join(".conda");
    std::fs::create_dir_all(&conda_home).unwrap();
    std::fs::write(
        conda_home.join("environments.txt"),
        format!(
            "{}\n{}\n",
            env.display(),
            home.path().join("missing-env").display()
        ),
    )
    .unwrap();
    (home, cache, env)
}

#[test]
fn scan_json_reports_conda_package_cache_and_environment_once() {
    let (home, cache, env) = conda_package_and_environment_fixture();
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    let cache = cache.canonicalize().unwrap();
    let cache_path = cache.to_string_lossy();
    let cache_finding = arr
        .iter()
        .find(|finding| finding["path"] == cache_path.as_ref())
        .unwrap();
    assert_eq!(cache_finding["ecosystem"], "conda");
    assert_eq!(cache_finding["kind"], "package_cache");
    assert_eq!(cache_finding["disposition"]["mode"], "opt_in");
    assert_eq!(cache_finding["hazard"], "breaks_consumers");

    let env = env.canonicalize().unwrap();
    let env_path = env.to_string_lossy();
    let env_findings = arr
        .iter()
        .filter(|finding| finding["path"] == env_path.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(env_findings.len(), 1);
    assert_eq!(env_findings[0]["ecosystem"], "conda");
    assert_eq!(env_findings[0]["kind"], "environment");
    assert_eq!(env_findings[0]["disposition"]["mode"], "report_only");
    assert_eq!(env_findings[0]["recovery"]["kind"], "user_asset");
    assert!(
        env_findings[0]["rationale"]
            .as_str()
            .unwrap()
            .contains("last package operation 0 days ago")
    );
}

// The Caskroom miniforge shape: the base lives outside HOME, so the fixed
// pkgs list cannot see it, and only the registered child environment leads
// discovery to the base and its package cache.
#[test]
fn scan_json_reports_derived_conda_pkgs_for_home_external_base() {
    let home = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let base = external.path().join("Caskroom/miniforge/base");
    std::fs::create_dir_all(base.join("conda-meta")).unwrap();
    let cache = base.join("pkgs");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join("urls.txt"),
        "https://conda.anaconda.org/conda-forge/noarch\n",
    )
    .unwrap();
    std::fs::write(cache.join("pkg-one.tar.bz2"), vec![0u8; 1024]).unwrap();
    let env = base.join("envs/foo");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
    let conda_home = home.path().join(".conda");
    std::fs::create_dir_all(&conda_home).unwrap();
    std::fs::write(
        conda_home.join("environments.txt"),
        format!("{}\n", env.display()),
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
    assert_eq!(arr.len(), 2);

    let cache = cache.canonicalize().unwrap();
    let cache_path = cache.to_string_lossy();
    let cache_finding = arr
        .iter()
        .find(|finding| finding["path"] == cache_path.as_ref())
        .unwrap();
    assert_eq!(cache_finding["ecosystem"], "conda");
    assert_eq!(cache_finding["kind"], "package_cache");
    assert_eq!(cache_finding["disposition"]["mode"], "opt_in");
    assert_eq!(cache_finding["hazard"], "breaks_consumers");
    assert_eq!(cache_finding["confidence"], "verified");
}

#[test]
fn scan_schedules_preferred_roots_before_deferred_roots() {
    let (home, conda_cache, conda_env) = conda_package_and_environment_fixture();
    let first_conda_env = home.path().join("miniconda3/envs/another-env");
    std::fs::create_dir_all(first_conda_env.join("conda-meta")).unwrap();
    std::fs::write(first_conda_env.join("conda-meta/history"), "created").unwrap();
    let pip_cache = home.path().join("relocated/pip-cache");
    std::fs::create_dir_all(&pip_cache).unwrap();
    // Redirect roots are logged verbatim from the environment; canonicalize
    // here so the log positions resolve on platforms where TMPDIR is a symlink.
    let pip_cache = pip_cache.canonicalize().unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0_u8; 1024]).unwrap();
    std::fs::write(
        pip_cache.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();
    let npm_cache = home.path().join("relocated/npm-cache");
    std::fs::create_dir_all(&npm_cache).unwrap();
    let npm_cache = npm_cache.canonicalize().unwrap();
    std::fs::write(npm_cache.join("tarball.tgz"), [0_u8; 1024]).unwrap();
    let project = tempfile::tempdir().unwrap();
    let checkpoints = project.path().join("checkpoints");
    std::fs::create_dir(&checkpoints).unwrap();
    std::fs::write(checkpoints.join("epoch.pt"), [0_u8; 1024]).unwrap();

    let mut command = degu();
    command
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("NPM_CONFIG_CACHE", &npm_cache)
        .args([
            "-v",
            "scan",
            "--only",
            "conda",
            "--only",
            "npm",
            "--only",
            "pip",
            "--only",
            "checkpoints",
            "--json",
        ]);
    let out = command.arg(project.path()).output().unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let preferred = [conda_cache, pip_cache].map(|root| scan_log_position(&stderr, root));
    let deferred = [
        project.path().to_path_buf(),
        first_conda_env,
        conda_env,
        npm_cache,
    ]
    .map(|root| scan_log_position(&stderr, root));

    assert!(
        preferred.iter().max().unwrap() < deferred.iter().min().unwrap(),
        "{stderr}"
    );
    assert!(
        preferred.windows(2).all(|pair| pair[0] < pair[1]),
        "{stderr}"
    );
    assert!(
        deferred.windows(2).all(|pair| pair[0] < pair[1]),
        "{stderr}"
    );
}

#[test]
fn scan_priority_matches_finding_disposition_class() {
    let (home, _conda_cache, _conda_env) = conda_package_and_environment_fixture();
    let pip_cache = crate::common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::write(pip_cache.join("wheel.whl"), [0_u8; 1024]).unwrap();
    let uv_cache = home.path().join(".cache/uv");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive.zst"), [0_u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .args([
            "-vv", "scan", "--only", "conda", "--only", "pip", "--only", "uv", "--json",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let mut priorities = std::collections::HashMap::new();
    for line in stderr
        .lines()
        .filter(|line| line.contains("scheduled root"))
    {
        let root = field_value(line, "root=");
        let priority = field_value(line, "priority=");
        priorities.insert(root, priority);
    }
    assert!(!priorities.is_empty(), "{stderr}");

    let findings = scan_findings(&out.stdout);
    let mut actionable = 0;
    let mut static_report_only = 0;
    for finding in findings.as_array().unwrap() {
        let path = finding["path"].as_str().unwrap();
        let priority = priorities
            .get(path)
            .unwrap_or_else(|| panic!("no scheduled-root log for {path}\n{stderr}"));
        match finding["disposition"]["mode"].as_str().unwrap() {
            "eligible" | "opt_in" => {
                actionable += 1;
                assert_eq!(priority, "Preferred", "{path} {stderr}");
            }
            "report_only" => {
                let reason = finding["disposition"]["reason"].as_str().unwrap();
                let static_class = reason.starts_with("user asset")
                    || reason.starts_with("managed by the owning tool");
                if static_class {
                    static_report_only += 1;
                    assert_eq!(priority, "Deferred", "{path} {stderr}");
                }
            }
            other => panic!("unexpected disposition mode {other}"),
        }
    }
    assert!(actionable >= 2, "fixture lost actionable coverage");
    assert!(static_report_only >= 2, "fixture lost report-only coverage");
}

#[test]
fn mixed_state_ai_roots_are_deferred_at_scheduling() {
    let home = tempfile::tempdir().unwrap();
    let claude_cache = home.path().join(".claude/pip-cache");
    std::fs::create_dir_all(&claude_cache).unwrap();
    let claude_cache = claude_cache.canonicalize().unwrap();
    std::fs::write(claude_cache.join("wheel.whl"), [0_u8; 1024]).unwrap();
    std::fs::write(
        claude_cache.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();
    let npm_cache = home.path().join(".npm");
    std::fs::create_dir_all(&npm_cache).unwrap();
    std::fs::write(npm_cache.join("tarball.tgz"), [0_u8; 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &claude_cache)
        .args(["-vv", "scan", "--only", "npm", "--only", "pip", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let mut priorities = std::collections::HashMap::new();
    for line in stderr
        .lines()
        .filter(|line| line.contains("scheduled root"))
    {
        priorities.insert(field_value(line, "root="), field_value(line, "priority="));
    }
    let claude_key = claude_cache.to_string_lossy().to_string();
    assert_eq!(
        priorities.get(&claude_key).map(String::as_str),
        Some("Deferred"),
        "{stderr}"
    );
    let npm_key = home
        .path()
        .canonicalize()
        .unwrap()
        .join(".npm")
        .to_string_lossy()
        .to_string();
    assert_eq!(
        priorities.get(&npm_key).map(String::as_str),
        Some("Preferred"),
        "{stderr}"
    );
}

fn field_value(line: &str, key: &str) -> String {
    let start = line.find(key).unwrap() + key.len();
    line[start..].split_whitespace().next().unwrap().to_string()
}

fn scan_log_position(stderr: &str, root: std::path::PathBuf) -> usize {
    let root = root.canonicalize().unwrap();
    stderr
        .lines()
        .position(|line| line.contains("scan complete") && line.contains(&*root.to_string_lossy()))
        .unwrap_or_else(|| panic!("missing scan log for {}\n{stderr}", root.display()))
}

#[test]
fn scan_json_reports_conda_envs_path_children_only_when_they_are_envs() {
    assert_conda_envs_redirect("CONDA_ENVS_PATH");
}

#[test]
fn scan_json_reports_conda_envs_dirs_children_only_when_they_are_envs() {
    assert_conda_envs_redirect("CONDA_ENVS_DIRS");
}

#[test]
fn scoped_scan_skips_non_environment_entries_but_fails_on_conda_probe_errors() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let envs = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(envs.path().join(".conda_envs_dir_test"), "").unwrap();
    std::os::unix::fs::symlink("loop", envs.path().join("loop")).unwrap();
    let scan = || {
        degu()
            .env("HOME", home.path())
            .env("CONDA_ENVS_PATH", envs.path())
            .args(["scan", "--only", "artifacts", "--json"])
            .arg(project.path())
            .output()
            .unwrap()
    };

    let complete = scan();
    assert!(
        complete.status.success(),
        "{}",
        String::from_utf8_lossy(&complete.stderr)
    );
    assert!(
        complete.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&complete.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&complete.stdout).unwrap();
    assert_eq!(report["completeness"]["findings"], "complete");

    // Removing search permission makes child probes fail with EACCES, which is
    // genuinely indeterminate and must keep failing closed.
    std::fs::set_permissions(envs.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
    let failed = scan();
    std::fs::set_permissions(envs.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!failed.status.success());
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains("conda environment root probe failed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("failed to resolve protective roots for adapter \"conda\""),
        "{stderr}"
    );
}

fn assert_conda_envs_redirect(variable: &str) {
    let home = tempfile::tempdir().unwrap();
    let envs_dir = home.path().join("scratch/conda-envs");
    let env = envs_dir.join("analysis");
    let stray = envs_dir.join("not-an-env");
    std::fs::create_dir_all(env.join("conda-meta")).unwrap();
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env(variable, &envs_dir)
        .args(["scan", "--only", "conda", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "conda");
    assert_eq!(arr[0]["kind"], "environment");
    assert_eq!(arr[0]["disposition"]["mode"], "report_only");
    assert_eq!(
        arr[0]["path"],
        env.canonicalize().unwrap().to_string_lossy().as_ref()
    );
}

#[test]
fn conflicting_conda_env_aliases_are_reported_without_dropping_roots() {
    let home = tempfile::tempdir().unwrap();
    let first = home.path().join("first/environment");
    let second = home.path().join("second/environment");
    for environment in [&first, &second] {
        std::fs::create_dir_all(environment.join("conda-meta")).unwrap();
        std::fs::write(environment.join("conda-meta/history"), "created").unwrap();
    }

    let out = degu()
        .env("HOME", home.path())
        .env("CONDA_ENVS_PATH", first.parent().unwrap())
        .env("CONDA_ENVS_DIRS", second.parent().unwrap())
        .args(["scan", "--only", "conda", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["completeness"]["findings"], "incomplete");
    let paths = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["path"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(first.canonicalize().unwrap().to_str().unwrap()));
    assert!(paths.contains(second.canonicalize().unwrap().to_str().unwrap()));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CONDA_ENVS_PATH") && stderr.contains("CONDA_ENVS_DIRS"));
}
