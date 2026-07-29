use super::support::*;

const LARGE_PAYLOAD_BYTES: usize = 128 * 1024;
const TIE_PAYLOAD_BYTES: usize = 8 * 1024;

#[test]
fn scan_json_orders_findings_by_size_ecosystem_and_path() {
    let fixture = OrderingFixture::new();
    let out = fixture.scan();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    let ecosystems = arr
        .iter()
        .map(|finding| finding["ecosystem"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ecosystems, ["pip", "cargo", "cargo", "pixi", "uv"]);
    assert!(arr[1]["path"].as_str().unwrap().ends_with("/git"));
    assert!(arr[2]["path"].as_str().unwrap().ends_with("/registry"));
    let tied_bytes = arr[1]["bytes_allocated"].as_u64().unwrap();
    assert!(arr[0]["bytes_allocated"].as_u64().unwrap() > tied_bytes);
    assert!(
        arr[1..]
            .iter()
            .all(|finding| finding["bytes_allocated"] == tied_bytes)
    );
}

struct OrderingFixture {
    home: tempfile::TempDir,
    pip: std::path::PathBuf,
    cargo: std::path::PathBuf,
    pixi: std::path::PathBuf,
    uv: std::path::PathBuf,
}

impl OrderingFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let scratch = home.path().join("scratch");
        let pip = scratch.join("pip");
        let cargo = scratch.join("cargo");
        let pixi = scratch.join("pixi");
        let uv = scratch.join("uv");
        write_cache(&pip, LARGE_PAYLOAD_BYTES);
        write_cache(&cargo.join("registry"), TIE_PAYLOAD_BYTES);
        write_cache(&cargo.join("git"), TIE_PAYLOAD_BYTES);
        write_cache(&pixi, TIE_PAYLOAD_BYTES);
        write_cache(&uv, TIE_PAYLOAD_BYTES);
        Self {
            home,
            pip,
            cargo,
            pixi,
            uv,
        }
    }

    fn scan(&self) -> std::process::Output {
        degu()
            .env("HOME", self.home.path())
            .env("PIP_CACHE_DIR", &self.pip)
            .env("CARGO_HOME", &self.cargo)
            .env("PIXI_CACHE_DIR", &self.pixi)
            .env("UV_CACHE_DIR", &self.uv)
            .args(["scan", "--json"])
            .output()
            .unwrap()
    }
}

fn write_cache(path: &std::path::Path, bytes: usize) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(path.join("payload"), vec![0_u8; bytes]).unwrap();
}

#[test]
fn scan_min_size_hides_small_fixture_and_prints_hidden_summary() {
    let (home, pip_cache) = fake_cache("scratch/pip-cache", "wheel.whl", 1024);
    let uv_cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), vec![0u8; 128 * 1024]).unwrap();

    let json_out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--json"])
        .output()
        .unwrap();
    assert!(json_out.status.success());
    let findings = scan_findings(&json_out.stdout);
    let arr = findings.as_array().unwrap();
    let pip_bytes = arr
        .iter()
        .find(|finding| finding["ecosystem"] == "pip")
        .unwrap()["bytes_allocated"]
        .as_u64()
        .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--min-size", "64K"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(strip_sgr(&out.stdout)).unwrap();
    assert!(stdout.contains("uv"));
    assert!(!stdout.contains("pip"));
    let hidden_bytes = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Hidden by filters: 1 location - "))
        .unwrap();
    assert_human_bytes(hidden_bytes, pip_bytes);
}

#[test]
fn scan_top_one_keeps_only_largest_finding() {
    let (home, pip_cache) = fake_cache("scratch/pip-cache", "wheel.whl", 1024);
    let uv_cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), vec![0u8; 128 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--top", "1", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "uv");
}

#[test]
fn scan_only_executes_the_selected_adapter_without_resolving_project_roots() {
    let (home, pip_cache) = fake_cache("scratch/pip-cache", "wheel.whl", 1024);
    let uv_cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), vec![0u8; 128 * 1024]).unwrap();
    let missing_project = home.path().join("missing-project");

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["-v", "scan", "--only", "pip", "--json"])
        .arg(&missing_project)
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(pip_cache.to_str().unwrap()), "{stderr}");
    assert!(!stderr.contains(uv_cache.to_str().unwrap()), "{stderr}");
    assert!(
        !stderr.contains(missing_project.to_str().unwrap()),
        "{stderr}"
    );
}

#[test]
fn scan_only_rejects_unknown_source_and_lists_project_sources() {
    let home = tempfile::tempdir().unwrap();
    let missing_project = home.path().join("missing-project");
    let out = degu()
        .env("HOME", home.path())
        .args(["scan", "--only", "missing-source"])
        .arg(&missing_project)
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("unknown source \"missing-source\""));
    assert!(stderr.contains("artifacts"));
    assert!(stderr.contains("checkpoints"));
    assert!(!stderr.contains("failed to access project root"));
}

#[test]
fn scan_older_than_keeps_stale_and_fail_closes_unknown_or_fresh_age() {
    let home = tempfile::tempdir().unwrap();
    let pip_cache = home.path().join("scratch/pip-cache");
    let uv_cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&pip_cache).unwrap();
    std::fs::create_dir_all(&uv_cache).unwrap();
    let stale_file = pip_cache.join("wheel.whl");
    std::fs::write(&stale_file, [0u8; 2048]).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), [0u8; 2048]).unwrap();
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 24 * 60 * 60);
    std::fs::File::open(&stale_file)
        .unwrap()
        .set_modified(stale)
        .unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--older-than", "7", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "pip");
}

#[test]
fn scan_json_with_min_size_returns_only_surviving_findings() {
    let (home, pip_cache) = fake_cache("scratch/pip-cache", "wheel.whl", 1024);
    let uv_cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&uv_cache).unwrap();
    std::fs::write(uv_cache.join("archive.zip"), vec![0u8; 128 * 1024]).unwrap();

    let out = degu()
        .env("HOME", home.path())
        .env("PIP_CACHE_DIR", &pip_cache)
        .env("UV_CACHE_DIR", &uv_cache)
        .args(["scan", "--min-size", "64K", "--json"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let findings = scan_findings(&out.stdout);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "uv");
}
