use super::support::*;

struct UvCase<'a> {
    home: &'a tempfile::TempDir,
    redirect: Option<&'a std::path::Path>,
    roots: &'a [std::path::PathBuf],
    sentinels: &'a [std::path::PathBuf],
    expected_inodes: u64,
    expected_confidence: &'static str,
}

impl UvCase<'_> {
    fn run(&self, state: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
        let mut cmd = degu();
        cmd.env("HOME", self.home.path());
        cmd.env("XDG_STATE_HOME", state.path());
        if let Some(redirect) = self.redirect {
            cmd.env("UV_CACHE_DIR", redirect);
        }
        cmd.args(args).output().unwrap()
    }

    fn canonical_roots(&self) -> Vec<std::path::PathBuf> {
        self.roots
            .iter()
            .map(|root| root.canonicalize().unwrap())
            .collect()
    }
}

fn assert_uv_cache_report_only_end_to_end(case: UvCase<'_>) {
    let state = tempfile::tempdir().unwrap();
    let roots = case.canonical_roots();
    let scan = json_stdout(case.run(&state, &["scan", "--json"]));
    assert_uv_scan(&scan, &case);

    let clean = case.run(&state, &["clean", "--yes", "--include-review", "--purge"]);
    assert!(clean.status.success(), "stderr: {}", stderr(&clean));
    for sentinel in case.sentinels {
        assert!(
            sentinel.is_file(),
            "clean must not touch {}",
            sentinel.display()
        );
    }
    assert_no_uv_operation(&case, &state, &roots);

    let summary = json_stdout(case.run(&state, &["scan", "--summary", "--json"]));
    let uv = summary["ecosystems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["ecosystem"] == "uv")
        .expect("scan summary must still attribute the uv source");
    assert!(uv["bytes_allocated"].as_u64().unwrap() > 0);
}

fn assert_uv_scan(scan: &serde_json::Value, case: &UvCase<'_>) {
    let findings = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["ecosystem"] == "uv")
        .collect::<Vec<_>>();
    assert!(!findings.is_empty(), "scan must report a uv finding");
    for finding in findings {
        assert!(finding["bytes_apparent"].as_u64().unwrap() >= 4096);
        assert!(finding["bytes_allocated"].as_u64().unwrap() >= 4096);
        assert_eq!(finding["inodes"], case.expected_inodes);
        assert_eq!(finding["skipped"], 0);
        assert_eq!(finding["age_days"], 0);
        assert_eq!(finding["bytes_hardlinked"], 0);
        assert_eq!(finding["confidence"], case.expected_confidence);
        assert_eq!(finding["ownership"], "tool_coordinated");
        assert_eq!(finding["disposition"]["mode"], "report_only");
        let rationale = finding["rationale"].as_str().unwrap();
        assert!(rationale.contains("never safe") || rationale.contains("locks"));
    }
}

fn assert_no_uv_operation(
    case: &UvCase<'_>,
    state: &tempfile::TempDir,
    roots: &[std::path::PathBuf],
) {
    let trash = json_stdout(case.run(state, &["trash", "list", "--json"]));
    assert_eq!(trash["omitted"], 0);
    assert!(trash["entries"].as_array().unwrap().iter().all(|row| {
        row["original"].as_str().is_none_or(|original| {
            roots
                .iter()
                .all(|root| !std::path::Path::new(original).starts_with(root))
        })
    }));
    let ops = json_stdout(case.run(state, &["ops", "--json"]));
    assert!(ops.as_array().unwrap().iter().all(|record| {
        let path = std::path::Path::new(record["path"].as_str().unwrap());
        roots.iter().all(|root| !path.starts_with(root))
    }));
}

#[test]
fn uv_default_dual_dir_cache_stays_tool_coordinated_report_only() {
    let home = tempfile::tempdir().unwrap();
    // uv stays XDG-only on every platform, so it probes just `.cache/uv`.
    let roots = [home.path().join(".cache/uv")];
    let sentinels = roots
        .iter()
        .map(|root| {
            std::fs::create_dir_all(root).unwrap();
            let sentinel = root.join("archive.zip");
            std::fs::write(&sentinel, [0u8; 4096]).unwrap();
            sentinel
        })
        .collect::<Vec<_>>();
    assert_uv_cache_report_only_end_to_end(UvCase {
        home: &home,
        redirect: None,
        roots: &roots,
        sentinels: &sentinels,
        expected_inodes: 2,
        expected_confidence: "verified",
    });
}

#[test]
fn uv_tagged_redirect_stays_tool_coordinated_report_only() {
    let home = tempfile::tempdir().unwrap();
    let (cache, sentinel) = redirected_cache(&home, true);
    assert_redirect_case(&home, &cache, &sentinel);
}

#[test]
fn uv_untagged_redirect_stays_tool_coordinated_report_only() {
    let home = tempfile::tempdir().unwrap();
    let (cache, sentinel) = redirected_cache(&home, false);
    assert_redirect_case(&home, &cache, &sentinel);
}

fn redirected_cache(
    home: &tempfile::TempDir,
    tagged: bool,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let cache = home.path().join("scratch/uv-cache");
    std::fs::create_dir_all(&cache).unwrap();
    let sentinel = cache.join("archive.zip");
    std::fs::write(&sentinel, [0u8; 4096]).unwrap();
    if tagged {
        std::fs::write(
            cache.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
    }
    (cache, sentinel)
}

fn assert_redirect_case(
    home: &tempfile::TempDir,
    cache: &std::path::Path,
    sentinel: &std::path::Path,
) {
    let tagged = cache.join("CACHEDIR.TAG").is_file();
    assert_uv_cache_report_only_end_to_end(UvCase {
        home,
        redirect: Some(cache),
        roots: &[cache.to_path_buf()],
        sentinels: &[sentinel.to_path_buf()],
        expected_inodes: if tagged { 3 } else { 2 },
        expected_confidence: if tagged { "verified" } else { "unverified" },
    });
}
