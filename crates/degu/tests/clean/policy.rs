use super::support::*;

#[test]
fn clean_only_checkpoints_is_valid_but_never_grants_cleanup_authority() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let root_temp = tempfile::tempdir().unwrap();
    let root = root_temp.path().canonicalize().unwrap();
    let checkpoints = root.join("run/checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    let first = checkpoints.join("epoch-1.pt");
    let second = checkpoints.join("epoch-2.pt");
    std::fs::write(&first, [0u8; 1024]).unwrap();
    std::fs::write(&second, [0u8; 1024]).unwrap();
    let out = degu()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", state.path())
        .args([
            "clean",
            "--only",
            "checkpoints",
            "--include-review",
            "--dry-run",
            "--json",
        ])
        .arg(&root)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(first.exists() && second.exists());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_not_planned_or_executed(&report, &checkpoints);
    assert!(
        report["excluded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["ecosystem"] == "checkpoints"
                    && finding["path"] == checkpoints.to_string_lossy().as_ref()
                    && finding["disposition"]["mode"] == "report_only"
                    && finding["recovery"]["kind"] == "user_asset"
            })
    );
}

fn assert_not_planned_or_executed(report: &serde_json::Value, path: &std::path::Path) {
    let expected = path.to_string_lossy();
    for section in ["planned", "executed"] {
        assert!(
            !report[section]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["path"] == expected.as_ref())
        );
    }
}

#[test]
fn clean_policy_evidence_respects_source_and_top_scope() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let hub = home.path().join(".cache/huggingface/hub");
    for (name, bytes) in [("models--org--large", 8192), ("models--org--small", 1024)] {
        let snapshot = hub.join(name).join("snapshots/main");
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::write(snapshot.join("model.bin"), vec![0_u8; bytes]).unwrap();
    }
    let conda = fake_conda_env(&home);

    let out = run_clean(
        &home,
        &state,
        &["clean", "--dry-run", "--only", "huggingface", "--top", "1"],
    );

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("models--org--large"), "{stdout}");
    assert!(!stdout.contains("models--org--small"), "{stdout}");
    assert!(!stdout.contains(&conda.display().to_string()), "{stdout}");

    let out = run_clean(
        &home,
        &state,
        &[
            "clean",
            "--dry-run",
            "--json",
            "--only",
            "huggingface",
            "--top",
            "1",
        ],
    );
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let excluded = report["excluded"].as_array().unwrap();
    for name in ["models--org--large", "models--org--small"] {
        let path = canonical_path_string(&hub.join(name));
        assert!(excluded.iter().any(|finding| finding["path"] == path));
    }
}

#[test]
fn clean_review_first_path_can_preview_the_same_scope() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let repo = home.path().join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
    std::fs::write(repo.join("snapshots/main/model.bin"), [0_u8; 8192]).unwrap();
    fake_conda_env(&home);
    let repo = repo.canonicalize().unwrap();
    let out = run_terminal_clean_path(&home, &state, &repo);

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("Needs review"), "{stdout}");
    assert!(
        stdout.contains("~/.cache/huggingface/hub/models--org--name"),
        "{stdout}"
    );
    assert!(!stdout.contains("myenv"), "{stdout}");
    assert!(
        stdout.contains(
            "degu clean --details --dry-run --include-review --path ~/.cache/huggingface/hub/models--org--name"
        ),
        "{stdout}"
    );
}

#[test]
fn clean_not_managed_path_does_not_offer_unrelated_review_authority() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let repo = home.path().join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
    std::fs::write(repo.join("snapshots/main/model.bin"), [0_u8; 8192]).unwrap();
    let conda = fake_conda_env(&home).canonicalize().unwrap();
    let out = run_terminal_clean_path(&home, &state, &conda);

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("Not managed"), "{stdout}");
    assert!(
        stdout.contains("degu never cleans these locations"),
        "{stdout}"
    );
    assert!(!stdout.contains("models--org--name"), "{stdout}");
    assert!(!stdout.contains("--include-review"), "{stdout}");
    assert!(!stdout.contains("Next:"), "{stdout}");
}
