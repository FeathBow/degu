use super::{assert_sgr_color, degu, parse_summary_sizes, strip_sgr};

struct DispositionFixture {
    home: tempfile::TempDir,
}

impl DispositionFixture {
    fn new() -> Self {
        let home = tempfile::Builder::new()
            .prefix("degu scan ")
            .tempdir()
            .unwrap();
        let pip = crate::common::platform_cache_dir(home.path(), "pip");
        std::fs::create_dir_all(&pip).unwrap();
        std::fs::write(pip.join("wheel.whl"), [0u8; 4 * 1024]).unwrap();
        let repo = home.path().join(".cache/huggingface/hub/models--org--name");
        std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
        std::fs::write(repo.join("snapshots/main/model.bin"), vec![0u8; 512 * 1024]).unwrap();
        let env = home.path().join("miniconda3/envs/myenv");
        std::fs::create_dir_all(env.join("conda-meta")).unwrap();
        std::fs::write(env.join("conda-meta/somepkg.json"), "{}").unwrap();
        std::fs::write(env.join("payload.bin"), vec![0u8; 8 * 1024 * 1024]).unwrap();
        Self { home }
    }
}

#[test]
fn scan_table_summary_buckets_findings_by_disposition() {
    let fixture = DispositionFixture::new();
    let out = degu()
        .env("HOME", fixture.home.path())
        .arg("scan")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_bucket_hierarchy(&stdout);
    assert_review_command(&stdout);
    assert_bucket_sizes(&stdout);
}

#[test]
fn scan_color_reinforces_each_action_state_without_changing_text() {
    let fixture = DispositionFixture::new();
    let plain = degu()
        .env("HOME", fixture.home.path())
        .args(["--color", "never", "scan"])
        .output()
        .unwrap();
    let colored = degu()
        .env("HOME", fixture.home.path())
        .args(["--color", "always", "scan"])
        .output()
        .unwrap();

    assert!(plain.status.success() && colored.status.success());
    let colored_text = String::from_utf8_lossy(&colored.stdout);
    assert_sgr_color(&colored_text, "Ready to clean", "38;5;10");
    // Standard yellow (palette 3): bright yellow (palette 11) is
    // near-invisible on light terminal themes.
    assert_sgr_color(&colored_text, "Needs review", "38;5;3");
    assert_sgr_color(&colored_text, "degu clean --details", "38;5;14");
    assert_label_has_no_color(&colored_text, "Not managed", "38;5;9");
    assert_eq!(strip_sgr(&colored.stdout), plain.stdout);
}

fn assert_label_has_no_color(output: &str, label: &str, color_code: &str) {
    let position = output
        .find(label)
        .unwrap_or_else(|| panic!("missing {label:?}: {output}"));
    let prefix = output[..position].rsplit("\x1b[0m").next().unwrap();
    assert!(
        !prefix.contains(color_code),
        "{label:?} unexpectedly uses {color_code:?}: {output:?}"
    );
}

fn assert_bucket_hierarchy(stdout: &str) {
    assert!(stdout.contains(" detected across 3 locations"), "{stdout}");
    assert!(
        stdout.contains("Ready to clean - 1 location - "),
        "{stdout}"
    );
    assert!(stdout.contains("Needs review - 1 location - "), "{stdout}");
    assert!(stdout.contains("Not managed - 1 location - "), "{stdout}");
    assert!(stdout.contains("costly to regenerate"), "{stdout}");
    assert!(stdout.contains("user asset"), "{stdout}");
    assert!(!stdout.contains(" cleanup "), "{stdout}");
    assert!(
        !stdout.contains("View-only findings are informational"),
        "{stdout}"
    );
    let sections = [
        "\nReady to clean - ",
        "\nNeeds review - ",
        "\nNot managed - ",
    ]
    .map(|heading| stdout.find(heading).unwrap());
    assert!(
        sections.windows(2).all(|pair| pair[0] < pair[1]),
        "{stdout}"
    );
}

// The review target sits under HOME with an unquoted-safe rest, so the
// suggested command abbreviates it to an expandable, unquoted ~ path.
fn assert_review_command(stdout: &str) {
    let review_command = "degu clean --details --dry-run --include-review --path ~/.cache/huggingface/hub/models--org--name";
    assert!(stdout.contains(review_command), "{stdout}");
    assert!(
        !stdout.contains("degu clean --include-review --path"),
        "{stdout}"
    );
}

fn assert_bucket_sizes(stdout: &str) {
    let (total, cleanable, review, view_only) = parse_summary_sizes(stdout);
    assert!((4.0 * 1024.0..128.0 * 1024.0).contains(&cleanable));
    assert!((512.0 * 1024.0..4.0 * 1024.0 * 1024.0).contains(&review));
    assert!(view_only >= 8.0 * 1024.0 * 1024.0);
    let sum = cleanable + review + view_only;
    assert!((total - sum).abs() <= total * 0.02, "{total} != {sum}");
    assert!(review < view_only);
}
