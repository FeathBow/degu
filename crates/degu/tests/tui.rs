//! The interactive review decides what to clean, so what it offers must be
//! what a clean could act on. These drive the real binary over a PTY.

#[path = "support/clean_run.rs"]
mod clean_run;
#[allow(dead_code)]
#[path = "support/mod.rs"]
mod common;
#[path = "support/pip_cache.rs"]
mod pip_cache;
#[path = "support/pip_fixture.rs"]
mod pip_fixture;
#[path = "support/pty.rs"]
mod pty;
#[path = "support/screen.rs"]
mod screen;

use pty::{PtyRun, run as run_pty, run_sealed as run_pty_sealed};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";
const CACHE_BYTES: usize = 2 * 1024 * 1024;
const ARTIFACT_BYTES: usize = 7 * 1024 * 1024;

/// A well-known cache degu cleans without being asked, plus a project whose
/// build artifacts are reachable only through a project root.
fn fixture(home: &Path) -> std::path::PathBuf {
    let cache = common::platform_cache_dir(home, "go-build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("blob.bin"), vec![0u8; CACHE_BYTES]).unwrap();

    let project = home.join("proj");
    std::fs::create_dir_all(project.join("target")).unwrap();
    std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(
        project.join("target/CACHEDIR.TAG"),
        format!("{CACHEDIR_TAG_SIGNATURE}\n"),
    )
    .unwrap();
    std::fs::write(project.join("target/.rustc_info.json"), "{}").unwrap();
    std::fs::write(project.join("target/debug.bin"), vec![0u8; ARTIFACT_BYTES]).unwrap();
    project
}

/// `docs/usage.md`: configured roots never authorize cleanup. A review that
/// offered one would turn read-only discovery into a cleanup authority the
/// reader never granted, and a keystroke would be enough to act on it.
#[test]
fn a_configured_root_is_not_offered_to_the_interactive_review() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[&project]);

    let stdout = review(home.path(), config.path(), "");

    assert!(
        stdout.contains("go-build"),
        "the well-known cache is still offered: {stdout}"
    );
    assert!(
        !stdout.contains("proj/target"),
        "a configured root reached the clean plan: {stdout}"
    );
    assert!(
        !stdout.contains(&project.display().to_string()),
        "a configured root was passed as a cleanup authority: {stdout}"
    );
}

/// The same project, named on the command line, is authorized exactly as it is
/// for `degu clean PATH`. Refusing it here would be a different defect.
#[test]
fn a_root_named_on_the_command_line_is_offered() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[]);

    let stdout = review(
        home.path(),
        config.path(),
        &format!(" {}", project.display()),
    );

    assert!(
        stdout.contains("proj/target"),
        "an explicit root was not offered: {stdout}"
    );
}

/// `degu scan` reports rather than cleans, so the configured root stays part of
/// its read-only discovery. The review's narrower authority must not have
/// narrowed the report too.
#[test]
fn a_configured_root_is_still_discovered_by_scan() {
    let home = tempfile::tempdir().unwrap();
    let project = fixture(home.path());
    let config = config_home_with_roots(&[&project]);
    let state = tempfile::tempdir().unwrap();

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho $env(DEGU_BIN) --color never scan
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("artifacts"),
        "scan stopped discovering the configured root: {stdout}"
    );
}

/// Open the review, preview the plan it would run, then decline to reopen it.
/// The preview is a dry run, so nothing is staged and the printed plan is the
/// exact set of locations the review offered.
fn review(home: &Path, config_home: &Path, args: &str) -> String {
    let state = tempfile::tempdir().unwrap();
    // A default-sized PTY renders nothing the interface can be recognized by,
    // so pin the geometry; then wait for the alternate screen rather than for
    // any drawn text, which arrives interleaved with escape sequences.
    let body = format!(
        r#"
spawn -noecho sh -c {{stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui{args}}}
expect -ex "\033\[?1049h"
sleep 1
send "p"
expect "Dry run"
expect "Proceed?"
send "n\r"
"#
    );
    let out = run_pty(PtyRun {
        body: &body,
        home,
        config_home,
        state_home: state.path(),
        extra_env: &[],
    });
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn config_home_with_roots(roots: &[&Path]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("degu")).unwrap();
    let entries = roots
        .iter()
        .map(|root| format!("{:?}", root.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.path().join("degu/config.toml"),
        format!("roots = [{entries}]\n"),
    )
    .unwrap();
    dir
}

/// The review draws its own screen, so `scan`'s output options have nothing to
/// act on. Accepting them would promise a rendering this command never makes.
#[test]
fn the_review_refuses_scan_output_options() {
    for flag in ["--json", "--details", "--summary"] {
        let out = common::isolated_degu()
            .args(["tui", flag])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{flag} was accepted");
        assert!(stderr.contains("unexpected argument"), "{flag}: {stderr}");
    }
}

/// The two halves are sequential, not atomic. A purge that does not happen —
/// here because its confirmation was declined — must stop the clean as well,
/// rather than staging more on the way out of a keystroke the reader declined.
#[test]
fn declining_the_purge_stops_the_clean_that_was_chosen_with_it() {
    // The staging fixture is the suite's own: a test that re-invents it can
    // fail for reasons that have nothing to do with what it is checking.
    let (home, state, _) = pip_fixture::create();
    clean_run::run(home.path(), state.path());
    let trash = state.path().join("degu/trash");
    let before = entry_names(&trash);
    assert_eq!(
        before.len(),
        1,
        "the staging fixture produced no entry, so the trash view has nothing to choose"
    );

    // Seed the same origin again so the clean half has work of its own; the
    // test is only meaningful if a clean would have done something.
    let kept = pip_cache::seed(home.path());
    assert!(kept.exists());

    let config = config_home_with_roots(&[]);
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "t"
sleep 1
send " "
sleep 1
send "c"
expect "Type 'purge'"
send "no\r"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a declined purge reported success");
    assert!(
        stderr.contains("the clean was not run either")
            || stdout.contains("the clean was not run either"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        entry_names(&trash),
        before,
        "the trash changed after a declined purge"
    );
    assert!(
        kept.exists(),
        "the clean ran even though the purge chosen with it did not"
    );
}

/// A purge and a clean chosen together run in that order, and the purge is done by
/// the time the clean asks. Declining the clean cancels the clean; it cannot also
/// unmake the deletion the same session reported one screen earlier, so the
/// cancellation must not say the session changed nothing.
#[test]
fn declining_the_clean_after_a_purge_does_not_deny_the_purge() {
    let (home, state, _) = pip_fixture::create();
    clean_run::run(home.path(), state.path());
    let trash = state.path().join("degu/trash");
    assert_eq!(
        entry_names(&trash).len(),
        1,
        "the staging fixture produced no entry"
    );

    // The origin refills, so the clean half has work the reader then declines.
    let kept = pip_cache::seed(home.path());
    assert!(kept.exists());

    let config = config_home_with_roots(&[]);
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "t"
sleep 1
send " "
sleep 1
send "c"
expect "Type 'purge'"
send "purge\r"
expect "Proceed?"
send "n\r"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        entry_names(&trash).is_empty(),
        "the confirmed purge did not run, so this says nothing about its report: {stdout}"
    );
    assert!(kept.exists(), "the declined clean ran anyway: {stdout}");
    assert!(
        stdout.contains("Canceled; nothing was cleaned."),
        "the cancellation does not say what was canceled: {stdout}"
    );
    assert!(
        !stdout.contains("no clean or purge changes"),
        "the cancellation denied a purge this session had already reported: {stdout}"
    );
}

/// Age every completed staging record but the last, so the next clean plans an expiry
/// that outlives whichever entry the reader purges. Only the reporting timestamp moves.
fn age_all_but_the_newest(state: &Path) {
    let log = state.join("degu/ops.jsonl");
    let mut rows = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let newest = rows
        .iter()
        .rposition(|row| row["action"] == "trash" && row["outcome"] == "ok")
        .expect("a completed staging record");
    for (index, row) in rows.iter_mut().enumerate() {
        if index != newest && row["action"] == "trash" && row["outcome"] == "ok" {
            row["ts"] = serde_json::json!("2000-01-01T00:00:00Z");
        }
    }
    std::fs::write(
        &log,
        rows.iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
}

/// A clean that would have expired something still cannot answer for a purge that
/// already happened. Saying nothing was permanently deleted is true of this clean and
/// false of the session, and the session is what the reader just watched.
#[test]
fn declining_a_clean_with_an_expiry_plan_does_not_deny_the_purge() {
    let (home, state, _) = pip_fixture::create();
    for _ in 0..3 {
        pip_cache::seed(home.path());
        clean_run::run(home.path(), state.path());
    }
    let trash = state.path().join("degu/trash");
    assert_eq!(
        entry_names(&trash).len(),
        3,
        "the fixture did not stage three entries"
    );
    age_all_but_the_newest(state.path());
    // The origin refills, so the clean the reader declines has work of its own.
    let kept = pip_cache::seed(home.path());

    let config = config_home_with_roots(&[]);
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "t"
sleep 1
send " "
sleep 1
send "c"
expect "Type 'purge'"
send "purge\r"
expect "Proceed?"
send "n\r"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        entry_names(&trash).len(),
        2,
        "the confirmed purge did not remove exactly one entry: {stdout}"
    );
    assert!(kept.exists(), "the declined clean ran anyway: {stdout}");
    assert!(
        stdout.contains("this clean deleted nothing permanently"),
        "the cancellation does not scope its claim to this clean: {stdout}"
    );
    assert!(
        !stdout.contains("nothing was permanently deleted"),
        "the cancellation denied a purge this session had already reported: {stdout}"
    );
}

fn entry_names(trash: &Path) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(trash) else {
        return Vec::new();
    };
    let mut names = dir
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// A sealed clean against one state directory, so the store the TUI is later asked
/// about is really activated. The ordinary clean helper enables the legacy seam,
/// which activates nothing.
fn sealed_clean(home: &Path, state: &Path, anchor: &Path) {
    let out = std::process::Command::new(assert_cmd::cargo::cargo_bin("degu"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("LOGNAME", home)
        .env("XDG_STATE_HOME", state)
        .env("DEGU_INTEGRATION_TEST_ANCHOR", anchor)
        .args(["clean", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        state.join("degu/sealed-staging/store.activation").exists(),
        "the clean activated no store, so the TUI has nothing to be wrong about"
    );
}

/// The CLI listing says when it is not looking at the account's activated store.
/// The staged screen is the same view through another door and has to say it too.
#[test]
fn the_staged_screen_says_when_it_is_not_the_account_it_looks_like() {
    let home = tempfile::tempdir().unwrap();
    let Some(_backend) = common::require_sealed_fixture_backend(home.path()) else {
        return;
    };
    let state = tempfile::tempdir_in(home.path()).unwrap();
    let elsewhere = tempfile::tempdir_in(home.path()).unwrap();
    pip_cache::seed(home.path());
    let anchor = state.path().join("degu-integration-activation-anchor");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
    common::make_tree_non_shared_writable(home.path()).unwrap();
    let anchor = std::fs::canonicalize(&anchor).unwrap();
    sealed_clean(home.path(), state.path(), &anchor);

    let config = config_home_with_roots(&[]);
    let out = run_pty_sealed(
        PtyRun {
            body: r#"
spawn -noecho sh -c {stty rows 40 columns 120; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "t"
sleep 1
send "q"
"#,
            home: home.path(),
            config_home: config.path(),
            state_home: elsewhere.path(),
            extra_env: &[],
        },
        &anchor,
    );

    let screen = String::from_utf8_lossy(&out.stdout);
    assert!(
        screen.contains("coverage"),
        "the staged screen claimed to be the whole account: {screen}"
    );
    assert!(
        screen.contains("doctor"),
        "the coverage panel did not say where to look: {screen}"
    );
}

/// The identifiers degu says are staged, which is the only authority on where its
/// trash roots are.
fn staged_entry_names(home: &Path, state: &Path) -> Vec<String> {
    let out = common::isolated_degu()
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .args(["trash", "list", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["omitted"], 0, "report: {report}");
    let mut names = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            Path::new(row["entry"].as_str().expect("entry path"))
                .file_name()
                .expect("entry name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// The last line of the field guide, which a reader has to reach to learn that
/// nothing moves from this screen. Taken from the constant so the test cannot drift
/// from the text it is about.
const HELP_LAST_LINE: &str = "Nothing moves until you leave this screen";

/// Drive the review at a fixed geometry and return the screen it left behind.
fn review_at(home: &Path, config_home: &Path, rows: u16, columns: u16, keys: &str) -> String {
    let state = tempfile::tempdir().unwrap();
    let body = format!(
        r#"
spawn -noecho sh -c {{stty rows {rows} columns {columns}; exec "$DEGU_BIN" --color never tui}}
expect -ex "\033\[?1049h"
sleep 1
{keys}
send "q"
"#
    );
    let out = run_pty(PtyRun {
        body: &body,
        home,
        config_home,
        state_home: state.path(),
        extra_env: &[],
    });
    screen::flattened(&out.stdout, usize::from(rows), usize::from(columns))
}

/// The field guide is longer than a standard terminal, so a reader who cannot
/// scroll it cannot read the part that says nothing moves from this screen.
#[test]
fn the_field_guide_can_be_read_to_its_end_on_a_standard_terminal() {
    let home = tempfile::tempdir().unwrap();
    fixture(home.path());
    let config = config_home_with_roots(&[]);

    let opened = review_at(home.path(), config.path(), 24, 80, "send \"?\"\nsleep 1\n");
    assert!(
        opened.contains("field guide"),
        "the help never opened: {opened}"
    );

    let scrolled = review_at(
        home.path(),
        config.path(),
        24,
        80,
        "send \"?\"\nsleep 1\nsend \"\\033\\[6~\"\nsleep 1\n",
    );
    assert!(
        scrolled.contains(HELP_LAST_LINE),
        "PgDn did not reach the end of the field guide: {scrolled}"
    );

    let to_end = review_at(
        home.path(),
        config.path(),
        24,
        80,
        "send \"?\"\nsleep 1\nsend \"\\033\\[F\"\nsleep 1\n",
    );
    assert!(
        to_end.contains(HELP_LAST_LINE),
        "End did not reach the end of the field guide: {to_end}"
    );
}

/// Two copies staged from one origin differ only by their entry identifier, and a
/// reader choosing one for permanent deletion has to be able to tell them apart. A
/// deep origin is the case that squeezes the row: the identifier is the shortest and
/// least redundant thing in it, so it must not be the first thing given up.
#[test]
fn two_staged_copies_of_one_origin_are_told_apart_on_a_standard_terminal() {
    let home = tempfile::tempdir().unwrap();
    // Inside the home, as every fixture here does: trash routing puts an entry in
    // the state trash only when the state directory is under the source mount's
    // owner anchor, and a sibling temporary directory is not.
    let state = tempfile::tempdir_in(home.path()).unwrap();
    let config = config_home_with_roots(&[]);
    // A project whose build artifacts sit behind a long path, so the origin alone
    // does not fit the row at 80 columns.
    let project = home
        .path()
        .join("workspaces/a-rather-long-project-directory-name");
    let artifacts = project.join("target");
    let root = project.display().to_string();
    for _ in 0..2 {
        std::fs::create_dir_all(&artifacts).unwrap();
        std::fs::write(
            artifacts.join("CACHEDIR.TAG"),
            format!("{CACHEDIR_TAG_SIGNATURE}\n"),
        )
        .unwrap();
        std::fs::write(artifacts.join(".rustc_info.json"), "{}").unwrap();
        std::fs::write(artifacts.join("debug.bin"), vec![0u8; ARTIFACT_BYTES]).unwrap();
        std::fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
        common::make_tree_non_shared_writable(home.path()).unwrap();
        let out = common::isolated_degu()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", state.path())
            .args(["clean", "--yes", &root])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!artifacts.exists(), "the clean staged nothing");
    }
    // Asked of degu rather than read off a path this test guessed: the trash root
    // is resolved per source mount, so a hardcoded one is right only by accident.
    let entries = staged_entry_names(home.path(), state.path());
    assert_eq!(entries.len(), 2, "the fixture staged {entries:?}");

    let body = r#"
spawn -noecho sh -c {stty rows 24 columns 80; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "t"
sleep 1
send "q"
"#;
    let out = run_pty(PtyRun {
        body,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });
    let screen = screen::flattened(&out.stdout, 24, 80);
    for entry in &entries {
        assert!(
            screen.contains(entry.as_str()),
            "the staged screen does not name {entry}, so its two copies read alike: {screen}"
        );
    }
}

/// Scan eligibility says a cache is cheap to regenerate. It says nothing about
/// whether sealed staging can move the tree, and `clean -n` on the same selection
/// refuses one with a hard link reaching outside it. The review offers `c` a keystroke
/// away, so a row it shows as ready and checked has to be one that could run.
#[test]
fn a_tree_staging_would_refuse_is_not_offered_as_ready_to_clean() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir_in(home.path()).unwrap();
    let config = config_home_with_roots(&[]);
    let cache = common::platform_cache_dir(home.path(), "pip");
    std::fs::create_dir_all(cache.join("http")).unwrap();
    std::fs::write(cache.join("http/blob"), vec![0u8; 4096]).unwrap();
    // The second link is outside the tree, which is what admission refuses.
    std::fs::hard_link(cache.join("http/blob"), home.path().join("outside-cache")).unwrap();
    common::make_tree_non_shared_writable(home.path()).unwrap();

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 24 columns 80; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "q"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });
    let lines = screen::render(&out.stdout, 24, 80);
    let row = lines
        .iter()
        .find(|line| line.contains("Caches/pip") || line.contains(".cache/pip"))
        .unwrap_or_else(|| panic!("the cache is not on the screen: {lines:#?}"));
    assert!(
        row.contains("Blocked"),
        "the row calls a tree staging would refuse ready: {row}"
    );
    assert!(
        !row.contains("Ready to clean"),
        "the row still claims the tree is ready: {row}"
    );
    assert!(
        !row.contains('✓'),
        "a tree staging would refuse starts in the plan: {row}"
    );
    let plan = lines
        .iter()
        .find(|line| line.contains("In the plan"))
        .cloned()
        .unwrap_or_default();
    assert!(
        plan.contains("0 locations") || plan.is_empty(),
        "the plan total counts a tree that cannot be staged: {plan}"
    );
    // The panel beside the table must not contradict it, and it is where the reason
    // fits: the table has one line per finding and no room for one.
    let screen = lines.join(" ");
    assert!(
        screen.contains("Blocked by sealed staging preflight"),
        "the details panel does not say what the row means: {screen}"
    );
    assert!(
        screen.contains("hard link"),
        "the review never says why the tree was refused: {screen}"
    );

    // Enter opens the full record, which must not say less than the row it came from.
    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 24 columns 80; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "\r"
sleep 1
send "q"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });
    let record = screen::render(&out.stdout, 24, 80).join(" ");
    assert!(
        record.contains("Blocked by sealed staging preflight") && record.contains("hard link"),
        "the full record dropped the refusal: {record}"
    );
    assert!(
        !record.contains("Ready to clean"),
        "the full record still calls the tree ready: {record}"
    );
}

/// One cache of each tier the screen distinguishes, plus a second Ready one: the
/// layout has to hold rows the reader can act on and rows they cannot.
fn caches_of_every_tier(home: &Path) {
    for (name, kilobytes) in [("pip", 400), ("go-build", 300), ("torch", 200), ("uv", 100)] {
        let cache = common::platform_cache_dir(home, name);
        std::fs::create_dir_all(cache.join("aa")).unwrap();
        std::fs::write(cache.join("aa/blob"), vec![0u8; kilobytes * 1024]).unwrap();
    }
    common::make_tree_non_shared_writable(home).unwrap();
}

/// The height of the findings panel, borders included, as drawn.
fn listing_height(lines: &[String]) -> usize {
    let top = lines
        .iter()
        .position(|line| line.contains("[2] Locations"))
        .unwrap_or_else(|| panic!("the findings panel is missing: {lines:#?}"));
    lines[top..]
        .iter()
        .position(|line| line.contains('╰'))
        .map(|end| end + 1)
        .unwrap_or_else(|| panic!("the findings panel does not close: {lines:#?}"))
}

/// A 24-row terminal is the common one, and the screen has to work there: the list is
/// this screen's subject, the staging trash is half of what it decides, and a panel
/// title that opens with a bare digit reads as a count of what the panel holds.
#[test]
fn the_findings_screen_works_on_a_standard_terminal() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir_in(home.path()).unwrap();
    caches_of_every_tier(home.path());
    let config = config_home_with_roots(&[]);

    let out = run_pty(PtyRun {
        body: r#"
spawn -noecho sh -c {stty rows 24 columns 80; exec "$DEGU_BIN" --color never tui}
expect -ex "\033\[?1049h"
sleep 1
send "q"
"#,
        home: home.path(),
        config_home: config.path(),
        state_home: state.path(),
        extra_env: &[],
    });
    let lines = screen::render(&out.stdout, 24, 80);
    let screen = lines.join(" ");

    // The staging trash is reachable from here, and `t` is the only way in.
    let footer = lines.last().cloned().unwrap_or_default();
    assert!(
        footer.contains("t trash"),
        "the footer does not offer the staging trash: {footer}"
    );

    // A title opening with a bare digit reads as a quantity, and the header above it
    // really does count locations, so the two must not look alike.
    assert!(
        screen.contains("[2] Locations"),
        "the findings panel title still reads as a count: {screen}"
    );
    assert!(
        !screen.contains("╭ 2 locations"),
        "the ambiguous title is still drawn: {screen}"
    );
    assert!(
        screen.contains("[3] Selected"),
        "the selected panel title still reads as a count: {screen}"
    );

    // The list is the screen's subject. With the share chart drawn it got eight of
    // twenty rows here, five of them usable; the chart's rows are most of what it was
    // short of, so a list that still fits in eight has not been given them.
    let height = listing_height(&lines);
    assert!(
        height >= 12,
        "the findings panel is {height} rows of a 24-row terminal: {screen}"
    );
    // And the selected item keeps its own context.
    assert!(
        screen.contains("Selected"),
        "the selected finding lost its panel: {screen}"
    );
}

/// The same screen at the widths a reader actually has. Narrow drops what it must and
/// keeps the way out; wide gets the chart back, because there the list can spare the
/// rows. What no width may do is stop saying which keys reach the rest of the screen.
#[test]
fn the_findings_screen_gives_up_the_least_useful_thing_first() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir_in(home.path()).unwrap();
    caches_of_every_tier(home.path());
    let config = config_home_with_roots(&[]);

    for (rows, columns, chart) in [(24u16, 60u16, false), (24, 80, false), (40, 120, true)] {
        let body = format!(
            r#"
spawn -noecho sh -c {{stty rows {rows} columns {columns}; exec "$DEGU_BIN" --color never tui}}
expect -ex "\033\[?1049h"
sleep 1
send "q"
"#
        );
        let out = run_pty(PtyRun {
            body: &body,
            home: home.path(),
            config_home: config.path(),
            state_home: state.path(),
            extra_env: &[],
        });
        let lines = screen::render(&out.stdout, usize::from(rows), usize::from(columns));
        let screen = lines.join(" ");
        let footer = lines.last().cloned().unwrap_or_default();
        // Two shapes, one job: the compact bar and the wide panels are both the
        // overview, so ask whether any of it is drawn rather than which one.
        let overview = ["share within report", "reported allocation", "report scope"]
            .iter()
            .any(|title| screen.contains(title));
        assert_eq!(
            overview, chart,
            "the overview at {columns}x{rows} is not where it belongs: {screen}"
        );
        assert!(
            footer.contains("q quit"),
            "the way out is gone at {columns}x{rows}: {footer}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Caches/") || line.contains(".cache/")),
            "no finding is visible at {columns}x{rows}: {screen}"
        );
    }
}
