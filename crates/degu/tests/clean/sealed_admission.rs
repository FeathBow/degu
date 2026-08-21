use super::support::*;
use assert_cmd::Command;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_TREE_DIRECTORIES: usize = 1_023;

#[test]
fn clean_tree_preview_assessment_does_not_activate_or_create_lifecycle_state() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    fixture.assert_preview_assessed();
}

#[test]
fn preview_blocks_1024_tree_directories_before_any_production_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    // The inventory counts its root. Root + 1,023 children is 1,024 tree
    // directories and would require 1,025 active recovery permissions once the
    // source-parent seal is included. Reject it before any lifecycle mutation.
    for index in 0..MAX_TREE_DIRECTORIES {
        let dir = fixture.cache.join(format!("dir-{index:04}"));
        std::fs::create_dir(&dir).unwrap();
        // Group-writable trees are deliberately demoted by classification, so
        // pin the fixture mode instead of inheriting the ambient umask.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(count_directories(&fixture.cache), 1_024);
    fixture.assert_preview_blocked("directory_limit_exceeded", "directory limit exceeded");
    fixture.assert_production_rejects("directory limit exceeded");
    assert_eq!(count_directories(&fixture.cache), 1_024);
    assert!(fixture.cache.join("wheel.whl").is_file());
}

#[test]
fn internal_hardlink_pair_previews_stages_and_fresh_process_undo_preserves_inode() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.cache.join("wheel.whl");
    let alias = fixture.cache.join("wheel-alias.whl");
    std::fs::hard_link(&original, &alias).unwrap();

    let preview = fixture.run(&["clean", "-n", "--json"]);
    assert_output_success(&preview);
    let report: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let preflight = &report["staging_preflight"][0];
    assert_eq!(preflight["status"], "tree_policy_assessed", "{report:#}");
    assert_eq!(preflight["requested_action"], "stage", "{report:#}");
    assert_eq!(preflight["contains_internal_hardlinks"], true);
    assert_eq!(
        preflight["regular_hard_links"]["topology"],
        "internal_complete"
    );
    assert_eq!(preflight["regular_hard_links"]["multi_link_groups"], 1);
    assert_eq!(preflight["regular_hard_links"]["linked_entries"], 2);
    assert_eq!(preflight["purge_admission"]["supported"], false);
    let human = fixture.run(&["clean", "-n"]);
    assert_output_success(&human);
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("staging and undo are supported"), "{human}");
    assert!(
        human.contains("later permanent purge is unsupported"),
        "{human}"
    );

    let clean = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&clean);
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(report["executed"][0]["state"], "staged", "{report:#}");
    let trash = PathBuf::from(report["executed"][0]["trash_entry"].as_str().unwrap());
    let first = std::fs::metadata(trash.join("wheel.whl")).unwrap();
    let second = std::fs::metadata(trash.join("wheel-alias.whl")).unwrap();
    assert_eq!(first.ino(), second.ino());
    assert_eq!(first.nlink(), 2);
    assert!(!fixture.cache.exists());

    // `run` starts a new CLI process and therefore exercises WAL reopen and
    // committed-tree rebind before exact undo.
    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    let first = std::fs::metadata(&original).unwrap();
    let second = std::fs::metadata(&alias).unwrap();
    assert_eq!(first.ino(), second.ino());
    assert_eq!(first.nlink(), 2);
    assert_eq!(second.nlink(), 2);
}

#[test]
fn internal_hardlink_purge_stages_full_tree_then_reports_unsupported_and_undoes() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.cache.join("wheel.whl");
    let alias = fixture.cache.join("wheel-alias.whl");
    std::fs::hard_link(&original, &alias).unwrap();

    let preview = fixture.run(&["clean", "-n", "--purge", "--json"]);
    assert_output_success(&preview);
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["staging_preflight"][0]["requested_action"], "purge");
    assert_eq!(
        preview["staging_preflight"][0]["purge_admission"]["supported"],
        false
    );
    let human = fixture.run(&["clean", "-n", "--purge"]);
    assert_output_success(&human);
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("Would stage"), "{human}");
    assert!(human.contains("not permanently delete"), "{human}");
    assert!(!human.contains("Would permanently delete 4"), "{human}");

    let clean = fixture.run(&[
        "clean",
        "--purge",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    let item = &report["executed"][0];
    assert_eq!(item["state"], "staged", "{report:#}");
    assert_eq!(item["purged"], false, "{report:#}");
    assert!(
        item["outcome"]["failed"]["reason"]
            .as_str()
            .unwrap()
            .contains("does not support a tree containing multi-link regular-file groups"),
        "{report:#}"
    );
    let trash = PathBuf::from(item["trash_entry"].as_str().unwrap());
    assert!(trash.join("wheel.whl").is_file());
    assert!(trash.join("wheel-alias.whl").is_file());
    assert_eq!(
        std::fs::metadata(trash.join("wheel.whl")).unwrap().nlink(),
        2
    );

    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    assert_eq!(
        std::fs::metadata(&original).unwrap().ino(),
        std::fs::metadata(&alias).unwrap().ino()
    );
    assert_eq!(std::fs::metadata(&original).unwrap().nlink(), 2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ordinary_regular_xattr_previews_stages_and_fresh_process_undo_preserves_value() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let file = fixture.cache.join("wheel.whl");
    set_ordinary_xattr(&file, b"proof-bound");

    let preview = fixture.run(&["clean", "-n", "--json"]);
    assert_output_success(&preview);
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let preflight = &preview["staging_preflight"][0];
    assert_eq!(preflight["status"], "tree_policy_assessed", "{preview:#}");
    assert_eq!(preflight["contains_ordinary_regular_xattrs"], true);
    assert_eq!(preflight["regular_xattrs"]["entries"], 1);
    assert_eq!(preflight["regular_xattrs"]["attributes"], 1);
    assert_eq!(preflight["regular_xattrs"]["value_bytes"], 11);
    assert_eq!(preflight["regular_xattrs"]["proof_schema"], 3);
    assert_eq!(preflight["purge_admission"]["supported"], false);

    let clean = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&clean);
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    let trash = PathBuf::from(report["executed"][0]["trash_entry"].as_str().unwrap());
    assert_eq!(
        read_ordinary_xattr(&trash.join("wheel.whl")),
        b"proof-bound"
    );

    let purge = fixture.run(&["trash", "purge", "--yes", "--json"]);
    assert!(!purge.status.success());
    let purge_report: serde_json::Value = serde_json::from_slice(&purge.stdout).unwrap();
    assert!(purge_report["purged"].as_array().unwrap().is_empty());
    assert_eq!(purge_report["failed"].as_array().unwrap().len(), 1);
    assert!(
        purge_report["failed"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("does not support a tree containing ordinary regular-file xattrs"),
        "{purge_report:#}"
    );
    assert_eq!(
        read_ordinary_xattr(&trash.join("wheel.whl")),
        b"proof-bound"
    );

    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    assert_eq!(read_ordinary_xattr(&file), b"proof-bound");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ordinary_regular_xattr_purge_is_gated_after_stage_and_remains_undoable() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let file = fixture.cache.join("wheel.whl");
    set_ordinary_xattr(&file, b"keep");

    let clean = fixture.run(&[
        "clean",
        "--purge",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert!(!clean.status.success());
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    let item = &report["executed"][0];
    assert_eq!(item["state"], "staged", "{report:#}");
    assert_eq!(item["purged"], false, "{report:#}");
    assert!(
        item["outcome"]["failed"]["reason"]
            .as_str()
            .unwrap()
            .contains("does not support a tree containing ordinary regular-file xattrs"),
        "{report:#}"
    );
    let trash = PathBuf::from(item["trash_entry"].as_str().unwrap());
    assert_eq!(read_ordinary_xattr(&trash.join("wheel.whl")), b"keep");

    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    assert_eq!(read_ordinary_xattr(&file), b"keep");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn xattr_only_human_purge_preview_does_not_promise_deletion() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let file = fixture.cache.join("wheel.whl");
    set_ordinary_xattr(&file, b"keep");

    let preview = fixture.run(&["clean", "-n", "--purge"]);
    assert_output_success(&preview);
    let preview = String::from_utf8(preview.stdout).unwrap();
    assert!(preview.contains("Would stage"), "{preview}");
    assert!(
        preview.contains(
            "not permanently delete it because sealed purge does not support proof-bound ordinary regular-file xattrs"
        ),
        "{preview}"
    );
    assert!(!preview.contains("multi-link"), "{preview}");

    let clean = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&clean);
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    let trash = PathBuf::from(report["executed"][0]["trash_entry"].as_str().unwrap());

    let purge = fixture.run(&["trash", "purge", "--yes"]);
    assert!(!purge.status.success());
    let stdout = String::from_utf8(purge.stdout).unwrap();
    assert!(
        stdout.contains("Purge plan: 1 reviewed trash entry will be considered"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "sealed entries with unsupported purge topology are retained and remain undoable"
        ),
        "{stdout}"
    );
    assert!(
        !stdout.contains("all 1 trash entry")
            && !stdout.contains("trash entry will be permanently deleted"),
        "{stdout}"
    );
    assert_eq!(read_ordinary_xattr(&trash.join("wheel.whl")), b"keep");
}

#[test]
fn trash_purge_retains_internal_hardlink_and_continues_legacy_entry() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.cache.join("wheel.whl");
    let alias = fixture.cache.join("wheel-alias.whl");
    std::fs::hard_link(&original, &alias).unwrap();
    let staged = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&staged);
    let staged: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    let retained = PathBuf::from(staged["executed"][0]["trash_entry"].as_str().unwrap());
    let retained_name = retained.file_name().unwrap().to_string_lossy();
    let legacy = retained
        .parent()
        .unwrap()
        .join(format!("{retained_name}-legacy-after"));
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(legacy.join("payload"), b"legacy").unwrap();
    assert!(
        retained < legacy,
        "hardlink entry must precede the unrelated entry in the real plan"
    );

    let purge = fixture.run(&["trash", "purge", "--yes", "--json"]);
    assert!(!purge.status.success());
    let report: serde_json::Value = serde_json::from_slice(&purge.stdout).unwrap();
    assert_eq!(report["purged"].as_array().unwrap().len(), 1, "{report:#}");
    assert!(
        report["purged"][0]
            .as_str()
            .unwrap()
            .ends_with(legacy.file_name().unwrap().to_str().unwrap())
    );
    assert_eq!(report["failed"].as_array().unwrap().len(), 1, "{report:#}");
    assert!(
        report["failed"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(retained.file_name().unwrap().to_str().unwrap())
    );
    let reason = report["failed"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("retained"), "{reason}");
    assert!(reason.contains("remains undoable"), "{reason}");
    assert!(
        reason.contains("permanent purge is unsupported"),
        "{reason}"
    );
    assert!(retained.is_dir());
    assert!(!legacy.exists(), "unrelated legacy entry was not purged");

    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    assert_eq!(
        std::fs::metadata(&original).unwrap().ino(),
        std::fs::metadata(&alias).unwrap().ino()
    );
}

#[test]
fn expiry_retains_middle_internal_hardlink_and_continues_legacy_entries() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let original = fixture.cache.join("wheel.whl");
    let alias = fixture.cache.join("wheel-alias.whl");
    std::fs::hard_link(&original, &alias).unwrap();
    let staged = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&staged);
    let staged: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    let retained = PathBuf::from(staged["executed"][0]["trash_entry"].as_str().unwrap());
    age_operation_log(fixture.state.path());
    let before = retained.parent().unwrap().join("0000-aaa-before");
    let after = retained.parent().unwrap().join("9999-zzz-after");
    for legacy in [&before, &after] {
        std::fs::create_dir(legacy).unwrap();
        std::fs::write(legacy.join("payload"), b"legacy").unwrap();
        append_aged_trash_record(fixture.state.path(), legacy);
    }
    assert!(
        before < retained && retained < after,
        "hardlink entry must be between the unrelated entries in the real plan"
    );
    let preview = fixture.run(&["clean", "--dry-run", "--json"]);
    assert_output_success(&preview);
    let preview_report: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(
        preview_report["expiry"]["planned"]
            .as_array()
            .unwrap()
            .len(),
        3,
        "preview: {preview_report:#}; oplog: {}",
        std::fs::read_to_string(fixture.state.path().join("degu/ops.jsonl")).unwrap()
    );

    let expiry = fixture.run(&["clean", "--yes", "--json"]);
    assert!(!expiry.status.success());
    let report: serde_json::Value = serde_json::from_slice(&expiry.stdout).unwrap();
    assert!(
        report["planned"].as_array().unwrap().is_empty(),
        "{report:#}"
    );
    let purged = report["expiry"]["purged"].as_array().unwrap();
    assert_eq!(purged.len(), 2, "{report:#}");
    for expected in [&before, &after] {
        assert!(purged.iter().any(|path| {
            path.as_str()
                .unwrap()
                .ends_with(expected.file_name().unwrap().to_str().unwrap())
        }));
    }
    assert_eq!(report["expiry"]["failed"].as_array().unwrap().len(), 1);
    assert!(
        report["expiry"]["failed"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(retained.file_name().unwrap().to_str().unwrap())
    );
    let reason = report["expiry"]["failed"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("retained"), "{reason}");
    assert!(reason.contains("remains undoable"), "{reason}");
    assert!(!before.exists());
    assert!(retained.is_dir());
    assert!(!after.exists());
    restore_retained_trash_path(fixture.state.path(), &retained);

    let undo = fixture.run(&["undo", "--json"]);
    assert_output_success(&undo);
    assert_eq!(
        std::fs::metadata(&original).unwrap().ino(),
        std::fs::metadata(&alias).unwrap().ino()
    );
}

#[test]
fn trash_purge_recovery_blocker_stops_later_legacy_entry() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let staged = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--path",
        fixture.cache.to_str().unwrap(),
    ]);
    assert_output_success(&staged);
    let staged: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    let blocked = PathBuf::from(staged["executed"][0]["trash_entry"].as_str().unwrap());
    std::fs::write(blocked.join("wheel.whl"), b"changed after sealing").unwrap();
    let blocked_name = blocked.file_name().unwrap().to_string_lossy();
    let legacy = blocked
        .parent()
        .unwrap()
        .join(format!("{blocked_name}-legacy-after"));
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(legacy.join("payload"), b"legacy").unwrap();
    assert!(blocked < legacy);

    let purge = fixture.run(&["trash", "purge", "--yes", "--json"]);
    assert!(!purge.status.success());
    let report: serde_json::Value = serde_json::from_slice(&purge.stdout).unwrap();
    assert!(
        report["purged"].as_array().unwrap().is_empty(),
        "{report:#}"
    );
    assert_eq!(report["failed"].as_array().unwrap().len(), 2, "{report:#}");
    let reasons = report["failed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["reason"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("RecoveryRequired")),
        "{report:#}"
    );
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("no later claim, deletion, or housekeeping")),
        "{report:#}"
    );
    assert!(blocked.is_dir());
    assert!(legacy.is_dir(), "recovery blocker did not stop later work");
}

fn restore_retained_trash_path(state: &Path, retained: &Path) {
    let path = state.join("degu/ops.jsonl");
    let restored = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
            if record["action"] == "trash"
                && record["trash_entry"]
                    .as_str()
                    .is_some_and(|entry| Path::new(entry).file_name() == retained.file_name())
            {
                record["trash_entry"] = serde_json::json!(retained);
            }
            serde_json::to_string(&record).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, format!("{restored}\n")).unwrap();
}

fn lifecycle_visible_path(path: &Path) -> PathBuf {
    path.strip_prefix("/private")
        .map(|relative| Path::new("/").join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn append_aged_trash_record(state: &Path, entry: &Path) {
    use std::io::Write;
    let identity = degu_core::oplog::ObjectIdentity::capture(entry).unwrap();
    let record = serde_json::json!({
        "ts": "2000-01-01T00:00:00Z",
        "tool_version": "0.0.0",
        "command": "clean",
        "action": "trash",
        "path": format!("/legacy/{}", entry.file_name().unwrap().to_string_lossy()),
        "bytes_allocated": 6,
        "inodes": 2,
        "trash_entry": lifecycle_visible_path(entry),
        "expected_identity": identity,
        "outcome": "ok",
    });
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(state.join("degu/ops.jsonl"))
            .unwrap(),
        "{record}"
    )
    .unwrap();
}

fn age_operation_log(state: &Path) {
    let path = state.join("degu/ops.jsonl");
    let aged = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
            record["ts"] = serde_json::json!("2000-01-01T00:00:00Z");
            if let Some(entry) = record["trash_entry"].as_str() {
                record["trash_entry"] = serde_json::json!(lifecycle_visible_path(Path::new(entry)));
            }
            serde_json::to_string(&record).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, format!("{aged}\n")).unwrap();
}

#[test]
fn preview_reports_external_or_unenumerated_hardlink_exactly() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let outside = fixture.home.path().join("outside-hardlink");
    std::fs::write(&outside, b"outside").unwrap();
    std::fs::hard_link(&outside, fixture.cache.join("external-alias")).unwrap();
    fixture.assert_preview_blocked(
        "external_or_unenumerated_hard_link",
        "external or unenumerated hard link encountered",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn preview_non_utf8_internal_alias_is_assessed_without_exposing_a_path() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let first_name = OsString::from_vec(vec![0xfe]);
    let second_name = OsString::from_vec(vec![0xff]);
    let first = fixture.cache.join(&first_name);
    let second = fixture.cache.join(&second_name);
    std::fs::write(&first, b"internal aliases").unwrap();
    std::fs::hard_link(&first, &second).unwrap();

    let output = fixture.run(&["clean", "-n", "--json"]);
    assert_output_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON output: {error}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let preflight = &report["staging_preflight"][0];
    assert_eq!(preflight["status"], "tree_policy_assessed", "{report:#}");
    assert_eq!(preflight["contains_internal_hardlinks"], true);
    assert_eq!(preflight["regular_hard_links"]["multi_link_groups"], 1);
    assert_eq!(preflight["regular_hard_links"]["linked_entries"], 2);
    assert!(preflight.get("relative_path").is_none());
    fixture.assert_no_activation_or_created_lifecycle_state();
    assert_eq!(std::fs::metadata(&first).unwrap().nlink(), 2);
}

#[test]
fn ordinary_full_scope_keeps_per_item_admission() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let rejected = fixture.home.path().join(".npm");
    std::fs::create_dir_all(&rejected).unwrap();
    let content = rejected.join("content");
    std::fs::write(&content, [0_u8; 4096]).unwrap();
    let external_peer = fixture.home.path().join(".npm-external-peer");
    std::fs::hard_link(&content, &external_peer).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();
    let eligible_path = std::fs::canonicalize(&fixture.cache).unwrap();
    let rejected_path = std::fs::canonicalize(&rejected).unwrap();

    let output = fixture.run(&["clean", "--yes", "--json"]);
    assert!(
        !output.status.success(),
        "mixed full-scope clean unexpectedly succeeded"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 2, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 2, "{report:#}");
    let staged = executed
        .iter()
        .find(|item| item["path"].as_str() == Some(eligible_path.to_string_lossy().as_ref()))
        .unwrap_or_else(|| panic!("missing staged pip result: {report:#}"));
    let failed = executed
        .iter()
        .find(|item| item["path"].as_str() == Some(rejected_path.to_string_lossy().as_ref()))
        .unwrap_or_else(|| panic!("missing rejected npm result: {report:#}"));
    assert_eq!(staged["state"], "staged", "{report:#}");
    assert_eq!(failed["state"], "stage_failed", "{report:#}");
    assert!(!fixture.cache.exists(), "admissible item was not staged");
    assert!(content.is_file(), "rejected item was mutated");
    assert!(external_peer.is_file(), "external peer was mutated");
    assert_activation_and_wal(&fixture.anchor, fixture.state.path());
    assert_eq!(
        visible_trash_entries(&fixture.state.path().join("degu/trash")).len(),
        1,
        "rejected item created a trash entry"
    );
}

#[test]
fn explicit_review_reaches_sealed_preflight_before_mutation() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let review = fixture
        .home
        .path()
        .join(".cache/huggingface/hub/models--org--name");
    std::fs::create_dir_all(review.join("snapshots/main")).unwrap();
    let model = review.join("snapshots/main/model.bin");
    std::fs::write(&model, [0_u8; 4096]).unwrap();
    let external_peer = review.parent().unwrap().join("model-external-peer.bin");
    std::fs::hard_link(&model, &external_peer).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();

    let output = fixture.run(&[
        "clean",
        "--yes",
        "--json",
        "--review",
        review.to_str().unwrap(),
    ]);
    assert_rejected(&output, "external or unenumerated hard link encountered");
    assert!(model.is_file());
    assert!(external_peer.is_file());
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(
        !fixture
            .state
            .path()
            .join("degu/sealed-staging/.claims")
            .exists()
    );
}

#[test]
fn explicit_path_batch_rejects_before_any_item_mutates() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let rejected = fixture.home.path().join(".npm");
    std::fs::create_dir_all(&rejected).unwrap();
    let content = rejected.join("content");
    std::fs::write(&content, [0_u8; 4096]).unwrap();
    let external_peer = fixture.home.path().join(".npm-external-peer");
    std::fs::hard_link(&content, &external_peer).unwrap();
    crate::common::make_tree_non_shared_writable(fixture.home.path()).unwrap();

    let eligible_arg = fixture.cache.to_str().unwrap();
    let rejected_arg = rejected.to_str().unwrap();
    let run = || {
        fixture.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            eligible_arg,
            "--path",
            rejected_arg,
        ])
    };

    let first = run();
    assert_atomic_batch_rejected_without_source_mutation(&first, &fixture.cache, &rejected);
    assert_activation_and_wal(&fixture.anchor, fixture.state.path());
    let store = fixture.state.path().join("degu/sealed-staging");
    let wal = store.join("seal.wal");
    let wal_len_after_startup = std::fs::metadata(&wal).unwrap().len();
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!store.join(".claims").exists());

    let second = run();
    assert_atomic_batch_rejected_without_source_mutation(&second, &fixture.cache, &rejected);
    assert_eq!(
        std::fs::metadata(&wal).unwrap().len(),
        wal_len_after_startup,
        "rejected explicit batch appended a transaction frame"
    );
    assert!(!fixture.state.path().join("degu/trash").exists());
    assert!(!store.join(".claims").exists());
    assert!(external_peer.is_file());
}

fn assert_atomic_batch_rejected_without_source_mutation(
    output: &std::process::Output,
    eligible: &Path,
    rejected: &Path,
) {
    assert!(
        !output.status.success(),
        "rejected batch unexpectedly succeeded"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON output: {error}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(report["planned"].as_array().unwrap().len(), 2, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 2, "{report:#}");
    let mut states = executed
        .iter()
        .map(|item| item["state"].as_str().unwrap())
        .collect::<Vec<_>>();
    states.sort_unstable();
    assert_eq!(states, ["not_attempted", "stage_failed"], "{report:#}");
    assert!(eligible.join("wheel.whl").is_file());
    assert!(rejected.join("content").is_file());
    assert_eq!(
        std::fs::metadata(rejected.join("content")).unwrap().nlink(),
        2
    );
}

struct Fixture {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    cache: PathBuf,
    anchor: PathBuf,
}

impl Fixture {
    fn new() -> Option<Self> {
        let home = tempfile::tempdir().unwrap();
        let backend = match certify_backend(home.path()) {
            Ok(backend) => backend,
            #[cfg(target_os = "linux")]
            Err(degu_core::backend::CertificationError::UnsupportedFilesystem) => {
                eprintln!(
                    "skipping sealed-admission characterization: fixture filesystem is not certified native ext4/XFS"
                );
                return None;
            }
            Err(reason) => {
                #[cfg(target_os = "macos")]
                panic!("macOS integration fixtures are expected to be on APFS: {reason:?}");
                #[cfg(not(target_os = "macos"))]
                panic!("native fixture certification failed unexpectedly: {reason:?}");
            }
        };
        #[cfg(target_os = "macos")]
        assert_eq!(backend, degu_core::backend::CertifiedLocalBackend::Apfs);

        let (cache, state) = fake_pip_cache(&home, ".cache/pip");
        assert_eq!(certify_backend(&cache).unwrap(), backend);
        assert_eq!(certify_backend(state.path()).unwrap(), backend);
        assert_eq!(
            std::fs::metadata(&cache).unwrap().dev(),
            std::fs::metadata(state.path()).unwrap().dev(),
            "source and state must have the same device identity; sealed production admission proves the mount binding"
        );
        let anchor = state.path().join("degu-integration-activation-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = std::fs::canonicalize(anchor).unwrap();
        Some(Self {
            home,
            state,
            cache,
            anchor,
        })
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin("degu"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("LOGNAME", test_config_home())
            .env("XDG_CONFIG_HOME", test_config_home())
            .env("XDG_STATE_HOME", self.state.path())
            .env("DEGU_INTEGRATION_TEST_ANCHOR", &self.anchor)
            // Intentionally omit DEGU_INTEGRATION_TEST_LEGACY_CLEAN.
            .args(args);
        command.output().unwrap()
    }

    fn assert_preview_assessed(&self) {
        let parent = self.cache.parent().unwrap();
        let parent_mode = std::fs::metadata(parent).unwrap().mode();
        self.assert_no_activation_or_created_lifecycle_state();
        let output = self.run(&["clean", "-n", "--json"]);
        assert_output_success(&output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["planned"].as_array().unwrap().len(), 1, "{report:#}");
        let preflight = report["staging_preflight"].as_array().unwrap();
        assert_eq!(preflight.len(), 1, "{report:#}");
        assert_eq!(preflight[0]["status"], "tree_policy_assessed");
        assert_eq!(preflight[0]["contains_internal_hardlinks"], false);
        assert_eq!(
            preflight[0]["pending_validation"],
            serde_json::json!({
                "source_parent_seal": "requires_execution",
                "regular_file_content_read_and_proof": "requires_execution",
                "runtime_revalidation": "requires_execution",
            })
        );
        assert!(preflight[0].get("kind").is_none());
        assert_eq!(std::fs::metadata(parent).unwrap().mode(), parent_mode);
        self.assert_no_activation_or_created_lifecycle_state();
    }

    fn assert_preview_blocked(&self, kind: &str, reason: &str) {
        let parent = self.cache.parent().unwrap();
        let parent_mode = std::fs::metadata(parent).unwrap().mode();
        self.assert_no_activation_or_created_lifecycle_state();

        let output = self.run(&["clean", "-n", "--json"]);
        assert_output_success(&output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let planned = report["planned"].as_array().unwrap();
        assert_eq!(
            planned.len(),
            1,
            "preview did not retain fixture: {report:#}"
        );
        assert_eq!(
            planned[0]["path"],
            std::fs::canonicalize(&self.cache)
                .unwrap()
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(planned[0]["disposition"]["mode"], "eligible");
        let preflight = report["staging_preflight"].as_array().unwrap();
        assert_eq!(preflight.len(), 1, "{report:#}");
        assert_eq!(preflight[0]["path"], planned[0]["path"]);
        assert_eq!(preflight[0]["status"], "blocked");
        assert_eq!(preflight[0]["kind"], kind);
        assert!(preflight[0]["category"].is_string());
        assert!(
            preflight[0]["reason"].as_str().unwrap().contains(reason),
            "{report:#}"
        );

        let human = self.run(&["clean", "-n"]);
        assert_output_success(&human);
        let stdout = String::from_utf8(human.stdout).unwrap();
        assert!(
            stdout.contains("Blocked by sealed staging preflight"),
            "{stdout}"
        );
        assert!(stdout.contains(reason), "{stdout}");
        assert!(!stdout.contains("Ready to clean"), "{stdout}");
        assert!(!stdout.contains("Would move"), "{stdout}");
        assert!(stdout.contains("pip"), "{stdout}");

        assert_eq!(std::fs::metadata(parent).unwrap().mode(), parent_mode);
        self.assert_no_activation_or_created_lifecycle_state();
        assert!(self.cache.is_dir());
    }

    // This is intentionally a mutation/activation assertion, not a claim that
    // the whole dry-run avoids lifecycle reads: expiry preview may inspect
    // existing operation and trash state.
    fn assert_no_activation_or_created_lifecycle_state(&self) {
        let degu_state = self.state.path().join("degu");
        assert!(!degu_state.exists(), "dry-run created XDG state");
        assert!(
            !degu_state.join("trash").exists(),
            "dry-run created trash state"
        );
        assert!(
            !degu_state.join("sealed-staging/seal.wal").exists(),
            "dry-run created or activated the sealed WAL"
        );
        for name in [
            "sealed-staging.authority",
            "sealed-staging.prepare",
            "sealed-staging.active",
        ] {
            assert!(!self.anchor.join(name).exists(), "dry-run created {name}");
        }
    }

    fn assert_production_rejects(&self, expected: &str) {
        let first = self.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            self.cache.to_str().unwrap(),
        ]);
        assert_rejected(&first, expected);
        assert!(self.cache.is_dir(), "rejected source was moved or deleted");
        assert_activation_and_wal(&self.anchor, self.state.path());
        let store = self.state.path().join("degu/sealed-staging");
        let wal = store.join("seal.wal");
        // Activation and the first CLI session's recovery may initialize or
        // advance store bookkeeping. Establish the no-mutation baseline only
        // after that recovery boundary; the next atomic preflight must not
        // advance it.
        let wal_len_before = std::fs::metadata(&wal).unwrap().len();
        assert!(!self.state.path().join("degu/trash").exists());
        assert!(!store.join(".claims").exists());

        // A new CLI session must reach the same data-only admission decision
        // without adding a transaction frame or creating staging destinations.
        let second = self.run(&[
            "clean",
            "--yes",
            "--json",
            "--path",
            self.cache.to_str().unwrap(),
        ]);
        assert_rejected(&second, expected);
        assert!(self.cache.is_dir());
        assert_eq!(std::fs::metadata(wal).unwrap().len(), wal_len_before);
        assert!(!self.state.path().join("degu/trash").exists());
    }
}

fn assert_rejected(output: &std::process::Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "rejected clean unexpectedly succeeded"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["planned"].as_array().unwrap().len(), 1, "{report:#}");
    let executed = report["executed"].as_array().unwrap();
    assert_eq!(executed.len(), 1, "{report:#}");
    assert_eq!(executed[0]["state"], "stage_failed");
    assert_eq!(executed[0]["purged"], false);
    assert!(executed[0]["trash_entry"].is_null());
    let reason = executed[0]["outcome"]["failed"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("sealed batch preflight rejected"),
        "{reason}"
    );
    assert!(reason.contains(expected), "{reason}");
    assert!(
        stderr.contains("one or more clean locations failed"),
        "{stderr}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_ordinary_xattr(path: &Path, value: &[u8]) {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).unwrap();
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"user.degu-proof-v3".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"com.apple.quarantine".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    assert_eq!(
        result,
        0,
        "failed to set ordinary xattr: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_ordinary_xattr(path: &Path) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).unwrap();
    #[cfg(target_os = "linux")]
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"user.degu-proof-v3".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    #[cfg(target_os = "macos")]
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"com.apple.quarantine".as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        )
    };
    assert!(size >= 0, "failed to size ordinary xattr");
    let mut value = vec![0_u8; size as usize];
    #[cfg(target_os = "linux")]
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"user.degu-proof-v3".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"com.apple.quarantine".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    assert_eq!(read, size, "failed to read ordinary xattr");
    value
}

fn count_directories(root: &Path) -> usize {
    1 + std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .count()
}
