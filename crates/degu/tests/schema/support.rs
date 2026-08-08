use serde_json::Value;
use std::path::PathBuf;

pub(super) use crate::clean_run::run as clean_pip_cache;
pub(super) use crate::common::isolated_degu as degu;
pub(super) use crate::pip_cache::seed as fake_pip_cache;

pub(super) const FINDING_KEYS: &[&str] = &[
    "age_days",
    "bytes_allocated",
    "bytes_apparent",
    "bytes_hardlinked",
    "confidence",
    "disposition",
    "ecosystem",
    "inodes",
    "kind",
    "ownership",
    "path",
    "rationale",
    "recovery",
    "skipped",
    "truncated",
];
pub(super) const FINDING_KEYS_WITH_HAZARD: &[&str] = &[
    "age_days",
    "bytes_allocated",
    "bytes_apparent",
    "bytes_hardlinked",
    "confidence",
    "disposition",
    "ecosystem",
    "hazard",
    "inodes",
    "kind",
    "ownership",
    "path",
    "rationale",
    "recovery",
    "skipped",
    "truncated",
];
pub(super) const SCAN_REPORT_KEYS: &[&str] = &["completeness", "findings", "runtime"];
pub(super) const SCAN_COMPLETENESS_KEYS: &[&str] = &["findings", "runtime"];
pub(super) const CLEAN_EXECUTION_KEYS: &[&str] =
    &["outcome", "path", "purged", "state", "trash_entry"];
pub(super) const CLEAN_REPORT_KEYS: &[&str] = &[
    "completeness",
    "excluded",
    "executed",
    "expiry",
    "omitted",
    "opt_in",
    "planned",
];
pub(super) const CLEAN_EXPIRY_KEYS: &[&str] =
    &["attempted", "failed", "planned", "purged", "retention_days"];
pub(super) const CLEAN_EXPIRY_FAILURE_KEYS: &[&str] = &["path", "reason"];
pub(super) const OP_RECORD_KEYS: &[&str] = &[
    "action",
    "bytes_allocated",
    "command",
    "inodes",
    "outcome",
    "path",
    "reclamation_id",
    "tool_version",
    "trash_entry",
    "ts",
];
pub(super) const SCAN_SUMMARY_ECOSYSTEM_KEYS: &[&str] = &[
    "bytes_allocated",
    "bytes_hardlinked",
    "ecosystem",
    "inodes",
    "lower_bound",
    "share",
];
pub(super) const SCAN_SUMMARY_REPORT_KEYS: &[&str] =
    &["ecosystems", "runtime", "total", "truncated"];
pub(super) const SCAN_SUMMARY_RUNTIME_KEYS: &[&str] = &["ecosystems", "total"];
pub(super) const SCAN_SUMMARY_TOTAL_KEYS: &[&str] = &[
    "bytes_allocated",
    "bytes_hardlinked",
    "inodes",
    "lower_bound",
];
pub(super) const RELOCATE_EXPORT_KEYS: &[&str] = &["current", "ecosystem", "value", "var"];
pub(super) const RELOCATE_NOT_RELOCATABLE_KEYS: &[&str] = &["ecosystem", "reason", "var"];
pub(super) const RELOCATE_REPORT_KEYS: &[&str] = &["exports", "not_relocatable", "target"];
pub(super) const RELOCATE_INIT_REPORT_KEYS: &[&str] =
    &["exports", "initialization", "not_relocatable", "target"];
pub(super) const RELOCATE_INITIALIZATION_KEYS: &[&str] = &["already_initialized", "initialized"];
pub(super) const TRASH_LIST_REPORT_KEYS: &[&str] = &["entries", "omitted"];
pub(super) const TRASH_LIST_ROW_KEYS: &[&str] = &[
    "age_days",
    "ambiguous",
    "bytes_allocated",
    "bytes_hardlinked",
    "entry",
    "interrupted_purge",
    "lower_bound",
    "original",
];
pub(super) const TRASH_PURGE_REPORT_KEYS: &[&str] = &["failed", "purged"];
pub(super) const OP_RECORD_KEYS_LEGACY: &[&str] = &[
    "action",
    "bytes_allocated",
    "command",
    "inodes",
    "outcome",
    "path",
    "tool_version",
    "trash_entry",
    "ts",
];
pub(super) const UNDO_REPORT_KEYS: &[&str] = &[
    "ambiguous",
    "failed",
    "gone",
    "log_failures",
    "reclamation_id",
    "restored",
];
pub(super) const UNDO_ENTRY_KEYS: &[&str] = &["path", "trash_entry"];

pub(super) fn fake_huggingface_cache(home: &tempfile::TempDir) -> PathBuf {
    let hf_home = home.path().join(".cache/huggingface");
    let repo = hf_home.join("hub/models--org--name");
    std::fs::create_dir_all(repo.join("snapshots/main")).unwrap();
    std::fs::write(repo.join("snapshots/main/model.bin"), [0u8; 8192]).unwrap();
    hf_home
}

pub(super) fn json_stdout(out: std::process::Output) -> Value {
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

pub(super) fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub(super) fn assert_keys(value: &Value, expected: &[&str]) {
    let object = value.as_object().unwrap();
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys.as_slice(), expected);
}

pub(super) fn assert_non_empty_array<'a>(value: &'a Value, label: &str) -> &'a [Value] {
    let array = value.as_array().unwrap();
    assert!(!array.is_empty(), "{label} fixture must be non-empty");
    array
}

fn assert_string_enum(value: &Value, variants: &[&str]) {
    let observed = value.as_str().unwrap();
    assert!(
        variants.contains(&observed),
        "unexpected enum spelling {observed:?}"
    );
}

pub(super) fn assert_finding(value: &Value) {
    if value.get("hazard").is_some() {
        assert_keys(value, FINDING_KEYS_WITH_HAZARD);
        assert_string_enum(&value["hazard"], &["active_use", "breaks_consumers"]);
    } else {
        assert_keys(value, FINDING_KEYS);
    }
    assert!(value["age_days"].is_number());
    assert_string_enum(&value["kind"], &finding_kind_variants());
    assert_string_enum(&value["confidence"], &["unverified", "verified"]);
    assert_string_enum(
        &value["ownership"],
        &["standalone", "tool_coordinated", "unknown"],
    );
    assert_recovery(&value["recovery"]);
    assert_disposition(&value["disposition"]);
}

fn assert_recovery(recovery: &Value) {
    assert_string_enum(&recovery["kind"], &["regenerable", "unknown", "user_asset"]);
    if recovery["kind"] == "regenerable" {
        assert_string_enum(&recovery["cost"], &["cheap", "costly"]);
    } else {
        assert!(recovery.get("cost").is_none());
    }
}

fn assert_disposition(disposition: &Value) {
    assert_string_enum(&disposition["mode"], &["eligible", "opt_in", "report_only"]);
    if disposition["mode"] == "eligible" {
        assert!(disposition.get("reason").is_none());
    } else {
        assert!(disposition["reason"].is_string());
    }
}

fn finding_kind_variants() -> [&'static str; 7] {
    [
        "build_artifact",
        "checkpoint",
        "container_cache",
        "environment",
        "model_cache",
        "other",
        "package_cache",
    ]
}

fn assert_oplog_outcome(value: &Value) {
    assert_string_enum(value, &["ok", "pending"]);
}

pub(super) fn assert_clean_outcome(value: &Value) {
    if value.is_string() {
        assert_string_enum(value, &["ok"]);
    } else {
        assert_keys(value, &["failed"]);
        assert_keys(&value["failed"], &["reason"]);
        assert!(value["failed"]["reason"].is_string());
    }
}

pub(super) fn assert_op_record(value: &Value, require_reclamation_id: bool) {
    if require_reclamation_id {
        assert_keys(value, OP_RECORD_KEYS);
        assert!(value["reclamation_id"].is_string());
    } else if value.get("reclamation_id").is_some() {
        assert_keys(value, OP_RECORD_KEYS);
    } else {
        assert_keys(value, OP_RECORD_KEYS_LEGACY);
    }
    assert_string_enum(&value["action"], &["purge", "restore", "trash"]);
    assert_oplog_outcome(&value["outcome"]);
}
