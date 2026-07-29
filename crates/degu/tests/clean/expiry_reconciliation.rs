use super::support::*;

#[test]
fn clean_expiry_reconciles_pending_records() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let fixture = seed_pending_entries(&home, &state);
    let out = run_clean(&home, &state, &["clean", "--yes"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("Purged 1 expired trash entry")
    );
    assert!(!fixture.staged.exists());
    assert!(fixture.ambiguous_entry.exists());
    assert!(fixture.ambiguous_original.exists());
}

struct PendingFixture {
    staged: std::path::PathBuf,
    ambiguous_entry: std::path::PathBuf,
    ambiguous_original: std::path::PathBuf,
}

fn seed_pending_entries(home: &tempfile::TempDir, state: &tempfile::TempDir) -> PendingFixture {
    let trash = private_trash_root(state);
    let staged = trash.join("0001-staged");
    std::fs::create_dir_all(&staged).unwrap();
    std::fs::write(staged.join("payload.bin"), [0u8; 512]).unwrap();
    let ambiguous_original = home.path().join(".cache/ambiguous");
    std::fs::create_dir_all(&ambiguous_original).unwrap();
    let ambiguous_entry = trash.join("0002-ambiguous");
    std::fs::create_dir_all(&ambiguous_entry).unwrap();
    let ts = expired_timestamp();
    write_oplog(
        state,
        &[
            pending_record(&ts, &home.path().join(".cache/staged"), &staged),
            pending_record(&ts, &ambiguous_original, &ambiguous_entry),
        ],
    );
    PendingFixture {
        staged,
        ambiguous_entry,
        ambiguous_original,
    }
}

fn expired_timestamp() -> String {
    let age = std::time::Duration::from_secs(8 * 24 * 60 * 60);
    jiff::Timestamp::try_from(std::time::SystemTime::now() - age)
        .unwrap()
        .to_string()
}

fn pending_record(ts: &str, path: &std::path::Path, entry: &std::path::Path) -> serde_json::Value {
    let identity = degu_core::oplog::ObjectIdentity::capture(entry).unwrap();
    serde_json::json!({
        "ts": ts,
        "tool_version": "0.0.1",
        "command": "clean",
        "action": "trash",
        "path": path,
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": entry,
        "reclamation_id": "interrupted-run",
        "expected_identity": identity,
        "outcome": "pending",
    })
}

#[test]
fn clean_expiry_prefers_new_pending_after_settled_entry_reuse() {
    let home = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let entry = seed_reused_pending_entry(&home, &state);
    let out = run_clean(&home, &state, &["clean", "--yes"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(entry.exists());
    assert!(
        !String::from_utf8(out.stdout)
            .unwrap()
            .contains("expired trash")
    );
}

fn seed_reused_pending_entry(
    home: &tempfile::TempDir,
    state: &tempfile::TempDir,
) -> std::path::PathBuf {
    let entry = private_trash_root(state).join("0001-cache");
    std::fs::create_dir_all(&entry).unwrap();
    let old = home.path().join(".cache/old");
    std::fs::create_dir_all(&old).unwrap();
    let new = home.path().join(".cache/new");
    write_oplog(
        state,
        &[
            reuse_record(ReuseRecord::old_trash(&old, &entry)),
            reuse_record(ReuseRecord::old_restore(&old, &entry)),
            reuse_record(ReuseRecord::new_pending(&new, &entry)),
        ],
    );
    entry
}

struct ReuseRecord<'a> {
    ts: String,
    action: &'static str,
    path: &'a std::path::Path,
    entry: &'a std::path::Path,
    reclamation_id: &'static str,
    outcome: &'static str,
}

impl<'a> ReuseRecord<'a> {
    fn old_trash(path: &'a std::path::Path, entry: &'a std::path::Path) -> Self {
        Self {
            ts: "2000-01-01T00:00:00Z".to_string(),
            action: "trash",
            path,
            entry,
            reclamation_id: "old",
            outcome: "ok",
        }
    }

    fn old_restore(path: &'a std::path::Path, entry: &'a std::path::Path) -> Self {
        Self {
            ts: "2000-01-01T00:00:01Z".to_string(),
            action: "restore",
            path,
            entry,
            reclamation_id: "old",
            outcome: "ok",
        }
    }

    fn new_pending(path: &'a std::path::Path, entry: &'a std::path::Path) -> Self {
        Self {
            ts: jiff::Timestamp::now().to_string(),
            action: "trash",
            path,
            entry,
            reclamation_id: "new",
            outcome: "pending",
        }
    }
}

fn reuse_record(spec: ReuseRecord<'_>) -> serde_json::Value {
    serde_json::json!({
        "ts": spec.ts,
        "tool_version": "0.0.1",
        "command": "test",
        "action": spec.action,
        "path": spec.path,
        "bytes_allocated": 0,
        "inodes": 0,
        "trash_entry": spec.entry,
        "reclamation_id": spec.reclamation_id,
        "outcome": spec.outcome,
    })
}
