use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;
use degu_core::oplog::{ObjectIdentity, OpAction, OpOutcome, OpRecord};

const OPS_LOG_PATH: &str = "degu/ops.jsonl";
const OPS_LOG_MAX_BYTES: usize = 64 * 1024 * 1024;
const OPS_RECORD_MAX_BYTES: usize = 64 * 1024;

pub(super) struct OperationLog {
    path: PathBuf,
}

impl OperationLog {
    pub(super) fn new(ctx: &DetectCtx) -> Self {
        Self::at(ctx.xdg_state().join(OPS_LOG_PATH))
    }

    pub(super) fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn append(&self, record: &OpRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_string(record).map_err(std::io::Error::other)?;
        line.push('\n');
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        isolate_partial_tail(&mut file)?;
        file.write_all(line.as_bytes())
    }

    pub(super) fn read(&self) -> Result<Vec<OpRecord>> {
        read_records(&self.path)
    }
}

pub(super) fn isolate_partial_tail(file: &mut std::fs::File) -> std::io::Result<()> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub(super) struct TrashRecord<'a> {
    pub(super) finding: &'a Finding,
    pub(super) trash_entry: Option<PathBuf>,
    pub(super) reclamation_id: Option<String>,
    pub(super) expected_identity: Option<ObjectIdentity>,
    pub(super) destination_parent: Option<ObjectIdentity>,
    pub(super) outcome: OpOutcome,
}

pub(super) fn trash_record(request: TrashRecord<'_>) -> OpRecord {
    stamped_record(RecordFields {
        command: "clean".to_string(),
        action: OpAction::Trash,
        path: request.finding.path().to_path_buf(),
        bytes_allocated: request.finding.bytes_allocated(),
        inodes: request.finding.inodes(),
        trash_entry: request.trash_entry,
        reclamation_id: request.reclamation_id,
        expected_identity: request.expected_identity,
        destination_parent: request.destination_parent,
        outcome: request.outcome,
    })
}

pub(super) struct PurgeRecord<'a> {
    pub(super) command: &'a str,
    pub(super) entry: &'a Path,
    pub(super) reclamation_id: Option<&'a str>,
    pub(super) outcome: OpOutcome,
}

pub(super) fn purge_record(request: PurgeRecord<'_>) -> OpRecord {
    stamped_record(RecordFields {
        command: request.command.to_string(),
        action: OpAction::Purge,
        path: request.entry.to_path_buf(),
        bytes_allocated: 0,
        inodes: 0,
        trash_entry: None,
        reclamation_id: request.reclamation_id.map(str::to_string),
        expected_identity: None,
        destination_parent: None,
        outcome: request.outcome,
    })
}

pub(super) struct VerifiedRestoreRecord<'a> {
    pub(super) path: &'a Path,
    pub(super) trash_entry: &'a Path,
    pub(super) reclamation_id: &'a str,
    pub(super) outcome: OpOutcome,
}

/// Builds a reporting-only projection after the leased WAL has durably reached
/// `Restored`. The existing JSONL schema deliberately carries no transaction
/// identifier and cannot mint sealed-staging authority.
pub(super) fn verified_restore_record(request: VerifiedRestoreRecord<'_>) -> OpRecord {
    stamped_record(RecordFields {
        command: "undo".to_string(),
        action: OpAction::Restore,
        path: request.path.to_path_buf(),
        bytes_allocated: 0,
        inodes: 0,
        trash_entry: Some(request.trash_entry.to_path_buf()),
        reclamation_id: Some(request.reclamation_id.to_owned()),
        expected_identity: None,
        destination_parent: None,
        outcome: request.outcome,
    })
}

pub(super) struct RestoreRecord<'a> {
    pub(super) target: &'a OpRecord,
    pub(super) trash_entry: &'a Path,
    pub(super) reclamation_id: Option<String>,
    pub(super) expected_identity: Option<ObjectIdentity>,
    pub(super) outcome: OpOutcome,
}

pub(super) fn restore_record(request: RestoreRecord<'_>) -> OpRecord {
    stamped_record(RecordFields {
        command: "undo".to_string(),
        action: OpAction::Restore,
        path: request.target.path.clone(),
        bytes_allocated: request.target.bytes_allocated,
        inodes: request.target.inodes,
        trash_entry: Some(request.trash_entry.to_path_buf()),
        reclamation_id: request.reclamation_id,
        expected_identity: request.expected_identity,
        destination_parent: None,
        outcome: request.outcome,
    })
}

struct RecordFields {
    command: String,
    action: OpAction,
    path: PathBuf,
    bytes_allocated: u64,
    inodes: u64,
    trash_entry: Option<PathBuf>,
    reclamation_id: Option<String>,
    expected_identity: Option<ObjectIdentity>,
    destination_parent: Option<ObjectIdentity>,
    outcome: OpOutcome,
}

fn stamped_record(fields: RecordFields) -> OpRecord {
    OpRecord {
        ts: jiff::Timestamp::now().to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        command: fields.command,
        action: fields.action,
        path: fields.path,
        bytes_allocated: fields.bytes_allocated,
        inodes: fields.inodes,
        trash_entry: fields.trash_entry,
        reclamation_id: fields.reclamation_id,
        expected_identity: fields.expected_identity,
        destination_parent: fields.destination_parent,
        outcome: fields.outcome,
    }
}

fn read_records(log_path: &Path) -> Result<Vec<OpRecord>> {
    let mut records = Vec::new();
    let limits = super::records::StateReadLimits::new(OPS_LOG_MAX_BYTES, OPS_RECORD_MAX_BYTES);
    super::records::visit_bounded_state_lines(log_path, limits, |line_no, line| {
        let line = match std::str::from_utf8(line) {
            Ok(line) => line,
            Err(_) => {
                tracing::warn!(
                    target: "degu",
                    path = %log_path.display(),
                    line = line_no,
                    "skipping non-UTF-8 operation log line"
                );
                return Ok(());
            }
        };
        match serde_json::from_str::<OpRecord>(line) {
            Ok(record) => records.push(record),
            Err(error) => tracing::warn!(
                target: "degu",
                path = %log_path.display(),
                line = line_no,
                %error,
                "skipping corrupt operation log line"
            ),
        }
        Ok(())
    })?;
    Ok(records)
}

#[cfg(test)]
mod tests;
