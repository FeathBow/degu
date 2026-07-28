use std::path::{Path, PathBuf};

use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use degu_core::oplog::OpRecord;

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

    pub(super) fn read(&self) -> Result<Vec<OpRecord>> {
        read_records(&self.path)
    }
}

fn read_records(log_path: &Path) -> Result<Vec<OpRecord>> {
    let mut records = Vec::new();
    let limits = super::state_read::StateReadLimits::new(OPS_LOG_MAX_BYTES, OPS_RECORD_MAX_BYTES);
    super::state_read::visit_bounded_state_lines(log_path, limits, |line_no, line| {
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
