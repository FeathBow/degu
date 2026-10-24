//! The room a WAL leaves for new staging, measured without a lease.
//!
//! A preview has to say whether a clean fits before it may change anything,
//! and taking the lease is a change: it repairs a torn tail and opens the way
//! to compaction. So the measure here works on bytes already read. Only the
//! committed frames count, exactly as a replay counts them: a tail that a crash
//! cut short, or that another process is writing now, is left out, and nothing
//! is truncated to leave it out. What the lease's compaction would take back is
//! measured from the same bytes, and nothing is compacted.

use super::*;

/// The room the committed frames of a WAL leave for a new staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalRoom {
    /// The most the WAL may hold.
    pub limit: u64,
    /// What its committed frames hold now.
    pub committed: u64,
    /// What its settled entries hold for the rest of their lives.
    pub reserved: u64,
    /// What a lease's compaction would take back from `committed` before a
    /// clean stages anything. The rewrite may still be abandoned, so a clean
    /// finds between [`Self::available`] and [`Self::available_once_compacted`].
    pub reclaimable: u64,
}

impl WalRoom {
    /// A WAL with nothing in it: a store that was never activated.
    pub fn empty() -> Self {
        Self {
            limit: MAX_WAL_LEN,
            committed: 0,
            reserved: 0,
            reclaimable: 0,
        }
    }

    /// What a new staging may use.
    pub fn available(self) -> u64 {
        self.limit
            .saturating_sub(self.committed)
            .saturating_sub(self.reserved)
    }

    /// What a new staging may use once a lease has compacted the WAL.
    pub fn available_once_compacted(self) -> u64 {
        self.limit
            .saturating_sub(self.committed.saturating_sub(self.reclaimable))
            .saturating_sub(self.reserved)
    }
}

/// Why the room could not be measured.
#[derive(Debug, thiserror::Error)]
pub enum WalRoomError {
    #[error("the seal WAL could not be read: {0}")]
    Replay(#[from] ReplayError),
    #[error("the seal WAL's replay could not be resumed for measuring: {0}")]
    Resume(#[from] AppendError),
    #[error("the seal WAL store does not hold the binding a lease requires: {0}")]
    Store(#[from] crate::seal::store::StoreError),
    #[error("the seal WAL could not be read: {0}")]
    Io(#[from] io::Error),
    /// A transaction is part way through, which blocks a new staging anyway:
    /// startup recovery has to move it on first, and the room depends on how.
    #[error("the seal WAL has a transaction recovery has not settled: {0}")]
    Unsettled(#[from] AllowanceError),
}

/// Committed frames held in memory, readable and never appended to.
struct CommittedFrames {
    bytes: Vec<u8>,
}

impl Write for CommittedFrames {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("a measured WAL is never appended to"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableWrite for CommittedFrames {
    fn sync_record(&mut self) -> io::Result<()> {
        Err(io::Error::other("a measured WAL is never appended to"))
    }

    fn prepare_append(&mut self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }

    fn read_committed(&self, start: u64, into: &mut [u8]) -> io::Result<()> {
        read_committed_from_memory(&self.bytes, start, into)
    }
}

/// Measures the room in WAL bytes already read.
pub(crate) fn room_in(mut bytes: Vec<u8>) -> Result<WalRoom, WalRoomError> {
    if bytes.len() as u64 > MAX_WAL_LEN {
        return Err(ReplayError::TooLarge { limit: MAX_WAL_LEN }.into());
    }
    let parsed = parse_frames(&bytes)?;
    let committed = parsed.committed_len;
    let frame_bytes = frame_bytes(&parsed.spans);
    let mut replay = replay_records(parsed.records, &bytes)?;
    replay.committed_len = committed as u64;
    replay.frame_bytes = frame_bytes;
    let reclaimable = compaction_reclaim(&replay, &compaction_dropped_transactions(&replay));
    bytes.truncate(committed);
    let wal = SealWal::resume(CommittedFrames { bytes }, replay)?;
    Ok(WalRoom {
        limit: wal.max_wal_len,
        committed: wal.committed_len,
        reserved: wal.reserved(None)?,
        reclaimable,
    })
}
