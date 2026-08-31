//! Durable seal machinery: the write-ahead log, its store, and the
//! WAL-bound mutation executor.

pub mod executor;
pub(crate) mod sidecar;
pub mod store;
pub mod wal;
