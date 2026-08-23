//! Durable seal machinery: the write-ahead log, its store, and the
//! WAL-bound mutation executor.

pub mod executor;
pub mod store;
pub mod wal;
