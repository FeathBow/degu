//! Keeps a fork out of the window where a freshly written file is execed.
//!
//! Execing a file this process has just written races every other fork in the
//! binary: a child forked in another thread inherits the still-open write
//! descriptor, and the exec then fails with ETXTBSY. The production sequence
//! is already careful — the writer is O_CLOEXEC, explicitly dropped, and
//! fsynced — but CLOEXEC only closes at the child's own exec, and the window
//! between another thread's fork and that exec is not ours to close.
//!
//! degu does not fork from several threads at once; this test binary does.
//! Writers take the gate exclusively, every other fork shares it.

use std::cell::Cell;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

static GATE: RwLock<()> = RwLock::new(());

thread_local! {
    /// Set while this thread holds the gate exclusively, so the exec it is
    /// about to make does not try to share a lock it already owns.
    static EXCLUSIVE: Cell<bool> = const { Cell::new(false) };
}

pub(crate) struct Exclusive(#[expect(dead_code)] RwLockWriteGuard<'static, ()>);

impl Drop for Exclusive {
    fn drop(&mut self) {
        EXCLUSIVE.with(|held| held.set(false));
    }
}

/// Hold across writing a file this process will exec, and across that exec.
pub(crate) fn exec_fresh_file() -> Exclusive {
    let guard = GATE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    EXCLUSIVE.with(|held| held.set(true));
    Exclusive(guard)
}

/// Hold across any other fork. Returns nothing when this thread is already the
/// exclusive holder, because the exec it is guarding is the one that took it.
pub(crate) fn forking() -> Option<RwLockReadGuard<'static, ()>> {
    if EXCLUSIVE.with(Cell::get) {
        return None;
    }
    Some(
        GATE.read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}
