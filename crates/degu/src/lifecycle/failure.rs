//! How a sealed failure is put to the reader.

use std::fmt::Write as _;

use degu_core::seal::wal::TransactionId;

/// The WAL transaction as the log spells it.
///
/// `TransactionId`'s `Debug` prints its bytes, which names nothing a reader can look
/// up, so nothing user-facing may use it.
pub(in crate::lifecycle) fn transaction_hex(transaction: TransactionId) -> String {
    let mut encoded = String::with_capacity(transaction.0.len() * 2);
    for byte in transaction.0 {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// The innermost thing that went wrong.
///
/// A sealed error's own `Display` restates the transaction and the stage that the
/// caller here has already named, and spells the transaction as its bytes. Reporting
/// the whole chain therefore says each fact twice, the second time in a form that
/// means nothing outside the WAL, and buries the one part that says what stopped —
/// which is the end of the chain.
pub(in crate::lifecycle) fn root_cause(error: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = error;
    while let Some(source) = cause.source() {
        cause = source;
    }
    cause.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_hex_is_fixed_width_and_adapter_local() {
        assert_eq!(
            transaction_hex(TransactionId([
                0x00, 0x01, 0x0f, 0x10, 0x2a, 0x7f, 0x80, 0xff, 0x55, 0xaa, 0x03, 0x30, 0x99, 0x09,
                0xd0, 0x0d,
            ])),
            "00010f102a7f80ff55aa03309909d00d"
        );
    }

    /// The reader is told what stopped, not the wrappers each layer added on the way
    /// out. A chain reported whole repeats what the caller already said.
    #[test]
    fn the_root_cause_is_the_end_of_the_chain() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer wraps {0}")]
        struct Outer(#[source] Middle);
        #[derive(Debug, thiserror::Error)]
        #[error("middle wraps {0}")]
        struct Middle(#[source] Inner);
        #[derive(Debug, thiserror::Error)]
        #[error("the destination is occupied")]
        struct Inner;

        assert_eq!(
            root_cause(&Outer(Middle(Inner))),
            "the destination is occupied"
        );
        // A chain of one is the same answer, and it is the loop's other edge.
        assert_eq!(root_cause(&Inner), "the destination is occupied");
    }
}
