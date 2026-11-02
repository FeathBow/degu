pub(crate) mod model;
mod platform;

use std::path::Path;

pub(crate) use model::QuotaSnapshot;
pub(crate) use platform::ProbeError;

/// Read one authoritative quota snapshot for an already-resolved path.
///
/// The user only: a clean brackets its work with this, and all it compares is
/// the user's usage.
pub(crate) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    platform::probe(path)
}

/// Everything the provider can say about limits on this path: the user, and the
/// group and project it also answers to. Answers `degu quota`. A subject that
/// cannot be read is reported as such, and only the user's failure fails it.
pub(crate) fn survey(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    platform::survey(path)
}
