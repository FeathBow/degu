pub(crate) mod model;
mod platform;

use std::path::Path;

pub(crate) use model::QuotaSnapshot;
pub(crate) use platform::ProbeError;

/// Read one authoritative quota snapshot for an already-resolved path.
pub(crate) fn probe(path: &Path) -> Result<QuotaSnapshot, ProbeError> {
    platform::probe(path)
}
