use std::path::Path;

use crate::lifecycle::trash::Trash;
use anyhow::{Context, Result};
use degu_core::oplog::ObjectIdentity;

use crate::lifecycle::claims::{reservation_marker_metadata, validate_existing_claims_dir};
use crate::lifecycle::expiry::{TRASH_TTL, fallback_mtime_age};

pub(super) fn purge_expired_claims(root: &Path) -> Result<()> {
    let Some(claims) = validate_existing_claims_dir(root)
        .with_context(|| format!("failed to validate claims in {}", root.display()))?
    else {
        return Ok(());
    };
    let entries = std::fs::read_dir(&claims)
        .with_context(|| format!("failed to read {}", claims.display()))?;
    let trash = Trash::new(claims.clone());
    let now = jiff::Timestamp::now();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read {}", claims.display()))?;
        let Some(metadata) = reservation_marker_metadata(&entry)? else {
            continue;
        };
        let path = entry.path();
        let expected = ObjectIdentity::from_metadata(&metadata);
        if fallback_mtime_age(&metadata, now) >= TRASH_TTL {
            trash.purge_entry_verified(&path, expected)?;
        }
    }
    Ok(())
}
