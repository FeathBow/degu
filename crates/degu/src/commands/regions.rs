//! Incompleteness-provenance proof shared by the clean gate and scan's
//! suggested-command emission: can every recorded measurement-cause
//! incomplete region be proven disjoint from a selection of filesystem
//! locations? Deliberate protected prunes are never consulted — protection
//! is pre-descent, name-based, and one-directional, so hidden content can
//! never change what a selection matches. Both sides of every comparison
//! canonicalize the same way the --path filter does, and anything
//! unprovable is reported as a failure so callers stay fail-closed.

use degu_core::ecosystem::{IncompleteRegion, IncompleteRegions, RegionCause};
use std::path::{Path, PathBuf};

/// Containment between an incompletely scanned region and a selected
/// location, compared component-wise on canonical paths; [`Overlap::between`]
/// returns `None` when the two are disjoint.
#[derive(Clone, Copy)]
pub(crate) enum Overlap {
    /// The region is the selected location or one of its ancestors.
    ContainsSelection,
    /// The region lies below the selected location.
    InsideSelection,
}

impl Overlap {
    fn between(region: &Path, selected: &Path) -> Option<Self> {
        if selected.starts_with(region) {
            Some(Self::ContainsSelection)
        } else if region.starts_with(selected) {
            Some(Self::InsideSelection)
        } else {
            None
        }
    }

    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::ContainsSelection => "contains the selected location",
            Self::InsideSelection => "lies inside the selected location",
        }
    }
}

/// Why provenance fails to prove every incomplete region disjoint from every
/// selected location. Unknown provenance and unresolvable paths are failures
/// too: an unproven disjointness must never pass.
pub(crate) enum DisjointnessFailure {
    /// Incompleteness events whose location was never recorded (beyond the
    /// sample bound or without a usable path).
    Unsampled { count: u64 },
    /// Incompleteness reported without any recorded region. Unreachable
    /// while every incompleteness source records provenance, but a proof
    /// must not survive a provenance bug.
    NoRecordedRegion,
    UnresolvableSelection {
        path: PathBuf,
        source: std::io::Error,
    },
    UnresolvableRegion {
        region: PathBuf,
        source: std::io::Error,
    },
    /// `selected` is canonical; `region` keeps its recorded spelling.
    Overlap {
        region: PathBuf,
        selected: PathBuf,
        overlap: Overlap,
    },
}

/// Proves every recorded measurement-cause incomplete region disjoint from
/// every selected location, or reports the first reason no such proof
/// exists. Protected-cause regions are deliberate guard prunes and are not
/// consulted at all — not even canonicalized, so an unresolvable protected
/// path can neither refuse nor influence the proof. Unsampled events count
/// as measurement events (their cause is unknown and fails closed).
pub(crate) fn prove_disjoint(
    selected: &[&Path],
    regions: &IncompleteRegions,
) -> Result<(), DisjointnessFailure> {
    if regions.unsampled() > 0 {
        return Err(DisjointnessFailure::Unsampled {
            count: regions.unsampled(),
        });
    }
    let measurement = regions
        .sample()
        .iter()
        .filter(|region| region.cause() == RegionCause::Measurement)
        .map(IncompleteRegion::path)
        .collect::<Vec<_>>();
    if measurement.is_empty() {
        if regions.sample().is_empty() {
            return Err(DisjointnessFailure::NoRecordedRegion);
        }
        // Every recorded event is a deliberate protected prune: nothing the
        // scan failed to measure can overlap the selection.
        return Ok(());
    }
    let selected = canonical_selection(selected)?;
    for region in measurement {
        let canonical_region = std::fs::canonicalize(region).map_err(|source| {
            DisjointnessFailure::UnresolvableRegion {
                region: region.to_path_buf(),
                source,
            }
        })?;
        if let Some((path, overlap)) = first_overlap(&canonical_region, &selected) {
            return Err(DisjointnessFailure::Overlap {
                region: region.to_path_buf(),
                selected: path.clone(),
                overlap,
            });
        }
    }
    Ok(())
}

fn canonical_selection(selected: &[&Path]) -> Result<Vec<PathBuf>, DisjointnessFailure> {
    selected
        .iter()
        .map(|path| {
            std::fs::canonicalize(path).map_err(|source| {
                DisjointnessFailure::UnresolvableSelection {
                    path: path.to_path_buf(),
                    source,
                }
            })
        })
        .collect()
}

fn first_overlap<'a>(region: &Path, selected: &'a [PathBuf]) -> Option<(&'a PathBuf, Overlap)> {
    selected
        .iter()
        .find_map(|path| Overlap::between(region, path).map(|overlap| (path, overlap)))
}
