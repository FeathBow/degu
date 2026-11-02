//! Incompleteness-provenance proof shared by the clean gate and scan's
//! suggested-command emission: can every recorded measurement-cause
//! incomplete region be proven disjoint from a selection of filesystem
//! locations? Deliberate protected prunes are never consulted — protection
//! is pre-descent, name-based, and one-directional, so hidden content can
//! never change what a selection matches. Both sides of every comparison
//! canonicalize the same way the --path filter does, and compare directory
//! identities as well, because `canonicalize` leaves two attachments of one
//! directory as two paths. Anything unprovable is reported as a failure so
//! callers stay fail-closed.

use degu_core::ecosystem::{IncompleteRegion, IncompleteRegions, RegionCause};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// A location as the proof compares it: its canonical path, and the identity of the
/// location and each of its ancestors, the location first. A bind mount gives one
/// directory a second path, and the same `(device, inode)` under both.
struct Located {
    path: PathBuf,
    chain: Vec<(u64, u64)>,
}

impl Located {
    fn resolve(path: &Path) -> std::io::Result<Self> {
        let path = std::fs::canonicalize(path)?;
        let chain = path
            .ancestors()
            .map(|dir| std::fs::symlink_metadata(dir).map(|stat| (stat.dev(), stat.ino())))
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(Self { path, chain })
    }

    /// Whether `other` is this location or lies below it, under either spelling.
    fn holds(&self, other: &Self) -> bool {
        other.path.starts_with(&self.path)
            || self
                .chain
                .first()
                .is_some_and(|identity| other.chain.contains(identity))
    }
}

/// Containment between an incompletely scanned region and a selected
/// location, by canonical path or by directory identity; [`Overlap::between`]
/// returns `None` when the two are disjoint.
#[derive(Clone, Copy)]
pub(crate) enum Overlap {
    /// The region is the selected location or one of its ancestors.
    ContainsSelection,
    /// The region lies below the selected location.
    InsideSelection,
}

impl Overlap {
    fn between(region: &Located, selected: &Located) -> Option<Self> {
        if region.holds(selected) {
            Some(Self::ContainsSelection)
        } else if selected.holds(region) {
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
        let located =
            Located::resolve(region).map_err(|source| DisjointnessFailure::UnresolvableRegion {
                region: region.to_path_buf(),
                source,
            })?;
        if let Some((path, overlap)) = first_overlap(&located, &selected) {
            return Err(DisjointnessFailure::Overlap {
                region: region.to_path_buf(),
                selected: path.clone(),
                overlap,
            });
        }
    }
    Ok(())
}

fn canonical_selection(selected: &[&Path]) -> Result<Vec<Located>, DisjointnessFailure> {
    selected
        .iter()
        .map(|path| {
            Located::resolve(path).map_err(|source| DisjointnessFailure::UnresolvableSelection {
                path: path.to_path_buf(),
                source,
            })
        })
        .collect()
}

fn first_overlap<'a>(region: &Located, selected: &'a [Located]) -> Option<(&'a PathBuf, Overlap)> {
    selected.iter().find_map(|location| {
        Overlap::between(region, location).map(|overlap| (&location.path, overlap))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: (u64, u64) = (1, 2);
    const HOME: (u64, u64) = (1, 10);
    const CACHE: (u64, u64) = (1, 20);
    const PIP: (u64, u64) = (1, 30);
    const SUB: (u64, u64) = (1, 40);
    const OTHER: (u64, u64) = (1, 50);
    const MIRROR_PARENT: (u64, u64) = (1, 60);

    fn at(path: &str, chain: &[(u64, u64)]) -> Located {
        Located {
            path: PathBuf::from(path),
            chain: chain.to_vec(),
        }
    }

    fn selected_pip() -> Located {
        at("/home/u/.cache/pip", &[PIP, CACHE, HOME, ROOT])
    }

    // `~/.cache` bound at `/mirror`: paths that share no prefix, one directory.
    #[test]
    fn bound_parent_holds_selection() {
        let region = at("/mirror", &[CACHE, ROOT]);
        assert!(matches!(
            Overlap::between(&region, &selected_pip()),
            Some(Overlap::ContainsSelection)
        ));
    }

    #[test]
    fn bound_alias_holds_selection() {
        let region = at("/mirror/pip", &[PIP, CACHE, ROOT]);
        assert!(matches!(
            Overlap::between(&region, &selected_pip()),
            Some(Overlap::ContainsSelection)
        ));
    }

    #[test]
    fn bound_child_inside_selection() {
        let region = at("/mirror/pip/sub", &[SUB, PIP, CACHE, ROOT]);
        assert!(matches!(
            Overlap::between(&region, &selected_pip()),
            Some(Overlap::InsideSelection)
        ));
    }

    // Sharing an ancestor is what siblings do, and it is not an overlap.
    #[test]
    fn shared_ancestor_stays_disjoint() {
        let sibling = at("/home/u/.cache/uv", &[OTHER, CACHE, HOME, ROOT]);
        assert!(Overlap::between(&sibling, &selected_pip()).is_none());
        let elsewhere = at("/mirror/other", &[OTHER, MIRROR_PARENT, ROOT]);
        assert!(Overlap::between(&elsewhere, &selected_pip()).is_none());
    }

    #[test]
    fn chain_starts_at_location() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();

        let located = Located::resolve(&nested).unwrap();

        let stat = std::fs::metadata(&nested).unwrap();
        assert_eq!(located.chain[0], (stat.dev(), stat.ino()));
        let parent = std::fs::metadata(root.path().join("a")).unwrap();
        assert_eq!(located.chain[1], (parent.dev(), parent.ino()));
        let top = std::fs::metadata("/").unwrap();
        assert_eq!(located.chain.last(), Some(&(top.dev(), top.ino())));
    }

    /// A real bind mount, for the Linux container that can make one. Everywhere else
    /// the chains above stand in for it.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_bind_mount_refuses() {
        use degu_core::ecosystem::{IncompleteRegions, RegionCause};
        struct Unmount<'a>(&'a Path);
        impl Drop for Unmount<'_> {
            fn drop(&mut self) {
                let _ = std::process::Command::new("umount").arg(self.0).status();
            }
        }
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("cache");
        let selected = parent.join("pip");
        std::fs::create_dir_all(selected.join("sub")).unwrap();
        let mirror = root.path().join("mirror");
        std::fs::create_dir_all(&mirror).unwrap();
        let bound = std::process::Command::new("mount")
            .arg("--bind")
            .arg(&parent)
            .arg(&mirror)
            .stderr(std::process::Stdio::null())
            .status();
        if !bound.is_ok_and(|status| status.success()) {
            eprintln!("skipped: cannot bind-mount here");
            return;
        }
        let _unmount = Unmount(&mirror);
        for (region, relation) in [
            (mirror.clone(), "contains"),
            (mirror.join("pip"), "contains"),
            (mirror.join("pip/sub"), "inside"),
        ] {
            let mut regions = IncompleteRegions::default();
            regions.record(&region, RegionCause::Measurement);
            match prove_disjoint(&[selected.as_path()], &regions) {
                Err(DisjointnessFailure::Overlap { overlap, .. }) => {
                    assert!(overlap.description().contains(relation), "{region:?}");
                }
                _ => panic!("{region:?} is the selection under another path"),
            }
        }
    }
}
