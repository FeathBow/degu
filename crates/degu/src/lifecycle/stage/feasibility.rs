//! The Staging Feasibility Probe — one implementation, two readers.
//!
//! Stageability is assessed twice in a clean: once by the preview, which reports
//! it, and once by production staging, which acts on it. `CONTEXT.md` says the
//! probe shares the exact admission implementation with production staging, and
//! that is true only while this sequence exists once. It was previously written
//! out in `commands/clean/preview.rs` and again in `lifecycle/stage/production.rs`,
//! each with its own copy of the open flags — the safety contract for holding a
//! directory — and nothing but a comment keeping them in step.
//!
//! What the two readers do with the answer is their own business and stays
//! theirs: the preview classifies a failure into a kind and a category for the
//! report, production turns it into a refusal. Only the act of looking is shared.
//!
//! Advisory only. Nothing here mints mutation authority.

use std::ffi::OsStr;
use std::path::Path;

use degu_core::backend::{
    CertificationError, HeldTreeAssessmentFailure, HeldTreePolicyAssessmentOutcome,
    assess_held_tree_policy_metadata, certify_held_fd,
};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags};

/// How degu opens a directory it intends to hold.
///
/// `NOFOLLOW` is the load-bearing flag: the parent must be the directory that
/// was named, not whatever a symlink at that name points at by the time the
/// open runs.
pub(crate) const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Why the probe could not answer.
///
/// Four kinds, because the readers separate them: a parent that could not be
/// held is a race or an I/O fault, a certification refusal names a backend the
/// staging path will not use, a name the trash cannot hold is refused whatever
/// the tree holds, and an assessment failure carries the tree policy that
/// withheld the answer.
pub(crate) enum ProbeFailure {
    ParentUnavailable(rustix::io::Errno),
    Certification(CertificationError),
    NameTooLong,
    Assessment(HeldTreeAssessmentFailure),
}

/// Why a source the trash cannot hold under its name is refused.
pub(crate) const NAME_TOO_LONG: &str =
    "the source's name is too long for the trash once a reservation's sequence is put before it";

/// Look at one already-canonical parent and the basename beneath it, which a
/// reservation of `sequence` would name in the trash.
///
/// The caller canonicalizes: the preview resolves a path the reader typed, and
/// production already holds a canonical source, so resolving again here would
/// re-introduce a second answer to a question one of them has already settled.
/// Production counts the sequence the reservation will take; the preview reads
/// no trash and asks of the first, the shortest.
pub(crate) fn probe(
    canonical_parent: &Path,
    basename: &OsStr,
    sequence: u64,
) -> Result<HeldTreePolicyAssessmentOutcome, ProbeFailure> {
    let source_parent = rustix::fs::open(canonical_parent, OPEN_DIRECTORY, Mode::empty())
        .map_err(ProbeFailure::ParentUnavailable)?;
    let name_fits = trash_holds(&source_parent, basename, sequence);
    let evidence = certify_held_fd(source_parent).map_err(ProbeFailure::Certification)?;
    if !name_fits {
        return Err(ProbeFailure::NameTooLong);
    }
    assess_held_tree_policy_metadata(evidence, basename).map_err(ProbeFailure::Assessment)
}

/// Whether the trash can hold `basename` under the name a reservation of
/// `sequence` gives it.
///
/// The trash is on the source's mount, so the source parent can answer, and
/// the reservation's own first step, a no-follow lookup of that name, is how.
/// The filesystem refuses a name it could never hold by its own measure, which
/// on APFS is not a byte count. Any other answer is left to the reservation.
fn trash_holds(source_parent: &OwnedFd, basename: &OsStr, sequence: u64) -> bool {
    let name =
        super::production::destination_name(&super::production::claim_name(sequence), basename);
    !matches!(
        rustix::fs::statat(source_parent, &name, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NAMETOOLONG)
    )
}

/// The narrowest and the widest shape a staging of one finding can take.
///
/// Two lengths are only known once staging runs, so they are bounded. A
/// reservation's sequence is zero-padded to four digits and grows past them
/// only as far as a `u64` goes; and the reclamation id names the process that
/// cleans, which is not the one previewing, so its process id has at least
/// one digit and at most as many as one can have. Every other length is the
/// one staging will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShapeBounds {
    pub(crate) narrowest: degu_core::seal::wal::StagingShape,
    pub(crate) widest: degu_core::seal::wal::StagingShape,
}

/// The shapes a staging of `finding` will be sized by, worked out the way
/// staging works them out, from the same policy, but holding nothing staging
/// holds: no captured identity, no reservation, no transaction. The check
/// staging makes under the lease measures the transaction itself.
pub(crate) fn staging_shapes(
    ctx: &degu_core::ecosystem::DetectCtx,
    finding: &degu_core::finding::Finding,
) -> Result<ShapeBounds, String> {
    let source = super::policy::preview_source(finding)?;
    let lexical_trash =
        super::super::storage::prospective_trash_dir(ctx, source.canonical_source())?;
    let policy = super::policy::complete_with(
        source,
        lexical_trash,
        super::super::storage::prospective_directory,
    )?;
    let source_parent = policy
        .canonical_source
        .parent()
        .ok_or_else(|| "sealed staging source has no canonical parent".to_string())?;
    let source_parent_relative =
        super::policy::confined_relative(&policy.recovery_anchor, source_parent)?;
    let destination_parent_relative =
        super::policy::confined_relative(&policy.recovery_anchor, &policy.trash_root)?;
    let source_basename = policy
        .canonical_source
        .file_name()
        .ok_or_else(|| "sealed staging source has no basename".to_string())?;
    let anchor = degu_walk::resolve_trusted_directory(
        &policy.recovery_anchor,
        "sealed-staging mount-domain anchor",
    )
    .map_err(|error| format!("mount-domain anchor cannot be reopened safely: {error}"))?;
    let filesystem_id = degu_core::staging::forward_filesystem_id(&anchor)
        .map_err(|error| format!("failed to derive sealed staging filesystem identity: {error}"))?;
    let widest = degu_core::seal::wal::StagingShape {
        source_parent: source_parent_relative.as_os_str().len(),
        source_basename: source_basename.len(),
        destination_parent: destination_parent_relative.as_os_str().len(),
        destination_basename: super::production::RESERVATION_DIGITS_BOUND
            + 1
            + source_basename.len(),
        filesystem_id: filesystem_id.len(),
        reclamation_id: Some(super::reclamation_id_bound()),
        recovery_anchor: Some(policy.recovery_anchor.as_os_str().len()),
    };
    Ok(ShapeBounds {
        narrowest: degu_core::seal::wal::StagingShape {
            destination_basename: super::production::RESERVATION_WIDTH + 1 + source_basename.len(),
            reclamation_id: Some(super::reclamation_id_floor()),
            ..widest
        },
        widest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NOFOLLOW` is the load-bearing flag, and until the probe was one function
    /// there was nowhere to say so: both readers hand it an already-canonical
    /// parent, so the flag only earns its place in the window between resolving
    /// a path and opening it. That window cannot be opened from a test, but the
    /// flag's effect can be observed directly.
    #[test]
    fn a_parent_that_is_a_symlink_is_not_followed() {
        let root = tempfile::tempdir().expect("a directory");
        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("the real parent");
        std::fs::write(real.join("cache"), b"x").expect("a child");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("a symlinked parent");

        // Through the link the open must refuse rather than land on `real`.
        let refused = probe(&link, std::ffi::OsStr::new("cache"), 1);
        assert!(
            matches!(refused, Err(ProbeFailure::ParentUnavailable(_))),
            "a symlinked parent was followed"
        );

        // The same directory reached directly gets past the open, so the refusal
        // above is the flag and not the fixture.
        let direct = probe(&real, std::ffi::OsStr::new("cache"), 1);
        assert!(
            !matches!(direct, Err(ProbeFailure::ParentUnavailable(_))),
            "the real parent could not be held either"
        );
    }

    /// The filesystem measures a name, not this probe. APFS does not count
    /// bytes, so 250 three-byte characters fit behind a sequence that 251 do
    /// not, though both are far past 255 bytes.
    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_measures_names() {
        let root = tempfile::tempdir().expect("a directory");
        let parent = root.path().canonicalize().expect("a canonical parent");
        for (count, fits) in [(250, true), (251, false)] {
            let name = "\u{4e2d}".repeat(count);
            std::fs::create_dir(parent.join(&name)).expect("a source APFS holds");
            let refused = matches!(
                probe(&parent, OsStr::new(&name), 1),
                Err(ProbeFailure::NameTooLong)
            );
            assert_eq!(refused, !fits, "{count} characters");
        }
    }
}
