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
use rustix::fs::{Mode, OFlags};

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
/// Three kinds, because the readers separate them: a parent that could not be
/// held is a race or an I/O fault, a certification refusal names a backend the
/// staging path will not use, and an assessment failure carries the tree policy
/// that withheld the answer.
pub(crate) enum ProbeFailure {
    ParentUnavailable(rustix::io::Errno),
    Certification(CertificationError),
    Assessment(HeldTreeAssessmentFailure),
}

/// Look at one already-canonical parent and the basename beneath it.
///
/// The caller canonicalizes: the preview resolves a path the reader typed, and
/// production already holds a canonical source, so resolving again here would
/// re-introduce a second answer to a question one of them has already settled.
pub(crate) fn probe(
    canonical_parent: &Path,
    basename: &OsStr,
) -> Result<HeldTreePolicyAssessmentOutcome, ProbeFailure> {
    let source_parent = rustix::fs::open(canonical_parent, OPEN_DIRECTORY, Mode::empty())
        .map_err(ProbeFailure::ParentUnavailable)?;
    let evidence = certify_held_fd(source_parent).map_err(ProbeFailure::Certification)?;
    assess_held_tree_policy_metadata(evidence, basename).map_err(ProbeFailure::Assessment)
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
        let refused = probe(&link, std::ffi::OsStr::new("cache"));
        assert!(
            matches!(refused, Err(ProbeFailure::ParentUnavailable(_))),
            "a symlinked parent was followed"
        );

        // The same directory reached directly gets past the open, so the refusal
        // above is the flag and not the fixture.
        let direct = probe(&real, std::ffi::OsStr::new("cache"));
        assert!(
            !matches!(direct, Err(ProbeFailure::ParentUnavailable(_))),
            "the real parent could not be held either"
        );
    }
}
