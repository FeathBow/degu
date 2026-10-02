//! Bounded, descriptor-bound uv version probe.
//!
//! The command owner supplies the lexical path. Before executing any bytes from
//! it, this module rejects foreign-writable namespace components, foreign-owned
//! symlinks, unsafe file ownership/mode, extended ACLs, and non-native binaries.
//! The selected object is pinned by descriptor and copied once into a bounded,
//! private native-binary snapshot. The version probe and any later native action
//! execute that same snapshot, so pathname replacement cannot exchange the
//! probed executable for a different cleanup executable. Snapshot cleanup is
//! restricted to fixed names below exact held directory descriptors.

mod attributes;
mod error;
mod snapshot;
mod source;
mod version;

use crate::native::{
    HeldNativeExecutable, NativePreparationError, NativeRunOutcome, PreparedNativeAction,
    prepare_native_action_from_held, prepare_native_action_from_held_with_binding,
};
use degu_adapters::native::{
    NativeActionIdentity, NativeActionRequest, NativeEnvironmentRequest, NativeExecutableSelection,
    NativeProcessContract,
};
pub(crate) use error::UvExecutableProbeError;
use error::inspect;
use rustix::fd::OwnedFd;
use snapshot::snapshot_executable;
use source::{ExecutableIdentity, OpenedExecutable, executable_identity, open_selected_executable};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
pub(crate) use version::{AUDITED_UV_PRUNE_VERSION, UvVersion};
use version::{MINIMUM_UV_VERSION, UvVersionParseError, parse_uv_version};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_OUTPUT_LIMIT: usize = 128;

/// Unforgeable within the CLI crate: owns the exact object that answered the
/// bounded version probe. It is intentionally neither public nor cloneable.
pub(crate) struct ProbedUvExecutable {
    selection: NativeExecutableSelection,
    canonical_path: PathBuf,
    identity: ExecutableIdentity,
    /// Pins the originally selected object so its inode cannot be reused while
    /// path attachment is revalidated.
    source_executable: OwnedFd,
    /// Private byte-for-byte snapshot used by both probe and later action. A
    /// stable private path is required because macOS cannot exec `/dev/fd/N`.
    executable: HeldNativeExecutable,
    version: UvVersion,
}

impl ProbedUvExecutable {
    pub(crate) fn selection(&self) -> &NativeExecutableSelection {
        &self.selection
    }

    pub(crate) fn version(&self) -> UvVersion {
        self.version
    }

    /// Re-resolve the reviewed path and require it still to name the held
    /// object. The held object prevents inode reuse while this proof exists.
    pub(crate) fn revalidate_path(&self) -> Result<(), UvExecutableProbeError> {
        let source_stat = rustix::fs::fstat(&self.source_executable)
            .map_err(|source| inspect(self.selection.as_path(), io::Error::from(source)))?;
        let pinned_identity = executable_identity(&source_stat, &self.canonical_path)?;
        let current = open_selected_executable(&self.selection)?;
        if pinned_identity != self.identity
            || current.canonical_path != self.canonical_path
            || current.identity != self.identity
        {
            return Err(UvExecutableProbeError::PathChanged);
        }
        Ok(())
    }

    /// Consume the exact snapshot that answered the version probe into one
    /// runner action. No held descriptor or reusable split capability escapes
    /// this module.
    pub(crate) fn into_native_action_with_binding(
        self,
        request: NativeActionRequest,
        mutation_binding: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<PreparedNativeAction, NativePreparationError> {
        prepare_native_action_from_held_with_binding(request, self.executable, mutation_binding)
    }
}

pub(crate) fn probe_uv_executable(
    selection: NativeExecutableSelection,
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    probe_uv_executable_with(selection, &mut execute_version_probe)
}

/// The version is supplied by the caller, so path admission, snapshotting and
/// post-probe revalidation can be exercised without executing any bytes.
/// Production has exactly one supplier: the bounded probe of the snapshot.
fn probe_uv_executable_with(
    selection: NativeExecutableSelection,
    probe_version: &mut impl FnMut(
        &HeldNativeExecutable,
        &NativeExecutableSelection,
    ) -> Result<UvVersion, UvExecutableProbeError>,
) -> Result<ProbedUvExecutable, UvExecutableProbeError> {
    let opened = open_selected_executable(&selection)?;
    let executable = snapshot_executable(&opened)?;
    require_source_unchanged(&opened)?;
    let version = probe_version(&executable, &selection)?;
    let current = open_selected_executable(&selection)?;
    if current.canonical_path != opened.canonical_path || current.identity != opened.identity {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(ProbedUvExecutable {
        selection,
        canonical_path: opened.canonical_path,
        identity: opened.identity,
        source_executable: opened.executable,
        executable,
        version,
    })
}

fn execute_version_probe(
    executable: &HeldNativeExecutable,
    selection: &NativeExecutableSelection,
) -> Result<UvVersion, UvExecutableProbeError> {
    let probe_executable =
        executable
            .duplicate()
            .map_err(|source| UvExecutableProbeError::Inspect {
                path: selection.as_path().to_path_buf(),
                source,
            })?;
    let request = NativeActionRequest::new(
        NativeActionIdentity::new("uv", "version-probe")
            .expect("static uv probe identity is valid"),
        selection.clone(),
        [OsString::from("-V")],
        NativeEnvironmentRequest::clear(),
        NativeProcessContract::AuditedCooperativeProcessGroup,
        VERSION_PROBE_TIMEOUT,
        VERSION_OUTPUT_LIMIT,
        VERSION_OUTPUT_LIMIT,
        [],
    )
    .expect("static uv probe declaration is bounded");
    let report = prepare_native_action_from_held(request, probe_executable)?
        .execute(parse_uv_version)
        .result()?;
    parsed_probe_version(report.outcome())
}

fn require_source_unchanged(source: &OpenedExecutable) -> Result<(), UvExecutableProbeError> {
    let current = rustix::fs::fstat(&source.executable)
        .map_err(|error| inspect(&source.canonical_path, io::Error::from(error)))?;
    if executable_identity(&current, &source.canonical_path)? != source.identity {
        return Err(UvExecutableProbeError::PathChanged);
    }
    Ok(())
}

fn parsed_probe_version(
    outcome: &NativeRunOutcome<UvVersion, UvVersionParseError>,
) -> Result<UvVersion, UvExecutableProbeError> {
    let version = match outcome {
        NativeRunOutcome::Success(version) => *version,
        NativeRunOutcome::ExitFailure { code } => {
            return Err(UvExecutableProbeError::ExitFailure { code: *code });
        }
        NativeRunOutcome::Signal { signal } => {
            return Err(UvExecutableProbeError::Signal { signal: *signal });
        }
        NativeRunOutcome::Timeout => return Err(UvExecutableProbeError::Timeout),
        NativeRunOutcome::OutputTruncated => {
            return Err(UvExecutableProbeError::OutputTruncated);
        }
        NativeRunOutcome::OutputParseFailure(error) => {
            return Err(UvExecutableProbeError::InvalidOutput(*error));
        }
    };
    if version < MINIMUM_UV_VERSION {
        return Err(UvExecutableProbeError::VersionTooOld {
            found: version,
            minimum: MINIMUM_UV_VERSION,
        });
    }
    Ok(version)
}

#[cfg(test)]
use attributes::first_undroppable_xattr;
#[cfg(test)]
use snapshot::validate_snapshot_parent_chain;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
mod tests;
