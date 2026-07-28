mod cmake;
mod python;

use super::ArtifactEvidence;
use degu_core::ecosystem::DetectCtx;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum ArtifactClassification {
    Match(ArtifactEvidence),
    Miss,
    Incomplete,
    Truncated { incomplete: bool },
}

impl ArtifactClassification {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Match(_) | Self::Truncated { .. })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Probe {
    /// Verified evidence: the caller's evidence tier is granted (eligible for a
    /// build structure).
    Match,
    /// Weak evidence: identifies the directory but not its recovery cost or
    /// ownership; CLAIMS the root (traversal stops) without granting clean authority.
    ReportOnly,
    Miss,
    Incomplete,
    Truncated {
        incomplete: bool,
    },
}

pub(crate) fn classify(path: &Path, ctx: &DetectCtx) -> ArtifactClassification {
    if ctx.deadline_elapsed() {
        return ArtifactClassification::Truncated { incomplete: false };
    }
    let named = path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or(Probe::Miss, |name| named_artifact(path, name, ctx));
    let mut classification = merge_probe(
        ArtifactClassification::Miss,
        named,
        ArtifactEvidence::BuildStructure,
    );
    if classification.is_terminal() {
        return classification;
    }
    classification = merge_probe(
        classification,
        cmake::probe(path, ctx),
        ArtifactEvidence::BuildStructure,
    );
    if classification.is_terminal() {
        return classification;
    }
    merge_probe(
        classification,
        valid_cachedir_tag(path, ctx),
        ArtifactEvidence::CacheTag,
    )
}

fn merge_probe(
    previous: ArtifactClassification,
    probe: Probe,
    evidence: ArtifactEvidence,
) -> ArtifactClassification {
    match probe {
        Probe::Match => ArtifactClassification::Match(evidence),
        Probe::ReportOnly => ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure),
        Probe::Miss => previous,
        Probe::Incomplete => ArtifactClassification::Incomplete,
        Probe::Truncated { incomplete } => ArtifactClassification::Truncated {
            incomplete: incomplete || matches!(previous, ArtifactClassification::Incomplete),
        },
    }
}

fn named_artifact(path: &Path, name: &str, ctx: &DetectCtx) -> Probe {
    match name {
        "target" => cargo_target_root(path, ctx),
        "node_modules" => node_modules_root(path, ctx),
        "__pycache__" => python::cache_root(path, ctx),
        ".tox" => legacy_tox_root(path, ctx),
        _ => Probe::Miss,
    }
}

/// Clean authority requires ALL of: a sibling manifest parsing as a real
/// Cargo [package]/[workspace], a cargo-written build marker, AND a
/// signature-verified root CACHEDIR.TAG. A generic tag proves "cache
/// storage", never "regenerable cargo output", so it grants nothing alone.
/// Manifest+marker without the root tag is CLAIMED report-only, without
/// descent. A child tag under a cross-target directory never authorizes its
/// untagged parent; a tagged target without a manifest falls through to the
/// generic cache-tag tier (also report-only); a bare target name never matches.
fn cargo_target_root(path: &Path, ctx: &DetectCtx) -> Probe {
    const CARGO_BUILD_MARKERS: [&str; 3] = [
        ".rustc_info.json",
        "debug/.cargo-lock",
        "release/.cargo-lock",
    ];
    match cargo_manifest_probe(path, ctx) {
        Probe::Match => {}
        Probe::Miss => return Probe::Miss,
        Probe::Incomplete => return Probe::Incomplete,
        Probe::ReportOnly => unreachable!("the manifest probe never reports the weak tier"),
        truncated @ Probe::Truncated { .. } => return truncated,
    }
    // One cargo-written marker suffices (stop at the first); an unreadable marker
    // only matters when no definitive marker was found.
    let mut marker_incomplete = false;
    let mut has_marker = false;
    for marker in CARGO_BUILD_MARKERS {
        match file_probe(&path.join(marker), ctx) {
            Probe::Match => {
                has_marker = true;
                break;
            }
            Probe::Miss => {}
            Probe::Incomplete => marker_incomplete = true,
            Probe::ReportOnly => unreachable!("file_probe never reports the weak tier"),
            truncated @ Probe::Truncated { .. } => return truncated,
        }
    }
    if !has_marker {
        return if marker_incomplete {
            Probe::Incomplete
        } else {
            Probe::Miss
        };
    }
    match valid_cachedir_tag(path, ctx) {
        Probe::Match => Probe::Match,
        Probe::Miss => Probe::ReportOnly,
        Probe::Incomplete => Probe::Incomplete,
        Probe::ReportOnly => unreachable!("the tag probe never reports the weak tier"),
        truncated @ Probe::Truncated { .. } => truncated,
    }
}

/// Cap on the sibling Cargo.toml read: 1 MiB covers any real manifest while
/// bounding the allocation; an over-cap manifest is indeterminate, not a match.
const CARGO_MANIFEST_READ_CAP: usize = 1024 * 1024;

/// Matches only valid TOML declaring [package] or [workspace]: an empty file
/// parses as valid TOML, so bare parsing is insufficient. Non-regular,
/// unparseable, or over-cap reads never match.
fn cargo_manifest_probe(path: &Path, ctx: &DetectCtx) -> Probe {
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    let Some(parent) = path.parent() else {
        return Probe::Miss;
    };
    let manifest = parent.join("Cargo.toml");
    let read = match degu_walk::read_regular_capped(&manifest, CARGO_MANIFEST_READ_CAP) {
        // A non-regular Cargo.toml (FIFO, directory, socket) carries no manifest
        // and must not hang the scan; it is a plain Miss.
        Ok(Some(read)) => read,
        Ok(None) => return Probe::Miss,
        Err(err) if crate::is_missing_path_error(&err) => return Probe::Miss,
        Err(err) => {
            tracing::warn!(path = %manifest.display(), %err, "Cargo.toml read failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    if read.truncated {
        // A cut-off manifest could drop the table that discriminates it, so an
        // over-cap read is indeterminate rather than a match.
        tracing::warn!(path = %manifest.display(), "Cargo.toml exceeds the read limit");
        return Probe::Incomplete;
    }
    let Ok(text) = std::str::from_utf8(&read.bytes) else {
        return Probe::Miss;
    };
    match text.parse::<toml::Table>() {
        Ok(table) if table.contains_key("package") || table.contains_key("workspace") => {
            Probe::Match
        }
        Ok(_) | Err(_) => Probe::Miss,
    }
}

/// Caps on the sibling manifest and lockfile reads. A package.json is tiny; an
/// npm lockfile can reach several MiB in a monorepo. An over-cap read is
/// indeterminate, never a match.
const NODE_MANIFEST_READ_CAP: usize = 1024 * 1024;
const NODE_LOCKFILE_READ_CAP: usize = 16 * 1024 * 1024;

/// Clean authority requires a sibling package.json parsing as a JSON object AND
/// the AUTHORITATIVE npm lockfile whose known schema fields validate for its
/// version and that names this same project. npm treats npm-shrinkwrap.json, when present, as the
/// sole authority and ignores package-lock.json. A valid package.json without a
/// verifiable lockfile (pnpm/yarn have no safe parser here, the lock is malformed,
/// or its version is unknown) is CLAIMED report-only, never cleaned. No
/// package.json means this is not an npm project at all.
fn node_modules_root(path: &Path, ctx: &DetectCtx) -> Probe {
    let Some(parent) = path.parent() else {
        return Probe::Miss;
    };
    let manifest = match read_json_object(&parent.join("package.json"), NODE_MANIFEST_READ_CAP, ctx)
    {
        Ok(manifest) => manifest,
        Err(probe) => return probe,
    };
    // A manifest whose schema is wrong is a recognizable project but an untrusted
    // one, so it is claimed report-only rather than granting a delete.
    if !valid_package_manifest(&manifest) {
        return Probe::ReportOnly;
    }
    // Presence -- not validity -- selects the authority, so a broken shrinkwrap
    // fails closed here instead of deferring to package-lock.
    let shrinkwrap = parent.join("npm-shrinkwrap.json");
    let authority = match marker_present(&shrinkwrap, ctx) {
        Ok(true) => shrinkwrap,
        Ok(false) => parent.join("package-lock.json"),
        Err(probe) => return probe,
    };
    match npm_lockfile_marker(&authority, &manifest, ctx) {
        Probe::Match => Probe::Match,
        Probe::Miss => Probe::ReportOnly,
        Probe::Incomplete => Probe::Incomplete,
        truncated @ Probe::Truncated { .. } => truncated,
        Probe::ReportOnly => unreachable!("npm_lockfile_marker never reports the weak tier"),
    }
}

/// Existence of a directory entry, without following or reading it. A lookup
/// error other than "missing" fails closed, so it cannot mask a shrinkwrap.
fn marker_present(path: &Path, ctx: &DetectCtx) -> Result<bool, Probe> {
    if ctx.deadline_elapsed() {
        return Err(Probe::Truncated { incomplete: false });
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if crate::is_missing_path_error(&err) => Ok(false),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "npm lockfile presence probe failed");
            Err(Probe::Incomplete)
        }
    }
}

/// Matches only a real npm lockfile that describes THIS project: a supported
/// integer lockfileVersion (1, 2, or 3), the version-appropriate dependency graph
/// (`dependencies` for v1, `packages` with a `""` root for v2/v3) whose entries
/// are objects, and a root name consistent with package.json. Any other JSON
/// object -- unknown version, mismatched graph, non-descriptor entries, or a
/// lockfile for a different project -- is a Miss, granting nothing.
fn npm_lockfile_marker(
    path: &Path,
    manifest: &serde_json::Map<String, serde_json::Value>,
    ctx: &DetectCtx,
) -> Probe {
    let lock = match read_json_object(path, NODE_LOCKFILE_READ_CAP, ctx) {
        Ok(lock) => lock,
        Err(probe) => return probe,
    };
    if valid_npm_lockfile(&lock, manifest) {
        Probe::Match
    } else {
        Probe::Miss
    }
}

fn valid_npm_lockfile(
    lock: &serde_json::Map<String, serde_json::Value>,
    manifest: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    match lock
        .get("lockfileVersion")
        .and_then(serde_json::Value::as_u64)
    {
        // v1's identity/flags are at the top level; v2/v3's identity is at
        // packages[""] and is checked together with its graph.
        Some(1) => valid_v1_root(lock) && valid_v1_graph(lock) && identity_agrees(lock, manifest),
        Some(2 | 3) => valid_v2_v3_graph(lock, manifest),
        _ => false,
    }
}

/// The v1 lockfile's own top-level object: identity strings plus the boolean
/// `requires` flag -- a plain `true`, unlike the name -> spec map an entry carries.
fn valid_v1_root(lock: &serde_json::Map<String, serde_json::Value>) -> bool {
    descriptor_fields_well_typed(lock)
        && field_absent_or(lock, "requires", serde_json::Value::is_boolean)
}

fn valid_v1_graph(lock: &serde_json::Map<String, serde_json::Value>) -> bool {
    lock.get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|deps| deps.values().all(is_v1_descriptor))
}

/// v1 nests the tree: an entry's own `dependencies` are more descriptors,
/// validated recursively (serde_json's depth limit bounds the recursion).
fn is_v1_descriptor(entry: &serde_json::Value) -> bool {
    entry.as_object().is_some_and(|descriptor| {
        descriptor_fields_well_typed(descriptor)
            && descriptor
                .get("version")
                .and_then(serde_json::Value::as_str)
                .is_some()
            && string_valued_map(descriptor, "requires")
            && nested_v1_deps_well_typed(descriptor)
    })
}

fn nested_v1_deps_well_typed(descriptor: &serde_json::Map<String, serde_json::Value>) -> bool {
    match descriptor.get("dependencies") {
        Some(nested) => nested
            .as_object()
            .is_some_and(|deps| deps.values().all(is_v1_descriptor)),
        None => true,
    }
}

fn valid_v2_v3_graph(
    lock: &serde_json::Map<String, serde_json::Value>,
    manifest: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let Some(packages) = lock.get("packages").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let Some(root) = packages.get("").and_then(serde_json::Value::as_object) else {
        return false;
    };
    if !v2_v3_descriptor_well_typed(root) || !identity_agrees(root, manifest) {
        return false;
    }
    packages.iter().all(|(install_path, entry)| {
        install_path.is_empty()
            || entry.as_object().is_some_and(|descriptor| {
                v2_v3_descriptor_well_typed(descriptor) && is_installed_descriptor(descriptor)
            })
    })
}

fn v2_v3_descriptor_well_typed(descriptor: &serde_json::Map<String, serde_json::Value>) -> bool {
    descriptor_fields_well_typed(descriptor)
        && string_valued_map(descriptor, "dependencies")
        && string_valued_map(descriptor, "optionalDependencies")
        && string_valued_map(descriptor, "peerDependencies")
}

/// Either an installed package (`version`) or a workspace link (`link: true`
/// with `resolved`).
fn is_installed_descriptor(descriptor: &serde_json::Map<String, serde_json::Value>) -> bool {
    if descriptor.get("link").and_then(serde_json::Value::as_bool) == Some(true) {
        descriptor
            .get("resolved")
            .and_then(serde_json::Value::as_str)
            .is_some()
    } else {
        descriptor
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_some()
    }
}

/// The npm lock descriptor fields with a single fixed JSON type. Value-typed
/// maps (`dependencies` etc.) and the `version`/`link` requirements are checked
/// by the version-specific callers, not here.
fn descriptor_fields_well_typed(descriptor: &serde_json::Map<String, serde_json::Value>) -> bool {
    field_absent_or(descriptor, "name", serde_json::Value::is_string)
        && field_absent_or(descriptor, "version", serde_json::Value::is_string)
        && field_absent_or(descriptor, "resolved", serde_json::Value::is_string)
        && field_absent_or(descriptor, "integrity", serde_json::Value::is_string)
        && field_absent_or(descriptor, "link", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "dev", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "optional", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "devOptional", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "inBundle", serde_json::Value::is_boolean)
        && field_absent_or(
            descriptor,
            "hasInstallScript",
            serde_json::Value::is_boolean,
        )
        && field_absent_or(descriptor, "hasShrinkwrap", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "bundled", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "peer", serde_json::Value::is_boolean)
        && field_absent_or(descriptor, "extraneous", serde_json::Value::is_boolean)
        && string_valued_map(descriptor, "engines")
        && string_array(descriptor, "os")
        && string_array(descriptor, "cpu")
        && string_array(descriptor, "libc")
}

/// A malformed package.json cannot corroborate a lockfile, so it is schema-checked
/// (identity strings, dependency families as spec-string maps), not just parsed.
fn valid_package_manifest(manifest: &serde_json::Map<String, serde_json::Value>) -> bool {
    field_absent_or(manifest, "name", serde_json::Value::is_string)
        && field_absent_or(manifest, "version", serde_json::Value::is_string)
        && field_absent_or(manifest, "private", serde_json::Value::is_boolean)
        && string_valued_map(manifest, "scripts")
        && string_valued_map(manifest, "engines")
        && string_array(manifest, "keywords")
        && string_array(manifest, "files")
        && string_array(manifest, "os")
        && string_array(manifest, "cpu")
        && string_valued_map(manifest, "dependencies")
        && string_valued_map(manifest, "devDependencies")
        && string_valued_map(manifest, "optionalDependencies")
        && string_valued_map(manifest, "peerDependencies")
}

/// npm's name-keyed maps hold string values -- dependency specs, script bodies,
/// engine ranges. A non-string value is not one npm wrote.
fn string_valued_map(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    match object.get(key) {
        Some(value) => value
            .as_object()
            .is_some_and(|map| map.values().all(serde_json::Value::is_string)),
        None => true,
    }
}

fn string_array(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    match object.get(key) {
        Some(value) => value
            .as_array()
            .is_some_and(|items| items.iter().all(serde_json::Value::is_string)),
        None => true,
    }
}

fn field_absent_or(
    descriptor: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    is_expected_type: fn(&serde_json::Value) -> bool,
) -> bool {
    match descriptor.get(key) {
        Some(value) => is_expected_type(value),
        None => true,
    }
}

/// The lockfile must describe THIS project: when package.json declares a name or
/// version, the lockfile's identity entry (v1 top level, v2/v3 packages[""]) must
/// carry the same value, so a lockfile planted from another project -- or a stale
/// one whose version drifted -- cannot authorize deleting this node_modules.
fn identity_agrees(
    identity: &serde_json::Map<String, serde_json::Value>,
    manifest: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    field_agrees(manifest, identity, "name") && field_agrees(manifest, identity, "version")
}

fn field_agrees(
    manifest: &serde_json::Map<String, serde_json::Value>,
    identity: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> bool {
    match (manifest.get(key), identity.get(key)) {
        (None, None) => true,
        // Lockfile declares identity the manifest omits: it must still be a string,
        // so a wrong-typed lockfile identity fails closed rather than being skipped.
        (None, Some(actual)) => actual.is_string(),
        (Some(declared), Some(actual)) => declared
            .as_str()
            .is_some_and(|declared| actual.as_str() == Some(declared)),
        // Manifest declares identity the lockfile lacks: it cannot corroborate.
        (Some(_), None) => false,
    }
}

/// Reads `path` no-follow and bounded, returning its top-level JSON object.
///
/// A symlink (see [`degu_walk::read_regular_capped_nofollow`]), FIFO, device, or
/// directory is a plain Miss; an over-cap or unreadable file is indeterminate
/// (fail closed, never a match); malformed JSON or a non-object top level is a Miss.
fn read_json_object(
    path: &Path,
    cap: usize,
    ctx: &DetectCtx,
) -> Result<serde_json::Map<String, serde_json::Value>, Probe> {
    if ctx.deadline_elapsed() {
        return Err(Probe::Truncated { incomplete: false });
    }
    let read = match degu_walk::read_regular_capped_nofollow(path, cap) {
        Ok(Some(read)) => read,
        Ok(None) => return Err(Probe::Miss),
        Err(err) if crate::is_missing_path_error(&err) => return Err(Probe::Miss),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "node manifest read failed");
            return Err(Probe::Incomplete);
        }
    };
    if read.truncated {
        tracing::warn!(path = %path.display(), "node manifest exceeds the read limit");
        return Err(Probe::Incomplete);
    }
    match serde_json::from_slice::<serde_json::Value>(&read.bytes) {
        Ok(serde_json::Value::Object(object)) => Ok(object),
        Ok(_) | Err(_) => Err(Probe::Miss),
    }
}

/// No-follow so a symlinked marker cannot borrow authority from unrelated content.
fn nonempty_regular_marker(path: &Path, ctx: &DetectCtx) -> Probe {
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Probe::Match,
        Ok(_) => Probe::Miss,
        Err(err) if crate::is_missing_path_error(&err) => Probe::Miss,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "artifact marker metadata probe failed");
            Probe::Incomplete
        }
    }
}

fn legacy_tox_root(path: &Path, ctx: &DetectCtx) -> Probe {
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    let mut entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "legacy tox directory read failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    let mut incomplete = false;
    loop {
        if ctx.deadline_elapsed() {
            return Probe::Truncated { incomplete };
        }
        let Some(entry) = entries.next() else {
            return if incomplete {
                Probe::Incomplete
            } else {
                Probe::Miss
            };
        };
        match tox_entry_probe(entry, path, ctx) {
            Probe::Match => return Probe::Match,
            Probe::ReportOnly => return Probe::ReportOnly,
            Probe::Miss => {}
            Probe::Incomplete => incomplete = true,
            Probe::Truncated {
                incomplete: current,
            } => {
                return Probe::Truncated {
                    incomplete: incomplete || current,
                };
            }
        }
    }
}

fn tox_entry_probe(
    entry: std::io::Result<std::fs::DirEntry>,
    root: &Path,
    ctx: &DetectCtx,
) -> Probe {
    let entry = match entry {
        Ok(entry) => entry,
        Err(err) => {
            tracing::warn!(path = %root.display(), %err, "legacy tox entry read failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    let entry_path = entry.path();
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(err) => {
            tracing::warn!(path = %entry_path.display(), %err, "legacy tox entry type probe failed during artifact classification");
            return Probe::Incomplete;
        }
    };
    if file_type.is_dir() {
        // Without parsing .tox-info.json we cannot confirm a real tox env, so a
        // present marker is report-only, never clean authority.
        match nonempty_regular_marker(&entry_path.join(".tox-info.json"), ctx) {
            Probe::Match => Probe::ReportOnly,
            other => other,
        }
    } else {
        Probe::Miss
    }
}

fn valid_cachedir_tag(path: &Path, ctx: &DetectCtx) -> Probe {
    match crate::cachedir_tag::probe(path, Some(ctx)) {
        crate::cachedir_tag::Probe::Match => Probe::Match,
        crate::cachedir_tag::Probe::Miss => Probe::Miss,
        crate::cachedir_tag::Probe::Incomplete => Probe::Incomplete,
        crate::cachedir_tag::Probe::Truncated => Probe::Truncated { incomplete: false },
    }
}

pub(super) fn file_probe(path: &Path, ctx: &DetectCtx) -> Probe {
    if ctx.deadline_elapsed() {
        return Probe::Truncated { incomplete: false };
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Probe::Match,
        Ok(_) => Probe::Miss,
        Err(err) if crate::is_missing_path_error(&err) => Probe::Miss,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "artifact evidence metadata probe failed");
            Probe::Incomplete
        }
    }
}

pub(super) fn canonical_path(path: &Path, ctx: &DetectCtx) -> Result<std::path::PathBuf, Probe> {
    if ctx.deadline_elapsed() {
        return Err(Probe::Truncated { incomplete: false });
    }
    path.canonicalize().map_err(|err| {
        tracing::warn!(path = %path.display(), %err, "artifact evidence canonicalization failed");
        Probe::Incomplete
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const PACKAGE_MANIFEST: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n";

    fn seed_untagged_cargo_target(root: &Path) -> std::path::PathBuf {
        let target = root.join("target");
        std::fs::create_dir_all(target.join("debug")).unwrap();
        std::fs::write(root.join("Cargo.toml"), PACKAGE_MANIFEST).unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        std::fs::write(target.join("debug/.cargo-lock"), "").unwrap();
        target
    }

    #[test]
    fn elapsed_deadline_precedes_legacy_tox_read() {
        let ctx = DetectCtx::from_process()
            .unwrap()
            .with_deadline(Some(Instant::now()));
        let missing = Path::new("/degu-missing/.tox");

        assert!(matches!(
            legacy_tox_root(missing, &ctx),
            Probe::Truncated { .. }
        ));
    }

    #[test]
    fn empty_root_tag_with_manifest_and_marker_is_not_eligible() {
        let root = tempfile::tempdir().unwrap();
        let target = seed_untagged_cargo_target(root.path());
        std::fs::write(target.join("CACHEDIR.TAG"), "").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        // An empty tag never grants eligibility; the weak tier still claims it
        // as report-only via the manifest and marker.
        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[test]
    fn wrong_signature_root_tag_with_manifest_and_marker_is_not_eligible() {
        let root = tempfile::tempdir().unwrap();
        let target = seed_untagged_cargo_target(root.path());
        std::fs::write(target.join("CACHEDIR.TAG"), "Signature: wrong\n").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[test]
    fn cargo_target_without_build_markers_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(root.path().join("Cargo.toml"), PACKAGE_MANIFEST).unwrap();
        std::fs::write(target.join("payload.bin"), [0u8; 16]).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn cargo_target_markers_without_manifest_stay_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(target.join("release")).unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        std::fs::write(target.join("release/.cargo-lock"), "").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn empty_manifest_without_package_or_workspace_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        // An empty Cargo.toml parses as valid TOML but declares neither a
        // package nor a workspace, so it is not a Cargo manifest.
        std::fs::write(root.path().join("Cargo.toml"), "").unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn manifest_without_package_or_workspace_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(
            root.path().join("Cargo.toml"),
            "[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn workspace_manifest_with_marker_is_report_only() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(
            root.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n",
        )
        .unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[test]
    fn oversized_manifest_is_not_eligible() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        let mut manifest = PACKAGE_MANIFEST.to_string();
        manifest.push_str(&"# padding\n".repeat(CARGO_MANIFEST_READ_CAP / 10 + 16));
        std::fs::write(root.path().join("Cargo.toml"), manifest).unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        // An over-cap manifest is indeterminate, so it never claims the root.
        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Incomplete
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_manifest_does_not_hang_and_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        let manifest = root.path().join("Cargo.toml");
        let c_path = std::ffi::CString::new(manifest.as_os_str().as_encoded_bytes()).unwrap();
        // A FIFO named Cargo.toml carries no manifest and must not hang.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn directory_manifest_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        // A directory named Cargo.toml is not a regular file, so it never reads.
        std::fs::create_dir(root.path().join("Cargo.toml")).unwrap();
        std::fs::write(target.join(".rustc_info.json"), "{}").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[cfg(unix)]
    #[test]
    fn definitive_cmake_match_overrides_named_probe_failure() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink("CACHEDIR.TAG", target.join("CACHEDIR.TAG")).unwrap();
        std::fs::write(
            target.join("CMakeCache.txt"),
            format!("CMAKE_HOME_DIRECTORY:INTERNAL={}\n", source.display()),
        )
        .unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&target, &ctx),
            ArtifactClassification::Match(ArtifactEvidence::BuildStructure)
        ));
    }

    const NODE_MANIFEST: &str = r#"{"name":"web","version":"1.0.0"}"#;
    // Real npm-generated shapes: v3 carries the root project at packages[""] plus
    // resolved descriptors; v1 keeps them under dependencies. Both name "web".
    const NPM_LOCK_V3: &str = r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"web","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XI5MPzVN"}}}"#;
    const NPM_LOCK_V1: &str = r#"{"name":"web","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XI5MPzVN"}}}"#;

    fn seed_node_modules(root: &Path) -> std::path::PathBuf {
        let project = root.join("web");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::fs::write(project.join("node_modules/lib.js"), [0u8; 16]).unwrap();
        project
    }

    fn classify_node_modules(files: &[(&str, &str)]) -> ArtifactClassification {
        let root = tempfile::tempdir().unwrap();
        let project = seed_node_modules(root.path());
        for (name, contents) in files {
            std::fs::write(project.join(name), contents).unwrap();
        }
        let ctx = DetectCtx::from_process().unwrap();
        classify(&project.join("node_modules"), &ctx)
    }

    fn is_eligible(classification: ArtifactClassification) -> bool {
        matches!(
            classification,
            ArtifactClassification::Match(ArtifactEvidence::BuildStructure)
        )
    }

    #[test]
    fn node_modules_with_real_v3_lockfile_is_eligible() {
        assert!(is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", NPM_LOCK_V3),
        ])));
    }

    #[test]
    fn node_modules_with_real_v1_lockfile_is_eligible() {
        assert!(is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", NPM_LOCK_V1),
        ])));
    }

    #[test]
    fn valid_shrinkwrap_grants_authority() {
        assert!(is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("npm-shrinkwrap.json", NPM_LOCK_V3),
        ])));
    }

    #[test]
    fn node_modules_without_lockfile_is_report_only() {
        assert!(matches!(
            classify_node_modules(&[("package.json", NODE_MANIFEST)]),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[test]
    fn node_modules_with_unparseable_lockfile_is_report_only() {
        for lockfile in ["", "{", r#"{"v":3}"#] {
            assert!(
                matches!(
                    classify_node_modules(&[
                        ("package.json", NODE_MANIFEST),
                        ("package-lock.json", lockfile),
                    ]),
                    ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
                ),
                "lockfile {lockfile:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn unknown_or_mismatched_lockfile_version_is_not_eligible() {
        let cases = [
            r#"{"name":"web","lockfileVersion":0,"packages":{"":{}}}"#,
            r#"{"name":"web","lockfileVersion":4,"packages":{"":{}}}"#,
            r#"{"name":"web","lockfileVersion":999,"packages":{"":{}}}"#,
            r#"{"name":"web","lockfileVersion":1,"packages":{"":{}}}"#, // v1 must use dependencies
            r#"{"name":"web","lockfileVersion":3,"dependencies":{}}"#,  // v2/v3 must use packages
            r#"{"name":"web","lockfileVersion":3,"packages":{}}"#,      // no packages[""] root
        ];
        for lockfile in cases {
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", lockfile),
                ])),
                "lockfile {lockfile:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn non_object_graph_entries_are_not_eligible() {
        let cases = [
            r#"{"name":"web","lockfileVersion":1,"dependencies":{"left-pad":"1.3.0"}}"#,
            r#"{"name":"web","lockfileVersion":3,"packages":{"":{},"node_modules/x":"1.0.0"}}"#,
        ];
        for lockfile in cases {
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", lockfile),
                ])),
                "lockfile {lockfile:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn lockfile_for_a_different_project_is_not_eligible() {
        let planted = r#"{"name":"other","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"other","version":"1.0.0"}}}"#;
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", planted),
        ])));
    }

    #[test]
    fn wrong_typed_descriptor_fields_are_not_eligible() {
        let root = r#""":{"name":"web","version":"1.0.0"}"#;
        let entries = [
            r#""node_modules/x":{"version":7}"#,    // number, not string
            r#""node_modules/x":{"version":null}"#, // null, not string
            r#""node_modules/x":{"link":"yes"}"#,   // link non-boolean, no version
            r#""node_modules/x":{"version":"1.0.0","dependencies":[]}"#, // array, not object
            r#""node_modules/x":{"version":"1.0.0","optional":"false"}"#, // string, not boolean
            r#""node_modules/x":{"version":"1.0.0","resolved":5}"#, // number, not string
        ];
        for entry in entries {
            let lockfile = format!(
                r#"{{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{{{root},{entry}}}}}"#
            );
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", &lockfile),
                ])),
                "descriptor {entry} must not grant eligibility"
            );
        }
    }

    #[test]
    fn root_identity_disagreeing_with_manifest_is_not_eligible() {
        let cases = [
            // Root version drifts from the manifest's declared version.
            r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web","version":"2.0.0"}}}"#,
            // Manifest declares a version the root entry omits.
            r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web"}}}"#,
        ];
        for lockfile in cases {
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", lockfile),
                ])),
                "lockfile {lockfile:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn valid_workspace_link_entry_is_eligible() {
        let lockfile = r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web","version":"1.0.0"},"apps/web":{"name":"web","version":"1.0.0"},"node_modules/web":{"resolved":"apps/web","link":true}}}"#;
        assert!(is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn malformed_package_json_schema_is_not_eligible() {
        // A valid lockfile cannot corroborate a manifest whose own schema is wrong.
        let manifests = [
            r#"{"name":7,"version":false}"#, // identity wrong type
            r#"{"name":"web","version":"1.0.0","dependencies":{"x":7}}"#, // dep spec not a string
            r#"{"name":"web","version":"1.0.0","devDependencies":{"y":5}}"#,
            r#"{"name":"web","version":"1.0.0","private":"yes"}"#, // private not boolean
            r#"{"name":"web","version":"1.0.0","keywords":[7]}"#,  // array element not string
        ];
        for manifest in manifests {
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", manifest),
                    ("package-lock.json", NPM_LOCK_V3),
                ])),
                "manifest {manifest:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn wrong_typed_manifest_identity_fails_closed() {
        // A wrong-typed manifest name must fail the identity check, not skip it.
        let lockfile = r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web","version":"1.0.0"}}}"#;
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", r#"{"name":7}"#),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn extended_descriptor_field_type_errors_are_not_eligible() {
        let cases = [
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","devOptional":"yes"}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","hasInstallScript":1}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","os":[7]}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","dependencies":{"y":5}}}"#,
        ];
        for packages in cases {
            let lockfile = format!(
                r#"{{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{packages}}}"#
            );
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", &lockfile),
                ])),
                "packages {packages} must not grant eligibility"
            );
        }
    }

    #[test]
    fn v1_nested_dependency_wrong_type_is_not_eligible() {
        // The top-level descriptor is well-formed, but a nested one is not; v1
        // validation must recurse.
        let lockfile = r#"{"name":"web","version":"1.0.0","lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"child":7}}}}"#;
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn descriptor_with_valid_extended_fields_is_eligible() {
        let lockfile = r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"web","version":"1.0.0","dependencies":{"dep":"^1.0.0"}},"node_modules/dep":{"version":"1.0.0","resolved":"https://r/dep.tgz","integrity":"sha512-AA","devOptional":true,"hasInstallScript":false,"os":["linux","darwin"],"dependencies":{"sub":"^2.0.0"}}}}"#;
        assert!(is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn v1_wrong_typed_top_level_identity_is_not_eligible() {
        // Manifest omits identity, but the v1 lockfile top level carries an
        // explicitly wrong-typed name/version; the symmetric check must reject it.
        let lockfile = r#"{"name":7,"version":false,"lockfileVersion":1,"requires":true,"dependencies":{"x":{"version":"1.0.0"}}}"#;
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", "{}"),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn v1_non_boolean_requires_flag_is_not_eligible() {
        // The v1 top-level `requires` flag is a boolean, not the entry-level map.
        let lockfile = r#"{"name":"web","version":"1.0.0","lockfileVersion":1,"requires":{"x":"1"},"dependencies":{"x":{"version":"1.0.0"}}}"#;
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", lockfile),
        ])));
    }

    #[test]
    fn descriptor_flag_field_type_errors_are_not_eligible() {
        let cases = [
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","peer":"yes"}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","extraneous":[]}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","engines":{"node":false}}}"#,
            r#"{"":{"name":"web","version":"1.0.0"},"node_modules/x":{"version":"1.0.0","libc":[7]}}"#,
        ];
        for packages in cases {
            let lockfile = format!(
                r#"{{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{packages}}}"#
            );
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", NODE_MANIFEST),
                    ("package-lock.json", &lockfile),
                ])),
                "packages {packages} must not grant eligibility"
            );
        }
    }

    #[test]
    fn manifest_config_map_non_string_values_are_not_eligible() {
        let manifests = [
            r#"{"name":"web","version":"1.0.0","scripts":{"install":7}}"#,
            r#"{"name":"web","version":"1.0.0","engines":{"node":false}}"#,
        ];
        for manifest in manifests {
            assert!(
                !is_eligible(classify_node_modules(&[
                    ("package.json", manifest),
                    ("package-lock.json", NPM_LOCK_V3),
                ])),
                "manifest {manifest:?} must not grant eligibility"
            );
        }
    }

    #[test]
    fn broken_shrinkwrap_does_not_defer_to_valid_package_lock() {
        assert!(!is_eligible(classify_node_modules(&[
            ("package.json", NODE_MANIFEST),
            ("package-lock.json", NPM_LOCK_V3),
            ("npm-shrinkwrap.json", r#"{"v":3}"#),
        ])));
    }

    #[test]
    fn node_modules_without_package_json_is_not_eligible() {
        assert!(matches!(
            classify_node_modules(&[("package-lock.json", NPM_LOCK_V3)]),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn node_modules_with_malformed_package_json_is_not_eligible() {
        assert!(matches!(
            classify_node_modules(&[("package.json", "{"), ("package-lock.json", NPM_LOCK_V3)]),
            ArtifactClassification::Miss
        ));
    }

    #[cfg(unix)]
    #[test]
    fn node_modules_with_symlinked_lockfile_is_not_eligible() {
        let root = tempfile::tempdir().unwrap();
        let project = seed_node_modules(root.path());
        std::fs::write(project.join("package.json"), NODE_MANIFEST).unwrap();
        // The target is a valid lockfile; the O_NOFOLLOW read must refuse to
        // resolve the symlink, so the project stays report-only.
        let real = root.path().join("real-lock.json");
        std::fs::write(&real, NPM_LOCK_V3).unwrap();
        std::os::unix::fs::symlink(&real, project.join("package-lock.json")).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&project.join("node_modules"), &ctx),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn node_modules_with_symlinked_package_json_is_not_eligible() {
        let root = tempfile::tempdir().unwrap();
        let project = seed_node_modules(root.path());
        let real = root.path().join("real-package.json");
        std::fs::write(&real, NODE_MANIFEST).unwrap();
        std::os::unix::fs::symlink(&real, project.join("package.json")).unwrap();
        std::fs::write(project.join("package-lock.json"), NPM_LOCK_V3).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&project.join("node_modules"), &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[test]
    fn legacy_tox_marker_is_report_only() {
        let root = tempfile::tempdir().unwrap();
        let env = root.path().join(".tox/py311");
        std::fs::create_dir_all(&env).unwrap();
        std::fs::write(env.join(".tox-info.json"), r#"{"tox_version":"4.11.0"}"#).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&root.path().join(".tox"), &ctx),
            ArtifactClassification::Match(ArtifactEvidence::WeakBuildStructure)
        ));
    }

    #[test]
    fn legacy_tox_with_empty_marker_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let env = root.path().join(".tox/py311");
        std::fs::create_dir_all(&env).unwrap();
        std::fs::write(env.join(".tox-info.json"), "").unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&root.path().join(".tox"), &ctx),
            ArtifactClassification::Miss
        ));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_tox_with_symlinked_marker_stays_unclaimed() {
        let root = tempfile::tempdir().unwrap();
        let env = root.path().join(".tox/py311");
        std::fs::create_dir_all(&env).unwrap();
        let real = root.path().join("real.json");
        std::fs::write(&real, r#"{"tox_version":"4.11.0"}"#).unwrap();
        std::os::unix::fs::symlink(&real, env.join(".tox-info.json")).unwrap();
        let ctx = DetectCtx::from_process().unwrap();

        assert!(matches!(
            classify(&root.path().join(".tox"), &ctx),
            ArtifactClassification::Miss
        ));
    }
}
