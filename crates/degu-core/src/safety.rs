use std::{
    ffi::{OsStr, OsString},
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

pub const CREDENTIAL_DIR_NAMES: [&str; 6] =
    [".ssh", ".gnupg", ".aws", ".kube", ".docker", "keyrings"];
const HOME_PROTECTED_PATHS: [&str; 10] = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
    ".config",
    ".local/share/keyrings",
    ".local/state/degu",
    "Documents",
    "Desktop",
];
pub const MIXED_STATE_AI_TOOL_DIR_NAMES: [&str; 3] = [".claude", ".codex", ".hermes"];
pub const MIXED_STATE_AI_TOOL_REASON: &str =
    "path overlaps a protected mixed-state AI tool directory";
pub const PROTECTED_CREDENTIAL_REASON: &str = "path contains a protected credential directory";
pub const SHARED_WRITABLE_REASON: &str = "path contains a group- or world-writable directory";

/// Names that demote any enclosing finding to report-only when found as a
/// descendant. Built from its two real sources so drift is impossible.
pub const PROTECTED_DESCENDANT_DIR_NAMES: [&str;
    CREDENTIAL_DIR_NAMES.len() + MIXED_STATE_AI_TOOL_DIR_NAMES.len()] =
    concat_protected_descendant_names();

const fn concat_protected_descendant_names()
-> [&'static str; CREDENTIAL_DIR_NAMES.len() + MIXED_STATE_AI_TOOL_DIR_NAMES.len()] {
    let mut names = [""; CREDENTIAL_DIR_NAMES.len() + MIXED_STATE_AI_TOOL_DIR_NAMES.len()];
    let mut index = 0;
    while index < CREDENTIAL_DIR_NAMES.len() {
        names[index] = CREDENTIAL_DIR_NAMES[index];
        index += 1;
    }
    let mut offset = 0;
    while offset < MIXED_STATE_AI_TOOL_DIR_NAMES.len() {
        names[CREDENTIAL_DIR_NAMES.len() + offset] = MIXED_STATE_AI_TOOL_DIR_NAMES[offset];
        offset += 1;
    }
    names
}

pub fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub struct ProtectionPolicy {
    protected_paths: Vec<PathBuf>,
    protected_names: Vec<OsString>,
    recursive_names: Vec<OsString>,
}

impl ProtectionPolicy {
    pub fn for_mixed_state_ai(home: &Path) -> Result<Self, GuardError> {
        let home = canonical_home(home)?;
        let mut policy = Self::with_names(
            MIXED_STATE_AI_TOOL_DIR_NAMES,
            PROTECTED_DESCENDANT_DIR_NAMES,
        );
        for name in MIXED_STATE_AI_TOOL_DIR_NAMES {
            policy.add(home.join(name))?;
        }
        Ok(policy)
    }

    fn with_guard_defaults(home: &Path) -> Result<Self, GuardError> {
        let home = canonical_home(home)?;
        let mut policy = Self::with_names(
            CREDENTIAL_DIR_NAMES
                .into_iter()
                .chain(MIXED_STATE_AI_TOOL_DIR_NAMES),
            PROTECTED_DESCENDANT_DIR_NAMES,
        );
        for path in HOME_PROTECTED_PATHS
            .into_iter()
            .chain(MIXED_STATE_AI_TOOL_DIR_NAMES)
        {
            policy.add(home.join(path))?;
        }
        Ok(policy)
    }

    fn with_names(
        names: impl IntoIterator<Item = &'static str>,
        recursive: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            protected_paths: Vec::new(),
            protected_names: names.into_iter().map(OsString::from).collect(),
            recursive_names: recursive.into_iter().map(OsString::from).collect(),
        }
    }

    pub fn add(&mut self, path: PathBuf) -> Result<(), GuardError> {
        if !path.is_absolute() {
            return Err(GuardError::NotAbsolute(path));
        }
        let exists = path
            .try_exists()
            .map_err(|source| protected_canonicalize(path.clone(), source))?;
        self.protected_paths.push(path.clone());
        if exists {
            let canonical = std::fs::canonicalize(&path)
                .map_err(|source| protected_canonicalize(path, source))?;
            self.protected_paths.push(canonical);
        }
        Ok(())
    }

    pub fn contains(&self, candidate: &Path) -> Result<Option<PathBuf>, GuardError> {
        let canonical = canonical_candidate(candidate)?;
        let views = [candidate, canonical.as_path()];
        Ok(self
            .named_component(&views)
            .or_else(|| self.containing_path(&views)))
    }

    pub fn contains_resolved(&self, views: &[&Path]) -> Option<PathBuf> {
        self.named_component(views)
            .or_else(|| self.containing_path(views))
    }

    pub fn identity_overlap(&self, candidate: &Path) -> Result<Option<PathBuf>, GuardError> {
        let canonical = canonical_candidate(candidate)?;
        let views = [candidate, canonical.as_path()];
        Ok(self.identity_match(&views))
    }

    pub fn overlap(&self, candidate: &Path) -> Result<Option<PathBuf>, GuardError> {
        let canonical = canonical_candidate(candidate)?;
        let views = [candidate, canonical.as_path()];
        if let Some(protected) = self.identity_match(&views) {
            return Ok(Some(protected));
        }
        self.named_descendant(&canonical)
    }

    fn identity_match(&self, views: &[&Path]) -> Option<PathBuf> {
        self.named_component(views)
            .or_else(|| self.overlapping_path(views))
    }

    fn named_component(&self, views: &[&Path]) -> Option<PathBuf> {
        views.iter().find_map(|view| {
            view.components().find_map(|component| {
                let Component::Normal(name) = component else {
                    return None;
                };
                matches_name(name, &self.protected_names).then(|| PathBuf::from(name))
            })
        })
    }

    fn containing_path(&self, views: &[&Path]) -> Option<PathBuf> {
        self.protected_paths
            .iter()
            .find(|protected| views.iter().any(|view| view.starts_with(protected)))
            .cloned()
    }

    fn overlapping_path(&self, views: &[&Path]) -> Option<PathBuf> {
        self.protected_paths
            .iter()
            .find(|protected| views.iter().any(|view| paths_overlap(view, protected)))
            .cloned()
    }

    fn named_descendant(&self, root: &Path) -> Result<Option<PathBuf>, GuardError> {
        degu_walk::find_named_entry_single_mount(root, &self.recursive_names)
            .map_err(|source| candidate_inspect(root.to_path_buf(), source))
    }
}

fn matches_name(name: &OsStr, protected_names: &[OsString]) -> bool {
    protected_names.iter().any(|protected| protected == name)
}

/// The last gate before any deletion plan executes: a protected-path hit
/// rejects the whole plan.
pub struct Guard {
    policy: ProtectionPolicy,
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("path {path} overlaps protected path {protected}")]
    Protected { path: PathBuf, protected: PathBuf },
    #[error("path {0} is not absolute")]
    NotAbsolute(PathBuf),
    #[error("failed to resolve protected path {path}")]
    ProtectedCanonicalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to canonicalize candidate path {path}")]
    CandidateCanonicalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect candidate path {path}")]
    CandidateInspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Guard {
    pub fn with_defaults(home: &Path) -> Result<Self, GuardError> {
        Ok(Self {
            policy: ProtectionPolicy::with_guard_defaults(home)?,
        })
    }

    pub fn add(&mut self, path: PathBuf) -> Result<(), GuardError> {
        self.policy.add(path)
    }

    pub fn check(&self, candidate: &Path) -> Result<(), GuardError> {
        if let Some(protected) = self.policy.overlap(candidate)? {
            return Err(protected_error(candidate, protected));
        }
        Ok(())
    }

    pub fn check_identity(&self, candidate: &Path) -> Result<(), GuardError> {
        if let Some(protected) = self.policy.identity_overlap(candidate)? {
            return Err(protected_error(candidate, protected));
        }
        Ok(())
    }
}

fn canonical_home(home: &Path) -> Result<PathBuf, GuardError> {
    std::fs::canonicalize(home).map_err(|source| protected_canonicalize(home.to_path_buf(), source))
}

fn canonical_candidate(candidate: &Path) -> Result<PathBuf, GuardError> {
    if !candidate.is_absolute() {
        return Err(GuardError::NotAbsolute(candidate.to_path_buf()));
    }
    std::fs::canonicalize(candidate).map_err(|source| GuardError::CandidateCanonicalize {
        path: candidate.to_path_buf(),
        source,
    })
}

fn protected_canonicalize(path: PathBuf, source: std::io::Error) -> GuardError {
    GuardError::ProtectedCanonicalize { path, source }
}

fn candidate_inspect(path: PathBuf, source: std::io::Error) -> GuardError {
    GuardError::CandidateInspect { path, source }
}

fn protected_error(path: &Path, protected: PathBuf) -> GuardError {
    GuardError::Protected {
        path: path.to_path_buf(),
        protected,
    }
}

#[cfg(test)]
mod tests;
