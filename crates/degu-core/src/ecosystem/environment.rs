//! Detection context: a read-only snapshot of the process environment plus
//! the XDG roots, deadline, and progress sink it exposes to discovery.

use super::discovery::Root;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;

/// Detection context with a read-only snapshot of the process environment.
#[derive(Clone)]
pub struct DetectCtx {
    pub home: PathBuf,
    pub max_concurrency: Option<NonZeroUsize>,
    pub progress: Option<Arc<degu_walk::Progress>>,
    pub deadline: Option<Instant>,
    env: HashMap<OsString, OsString>,
    reported_invalid_roots: Arc<Mutex<HashSet<&'static str>>>,
}

#[derive(Debug, Error)]
pub enum DetectCtxError {
    #[error("HOME is not set; degu works strictly in user space")]
    MissingHome,
    #[error("failed to canonicalize HOME {path}")]
    HomeCanonicalize {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl DetectCtx {
    /// Missing $HOME is unrecoverable: degu works strictly in user space;
    /// home-less scratch containers are not a target environment.
    pub fn from_process() -> Result<Self, DetectCtxError> {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .ok_or(DetectCtxError::MissingHome)?;
        let home = std::fs::canonicalize(&home)
            .map_err(|source| DetectCtxError::HomeCanonicalize { path: home, source })?;
        Ok(Self {
            home,
            max_concurrency: None,
            progress: None,
            deadline: None,
            env: std::env::vars_os().collect(),
            reported_invalid_roots: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Test-support constructor: a context over an explicit home and env map,
    /// so a test can point discovery at a temp tree without mutating the shared
    /// process environment.
    #[doc(hidden)]
    pub fn for_test<K, V>(home: PathBuf, env: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            home,
            max_concurrency: None,
            progress: None,
            deadline: None,
            env: env
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            reported_invalid_roots: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn with_max_concurrency(mut self, max_concurrency: Option<NonZeroUsize>) -> Self {
        self.max_concurrency = max_concurrency;
        self
    }

    pub fn with_progress(mut self, progress: Option<Arc<degu_walk::Progress>>) -> Self {
        self.progress = progress;
        self
    }

    pub fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    pub fn deadline_elapsed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Empty strings count as unset (the usual `export FOO=` shell residue).
    pub fn env(&self, key: &str) -> Option<&OsStr> {
        self.env
            .get(OsStr::new(key))
            .map(OsString::as_os_str)
            .filter(|v| !v.is_empty())
    }

    pub fn claim_invalid_root_diagnostic(&self, source: &'static str) -> bool {
        self.reported_invalid_roots
            .lock()
            .expect("invalid-root diagnostic state poisoned")
            .insert(source)
    }

    pub fn xdg_cache(&self) -> Root {
        self.xdg_root("XDG_CACHE_HOME", ".cache")
    }

    pub fn xdg_data(&self) -> Root {
        self.xdg_root("XDG_DATA_HOME", ".local/share")
    }

    pub fn xdg_config(&self) -> PathBuf {
        self.absolute_env_path("XDG_CONFIG_HOME")
            .unwrap_or_else(|| self.home.join(".config"))
    }

    pub fn xdg_state(&self) -> PathBuf {
        self.absolute_env_path("XDG_STATE_HOME")
            .unwrap_or_else(|| self.home.join(".local/state"))
    }

    /// XDG Base Directory variables must be absolute; relative values are
    /// invalid and ignored. Cache/data roots deliberately keep the invalid
    /// spelling so discovery reports them as incomplete rather than silently
    /// changing scan scope.
    fn absolute_env_path(&self, variable: &str) -> Option<PathBuf> {
        self.env(variable)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    }

    fn xdg_root(&self, variable: &'static str, fallback: &str) -> Root {
        self.env(variable)
            .map(|path| Root::well_known_environment(variable, PathBuf::from(path)))
            .unwrap_or_else(|| Root::well_known(self.home.join(fallback)))
    }
}
