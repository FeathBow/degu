use anyhow::{Context, Result};
use degu_core::config::Config;
use degu_core::ecosystem::DetectCtx;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

pub(crate) fn valid_adapter_ids() -> Vec<String> {
    let mut ids = degu_adapters::all()
        .into_iter()
        .map(|registration| registration.id().to_string())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

/// Upper bound on a config file. A degu config is tiny; 1 MiB is orders of
/// magnitude above any legitimate file and caps the read so a huge or
/// newline-free file cannot exhaust memory.
const CONFIG_READ_CAP: usize = 1024 * 1024;

pub(crate) fn load_config(ctx: &DetectCtx) -> Result<Config> {
    let path = ctx.xdg_config().join("degu/config.toml");
    // Read through the safe primitive: a FIFO at the config path is user
    // misconfiguration and must not hang the process, and an oversized file must
    // not be slurped whole.
    let read = match degu_walk::read_regular_capped(&path, CONFIG_READ_CAP) {
        Ok(Some(read)) => read,
        // A non-regular config (FIFO/socket/device/dir) is a misconfiguration we
        // report honestly rather than silently defaulting.
        Ok(None) => anyhow::bail!("{} is not a regular file", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    if read.truncated {
        anyhow::bail!(
            "{} exceeds the {CONFIG_READ_CAP}-byte configuration limit",
            path.display()
        );
    }
    let text = String::from_utf8(read.bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    let config =
        Config::from_toml(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    validate_config(&config)?;
    Ok(config)
}

pub(crate) fn resolve_max_concurrency(
    flag: Option<NonZeroUsize>,
    config: &Config,
) -> Option<NonZeroUsize> {
    flag.or(config.max_concurrency)
}

pub(crate) fn deadline_from_budget(budget: Option<Duration>) -> Result<Option<Instant>> {
    budget
        .map(|budget| {
            Instant::now()
                .checked_add(budget)
                .ok_or_else(|| anyhow::anyhow!("budget is too large"))
        })
        .transpose()
}

fn validate_config(config: &Config) -> Result<()> {
    validate_disabled_adapters(&config.disable)?;
    for entry in &config.protect {
        validate_protect_entry(entry)?;
    }
    for entry in &config.roots {
        validate_root_entry(entry)?;
    }
    Ok(())
}

fn validate_disabled_adapters(disabled: &[String]) -> Result<()> {
    let valid = valid_adapter_ids();
    let valid_set = valid.iter().map(String::as_str).collect::<HashSet<_>>();
    let invalid = disabled
        .iter()
        .filter(|id| !valid_set.contains(id.as_str()))
        .map(|id| format!("{id:?}"))
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "unknown adapter ids in disable: {}; valid adapter ids: {}",
        invalid.join(", "),
        valid.join(", ")
    )
}

fn validate_protect_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        anyhow::bail!("invalid protect entry {entry:?}: empty string");
    }
    if entry.starts_with('~') {
        anyhow::bail!("invalid protect entry {entry:?}: leading ~ is not allowed");
    }
    validate_no_glob_or_parent("protect", entry)
}

fn validate_root_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        anyhow::bail!("invalid root entry {entry:?}: empty string");
    }
    if entry.starts_with('~') && !entry.starts_with("~/") {
        anyhow::bail!("invalid root entry {entry:?}: leading ~ must be followed by /");
    }
    if !(Path::new(entry).is_absolute() || entry.starts_with("~/")) {
        anyhow::bail!(
            "invalid root entry {entry:?}: root entries must be absolute or start with ~/"
        );
    }
    validate_no_glob_or_parent("root", entry)
}

fn validate_no_glob_or_parent(kind: &str, entry: &str) -> Result<()> {
    if entry
        .chars()
        .any(|character| matches!(character, '*' | '?' | '['))
    {
        anyhow::bail!("invalid {kind} entry {entry:?}: glob characters are not allowed");
    }
    if Path::new(entry)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        anyhow::bail!(
            "invalid {kind} entry {entry:?}: parent directory components are not allowed"
        );
    }
    Ok(())
}
