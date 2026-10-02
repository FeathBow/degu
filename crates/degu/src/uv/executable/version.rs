//! Parse the stable version and build annotation printed by uv.
use std::fmt;

pub(super) const MINIMUM_UV_VERSION: UvVersion = UvVersion::new(0, 8, 19);
/// The only cache-prune layout whose exact traversal and mutation contract is
/// audited. A newer binary may pass the minimum-version probe, but native
/// authority must remain unavailable until that version's prune implementation
/// is separately audited.
pub(crate) const AUDITED_UV_PRUNE_VERSION: UvVersion = UvVersion::new(0, 12, 3);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct UvVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl UvVersion {
    pub(crate) const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for UvVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UvVersionParseError {
    #[error("output is not UTF-8")]
    NotUtf8,
    #[error("expected `uv MAJOR.MINOR.PATCH` with optional build information and one newline")]
    InvalidShape,
    #[error("version component is empty, non-decimal, non-canonical, or overflowing")]
    InvalidComponent,
}

pub(super) fn parse_uv_version(stdout: &[u8]) -> Result<UvVersion, UvVersionParseError> {
    let output = std::str::from_utf8(stdout).map_err(|_| UvVersionParseError::NotUtf8)?;
    let body = output
        .strip_suffix('\n')
        .ok_or(UvVersionParseError::InvalidShape)?;
    if body.contains(['\n', '\r']) {
        return Err(UvVersionParseError::InvalidShape);
    }
    let version = body
        .strip_prefix("uv ")
        .ok_or(UvVersionParseError::InvalidShape)?;
    let version = release_version(version)?;
    let mut components = version.split('.');
    let major = parse_version_component(components.next())?;
    let minor = parse_version_component(components.next())?;
    let patch = parse_version_component(components.next())?;
    if components.next().is_some() {
        return Err(UvVersionParseError::InvalidShape);
    }
    Ok(UvVersion {
        major,
        minor,
        patch,
    })
}

/// uv 0.12.3 prints `(hash date target)` or `(target)` without Git metadata.
/// The minimum supported version, 0.8.19, prints `(hash date)` or no annotation.
/// Development builds append `+N` to the version itself, which must still fail
/// numeric component parsing before a stable release can be claimed.
fn release_version(output: &str) -> Result<&str, UvVersionParseError> {
    let Some((version, annotation)) = output.split_once(' ') else {
        return Ok(output);
    };
    let annotation = annotation
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or(UvVersionParseError::InvalidShape)?;
    let fields: Vec<_> = annotation.split(' ').collect();
    let valid = match fields.as_slice() {
        [target] => valid_target(target),
        [hash, date] => valid_commit(hash, date),
        [hash, date, target] => valid_commit(hash, date) && valid_target(target),
        _ => false,
    };
    if !valid {
        return Err(UvVersionParseError::InvalidShape);
    }
    Ok(version)
}

fn valid_commit(hash: &str, date: &str) -> bool {
    const COMMIT_DATE_WIDTH: usize = 10;
    !hash.is_empty()
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && date.len() == COMMIT_DATE_WIDTH
        && date.parse::<jiff::civil::Date>().is_ok()
}

fn valid_target(target: &str) -> bool {
    const MINIMUM_TARGET_COMPONENTS: usize = 3;
    target.split('-').count() >= MINIMUM_TARGET_COMPONENTS
        && target.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        })
}

fn parse_version_component(component: Option<&str>) -> Result<u64, UvVersionParseError> {
    let component = component.ok_or(UvVersionParseError::InvalidShape)?;
    if component.is_empty()
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return Err(UvVersionParseError::InvalidComponent);
    }
    component
        .parse()
        .map_err(|_| UvVersionParseError::InvalidComponent)
}
