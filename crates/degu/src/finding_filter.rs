use crate::filters::Filters;
use anyhow::{Context, Result};
use degu_core::finding::Finding;
use std::collections::{HashMap, hash_map::Entry};
use std::path::PathBuf;

pub(crate) struct PreparedFindingFilter<'a> {
    filters: &'a Filters,
    path_scope: PathScope,
}

pub(crate) struct FilterResult {
    pub(crate) included: Vec<Finding>,
    pub(crate) excluded: Vec<FilteredFinding>,
}

enum PathScope {
    All,
    Validated(ValidatedPathScope),
}

struct ValidatedPathScope {
    filters: Vec<PathBuf>,
    canonical_findings: HashMap<PathBuf, PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilterReason {
    Path,
    OlderThan,
    MinSize,
    Top,
}

impl FilterReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::OlderThan => "older_than",
            Self::MinSize => "min_size",
            Self::Top => "top",
        }
    }
}

#[derive(Debug)]
pub(crate) struct FilteredFinding {
    pub(crate) finding: Finding,
    pub(crate) reason: FilterReason,
}

impl<'a> PreparedFindingFilter<'a> {
    pub(crate) fn prepare(
        filters: &'a Filters,
        paths: &[PathBuf],
        universe: &[Finding],
    ) -> Result<Self> {
        Ok(Self {
            filters,
            path_scope: PathScope::prepare(paths, universe)?,
        })
    }

    pub(crate) fn select(&self, findings: Vec<Finding>) -> Result<FilterResult> {
        let mut result = self.path_scope.select(findings)?;
        if let Some(days) = self.filters.older_than {
            result = result.retain(FilterReason::OlderThan, |finding| {
                finding.age_days().is_some_and(|age| age >= days)
            });
        }
        if let Some(min_size) = self.filters.min_size {
            result = result.retain(FilterReason::MinSize, |finding| {
                finding.bytes_allocated() >= min_size
            });
        }
        Ok(result.rank_and_limit(self.filters.top))
    }
}

impl FilterResult {
    fn retain(self, reason: FilterReason, mut keep: impl FnMut(&Finding) -> bool) -> Self {
        let (included, removed): (Vec<_>, Vec<_>) =
            self.included.into_iter().partition(|finding| keep(finding));
        let mut excluded = self.excluded;
        excluded.extend(
            removed
                .into_iter()
                .map(|finding| FilteredFinding { finding, reason }),
        );
        Self { included, excluded }
    }

    fn rank_and_limit(self, top: Option<usize>) -> Self {
        let mut included = rank_findings(self.included);
        let mut excluded = self.excluded;
        if let Some(top) = top.filter(|top| *top < included.len()) {
            excluded.extend(
                included
                    .split_off(top)
                    .into_iter()
                    .map(|finding| FilteredFinding {
                        finding,
                        reason: FilterReason::Top,
                    }),
            );
        }
        Self { included, excluded }
    }
}

impl PathScope {
    fn prepare(paths: &[PathBuf], universe: &[Finding]) -> Result<Self> {
        if paths.is_empty() {
            return Ok(Self::All);
        }
        Ok(Self::Validated(ValidatedPathScope::capture(
            universe, paths,
        )?))
    }

    fn select(&self, findings: Vec<Finding>) -> Result<FilterResult> {
        match self {
            Self::All => Ok(FilterResult {
                included: findings,
                excluded: Vec::new(),
            }),
            Self::Validated(scope) => select_paths(findings, scope),
        }
    }
}

fn select_paths(findings: Vec<Finding>, path_scope: &ValidatedPathScope) -> Result<FilterResult> {
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for finding in findings {
        if path_scope.includes(&finding)? {
            included.push(finding);
        } else {
            excluded.push(FilteredFinding {
                finding,
                reason: FilterReason::Path,
            });
        }
    }
    Ok(FilterResult { included, excluded })
}

impl ValidatedPathScope {
    fn capture(findings: &[Finding], paths: &[PathBuf]) -> Result<Self> {
        let filters = canonicalize_filters(paths)?;
        let canonical_findings = canonicalize_findings(findings)?;
        ensure_filters_match(&filters, &canonical_findings)?;
        Ok(Self {
            filters,
            canonical_findings,
        })
    }

    fn includes(&self, finding: &Finding) -> Result<bool> {
        let canonical = self
            .canonical_findings
            .get(finding.path())
            .with_context(|| {
                format!(
                    "finding {} was not present when --path scope was validated",
                    finding.path().display()
                )
            })?;
        Ok(self
            .filters
            .iter()
            .any(|filter| canonical.starts_with(filter)))
    }
}

fn canonicalize_filters(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|path| {
            std::fs::canonicalize(path)
                .with_context(|| format!("failed to canonicalize --path {}", path.display()))
        })
        .collect()
}

fn canonicalize_findings(findings: &[Finding]) -> Result<HashMap<PathBuf, PathBuf>> {
    let mut canonical = HashMap::with_capacity(findings.len());
    for finding in findings {
        if let Entry::Vacant(entry) = canonical.entry(finding.path().to_path_buf()) {
            entry.insert(canonicalize_finding(finding)?);
        }
    }
    Ok(canonical)
}

fn canonicalize_finding(finding: &Finding) -> Result<PathBuf> {
    std::fs::canonicalize(finding.path()).with_context(|| {
        format!(
            "failed to canonicalize finding {}",
            finding.path().display()
        )
    })
}

fn ensure_filters_match(filters: &[PathBuf], findings: &HashMap<PathBuf, PathBuf>) -> Result<()> {
    for filter in filters {
        if !findings.values().any(|finding| finding.starts_with(filter)) {
            anyhow::bail!("--path {} matched no selected findings", filter.display());
        }
    }
    Ok(())
}

pub(crate) fn rank_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut ranked = findings;
    ranked.sort_by(|left, right| {
        right
            .bytes_allocated()
            .cmp(&left.bytes_allocated())
            .then_with(|| left.ecosystem().cmp(right.ecosystem()))
            .then_with(|| left.path().cmp(right.path()))
    });
    ranked
}
