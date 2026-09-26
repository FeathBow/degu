//! Decision support beside a finding, never part of one.
//!
//! degu classifies from what it measured. When it cannot classify, the reader is
//! left with a size and a name, which is not enough to decide with and is why
//! the unrecognized tier is where people give up and reach for `rm -rf`.
//!
//! This module fills that gap without putting anything into the decision.
//! degu speaks no model protocol, ships no client, and holds no credential: the
//! reader names an executable, degu hands it a signature on standard input and
//! reads prose back, under the same bounds every other host tool runs under.
//! Which model, which endpoint and which key are that program's business.
//! degu could not learn them if it wanted to — the child's environment is
//! emptied before exec, so a credential cannot be passed through it.
//!
//! Nothing here can reach a disposition, a plan, or a selection. The strongest
//! thing an advisory can do is put a sentence on a screen, and the screen says
//! whose sentence it is.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use degu_core::config::AdvisoryConfig;
use degu_core::ecosystem::DetectCtx;
use degu_core::finding::Finding;

mod discovery;
mod protocol;
#[cfg(test)]
mod tests;

pub(crate) use discovery::{Origin, Resolution, resolve_advisor};
pub(crate) use protocol::is_unrecognized;
use protocol::{Request, Response, Subject, resolve, subjects};

/// A response is a few sentences per subject. This admits a generous answer and
/// refuses a flood.
const RESPONSE_CAP_BYTES: usize = 64 * 1024;

/// One advisor's answer about one location, already bounded and de-escaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Advice {
    /// What the advisor thinks this is. Never a classification.
    pub(crate) summary: String,
    /// A command the reader can run to confirm or refute the summary.
    ///
    /// This is the most useful thing an advisor produces: it turns an opinion
    /// into something the reader can settle themselves. An answer without one
    /// stays a hint.
    pub(crate) check: Option<String>,
}

/// Why a pane has no external advisory to show.
///
/// Distinguished because they mean different things to the reader: one is a
/// choice they have not made, the rest are a program of theirs that did not
/// work. Silence would read as "degu has nothing to say", which is a different
/// and untrue statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// No advisor exists, carrying where one would go.
    Absent(PathBuf),
    /// Something is there that degu declined to run.
    Refused(String),
    /// An advisor ran and produced nothing usable.
    Failed(String),
}

/// Every advisory for one review, keyed by the path it is about.
#[derive(Clone, Debug, Default)]
pub(crate) struct Advisories {
    advice: BTreeMap<PathBuf, Advice>,
    unavailable: Option<Unavailable>,
    /// The program that produced these, for the pane to name.
    source: Option<String>,
    /// The reader turned the pane off. Nothing is drawn at all: turning
    /// something off has to remove it, not change what it says.
    disabled: bool,
}

impl Advisories {
    fn without(unavailable: Unavailable) -> Self {
        Self {
            unavailable: Some(unavailable),
            ..Self::default()
        }
    }

    pub(crate) fn for_path(&self, path: &Path) -> Option<&Advice> {
        self.advice.get(path)
    }

    pub(crate) fn unavailable(&self) -> Option<&Unavailable> {
        self.unavailable.as_ref()
    }

    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub(crate) fn disabled(&self) -> bool {
        self.disabled
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        advice: impl IntoIterator<Item = (PathBuf, Advice)>,
        unavailable: Option<Unavailable>,
        source: Option<&str>,
    ) -> Self {
        Self {
            advice: advice.into_iter().collect(),
            unavailable,
            source: source.map(str::to_owned),
            disabled: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        Self {
            disabled: true,
            ..Self::default()
        }
    }
}

/// Consult the configured advisor about what degu could not classify.
///
/// Every failure is an absence of advice, never an error the reader has to
/// clear: an advisory is decision support, and a review must open whether or not
/// somebody's script worked.
pub(crate) fn consult(
    config: &AdvisoryConfig,
    findings: &[Finding],
    ctx: &DetectCtx,
) -> Advisories {
    let home = &ctx.home;
    let config_home = ctx.xdg_config();
    if !config.enabled {
        return Advisories {
            disabled: true,
            ..Advisories::default()
        };
    }
    // Before looking for an advisor at all: a scan where degu classified
    // everything has nothing to ask about, and neither starting somebody's
    // program nor reporting on one they have not set up says anything useful
    // about a screen where no advisory block will be drawn.
    let subjects = subjects(findings, home);
    if subjects.is_empty() {
        return Advisories::default();
    }
    let path = match resolve_advisor(config, &config_home) {
        Resolution::Found { path, .. } => path,
        Resolution::Absent { convention } => {
            return Advisories::without(Unavailable::Absent(convention));
        }
        Resolution::Refused { path, reason } => {
            return Advisories::without(Unavailable::Refused(format!(
                "{} was not run because {reason}",
                path.display()
            )));
        }
    };
    let command = path.to_string_lossy().into_owned();
    // What the pane will name. Elided like every other path degu prints, so an
    // advisor under the account home reads as `~/.config/degu/advisor` rather
    // than spending three wrapped lines on the reader's own home.
    let shown = crate::presentation::display_path(&path, home);
    Advisor {
        command: &command,
        shown: &shown,
        timeout: Duration::from_secs(config.timeout_seconds),
    }
    .consult(&subjects, run_advisor)
}

type Runner = fn(&Path, &[u8], Duration) -> Result<Vec<u8>, String>;

fn run_advisor(binary: &Path, input: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let arguments: [&OsStr; 0] = [];
    match (degu_core::system_tool::Invocation {
        binary,
        arguments: &arguments,
        timeout,
        stdout_cap: RESPONSE_CAP_BYTES,
    })
    .run(Some(input))
    {
        Ok(run) if run.success => Ok(run.stdout),
        Ok(_) => Err("the advisor exited unsuccessfully".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

struct Advisor<'a> {
    command: &'a str,
    shown: &'a str,
    timeout: Duration,
}

impl Advisor<'_> {
    fn consult(self, subjects: &[Subject], run: Runner) -> Advisories {
        let Self {
            command,
            shown,
            timeout,
        } = self;
        let request = Request {
            degu_advisory_request: 1,
            subjects,
        };
        let Ok(payload) = serde_json::to_vec(&request) else {
            return failed(shown, "the request could not be encoded");
        };
        let output = match run(Path::new(command), &payload, timeout) {
            Ok(output) => output,
            Err(reason) => return failed(shown, &reason),
        };
        let Ok(response) = serde_json::from_slice::<Response>(&output) else {
            return failed(shown, "the advisor did not answer with a degu advisory");
        };
        Advisories {
            advice: resolve(&response, subjects),
            unavailable: None,
            source: Some(shown.to_owned()),
            disabled: false,
        }
    }
}

fn failed(command: &str, reason: &str) -> Advisories {
    Advisories {
        advice: BTreeMap::new(),
        unavailable: Some(Unavailable::Failed(reason.to_owned())),
        source: Some(command.to_owned()),
        disabled: false,
    }
}
