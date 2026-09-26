//! What degu is actually configured to do, and where each answer came from.
//!
//! A configuration that is read from a file, defaulted, or discovered by
//! convention gives three different reasons for the same observed behaviour,
//! and a reader who cannot tell them apart cannot fix anything. This prints the
//! effective values beside their origin.
//!
//! It reads. Nothing here writes a configuration file: the file is the reader's,
//! it carries their comments, and degu rewriting it would be degu editing a
//! document it did not author.

use anyhow::Result;
use degu_core::{config::Config, ecosystem::DetectCtx};
use std::path::{Path, PathBuf};

use crate::advisory::{Origin, Resolution};
use crate::presentation::{display_path, escape_terminal_text};

struct ConfigurationReport {
    path: PathBuf,
    present: bool,
    config: Config,
    resolution: Resolution,
    home: PathBuf,
}

pub(crate) fn run(json: bool) -> Result<()> {
    let report = ConfigurationReport::read()?;
    let out = if json {
        format!("{:#}\n", report.json())
    } else {
        report.human()
    };
    crate::output::write_stdout(out.into_bytes())
}

impl ConfigurationReport {
    fn read() -> Result<Self> {
        let ctx = DetectCtx::from_process()?;
        let path = ctx.xdg_config().join("degu/config.toml");
        let present = path.is_file();
        let config = crate::configuration::load_config(&ctx)?;
        let resolution = crate::advisory::resolve_advisor(&config.advisory, &ctx.xdg_config());
        Ok(Self {
            path,
            present,
            config,
            resolution,
            home: ctx.home,
        })
    }

    fn shown(&self, path: &Path) -> String {
        display_path(path, &self.home)
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "check": "effective_configuration",
            "file": self.shown(&self.path),
            "file_present": self.present,
            "roots": self.config.roots,
            "protect": self.config.protect,
            "disable": self.config.disable,
            "max_concurrency": self.config.max_concurrency.map(std::num::NonZeroUsize::get),
            "runtime": self.config.runtime,
            "advisory": {
                "enabled": self.config.advisory.enabled,
                "timeout_seconds": self.config.advisory.timeout_seconds,
                "advisor": advisor_json(&self.resolution, &|path| self.shown(path)),
            },
        })
    }

    fn human(&self) -> String {
        let mut out = format!(
            "Configuration\n  file             {} ({})\n\n",
            escape_terminal_text(&self.shown(&self.path)),
            if self.present {
                "read"
            } else {
                "not present; defaults in use"
            }
        );
        out.push_str(&self.scanning());
        out.push_str(&self.advisory());
        out
    }

    fn scanning(&self) -> String {
        format!(
            "Scanning\n  roots            {}\n  protect          {}\n  disable          {}\n  max_concurrency  {}\n  runtime          {}\n\n",
            list(&self.config.roots),
            list(&self.config.protect),
            list(&self.config.disable),
            self.config.max_concurrency.map_or_else(
                || "per-filesystem default".to_owned(),
                |value| value.to_string()
            ),
            if self.config.runtime { "on" } else { "off" }
        )
    }

    fn advisory(&self) -> String {
        let mut out = format!(
            "Advisory\n  pane             {}\n  advisor          {}\n  bound            {}s\n",
            if self.config.advisory.enabled {
                "on"
            } else {
                "off (advisory.enabled = false)"
            },
            escape_terminal_text(&advisor_line(&self.resolution, &|path| self.shown(path))),
            self.config.advisory.timeout_seconds
        );
        if self.config.advisory.enabled
            && let Resolution::Absent { convention } = &self.resolution
        {
            out.push_str(&format!(
                "\nAn advisor is any executable that reads a signature on standard input and writes\nJSON back. Put one at {} and degu uses it; degu holds no key\nand speaks no model protocol, so which model or endpoint it uses is its business.\nSee degu's configuration documentation for the exact contract.\n",
                escape_terminal_text(&self.shown(convention))
            ));
        }
        out
    }
}

fn list(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values
            .iter()
            .map(|value| escape_terminal_text(value))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn advisor_line(resolution: &Resolution, shown: &impl Fn(&std::path::Path) -> String) -> String {
    match resolution {
        Resolution::Found { path, origin } => format!(
            "{} ({})",
            shown(path),
            match origin {
                Origin::Configured => "named by advisory.command",
                Origin::Convention => "found at the conventional path",
            }
        ),
        Resolution::Absent { convention } => {
            format!("none; put one at {}", shown(convention))
        }
        Resolution::Refused { path, reason } => {
            format!("{} will not be run: {reason}", shown(path))
        }
    }
}

fn advisor_json(
    resolution: &Resolution,
    shown: &impl Fn(&std::path::Path) -> String,
) -> serde_json::Value {
    match resolution {
        Resolution::Found { path, origin } => serde_json::json!({
            "status": "found",
            "path": shown(path),
            "origin": match origin {
                Origin::Configured => "configured",
                Origin::Convention => "convention",
            },
        }),
        Resolution::Absent { convention } => serde_json::json!({
            "status": "absent",
            "convention_path": shown(convention),
        }),
        Resolution::Refused { path, reason } => serde_json::json!({
            "status": "refused",
            "path": shown(path),
            "reason": reason,
        }),
    }
}
