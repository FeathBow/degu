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
use degu_core::ecosystem::DetectCtx;

use crate::advisory::{Origin, Resolution};

pub(crate) fn run(json: bool) -> Result<()> {
    let ctx = DetectCtx::from_process()?;
    let path = ctx.xdg_config().join("degu/config.toml");
    let present = path.is_file();
    let config = crate::configuration::load_config(&ctx)?;
    let resolution = crate::advisory::resolve_advisor(&config.advisory, &ctx.xdg_config());
    let home = ctx.home.clone();
    let shown = |value: &std::path::Path| crate::presentation::display_path(value, &home);

    if json {
        let report = serde_json::json!({
            "schema_version": 1,
            "check": "effective_configuration",
            "file": shown(&path),
            "file_present": present,
            "roots": config.roots,
            "protect": config.protect,
            "disable": config.disable,
            "max_concurrency": config.max_concurrency.map(std::num::NonZeroUsize::get),
            "runtime": config.runtime,
            "advisory": {
                "enabled": config.advisory.enabled,
                "timeout_seconds": config.advisory.timeout_seconds,
                "advisor": advisor_json(&resolution, &shown),
            },
        });
        return crate::output::write_stdout(format!("{report:#}\n").into_bytes());
    }

    let mut out = String::new();
    out.push_str("Configuration\n");
    out.push_str(&format!(
        "  file             {} ({})\n\n",
        shown(&path),
        if present {
            "read"
        } else {
            "not present; defaults in use"
        }
    ));
    out.push_str("Scanning\n");
    out.push_str(&format!("  roots            {}\n", list(&config.roots)));
    out.push_str(&format!("  protect          {}\n", list(&config.protect)));
    out.push_str(&format!("  disable          {}\n", list(&config.disable)));
    out.push_str(&format!(
        "  max_concurrency  {}\n",
        config.max_concurrency.map_or_else(
            || "per-filesystem default".to_owned(),
            |value| value.to_string()
        )
    ));
    out.push_str(&format!(
        "  runtime          {}\n\n",
        if config.runtime { "on" } else { "off" }
    ));
    out.push_str("Advisory\n");
    out.push_str(&format!(
        "  pane             {}\n",
        if config.advisory.enabled {
            "on"
        } else {
            "off (advisory.enabled = false)"
        }
    ));
    out.push_str(&format!(
        "  advisor          {}\n",
        advisor_line(&resolution, &shown)
    ));
    out.push_str(&format!(
        "  bound            {}s\n",
        config.advisory.timeout_seconds
    ));
    if config.advisory.enabled
        && let Resolution::Absent { convention } = &resolution
    {
        out.push_str(&format!(
            "\nAn advisor is any executable that reads a signature on standard input and writes\nJSON back. Put one at {} and degu uses it; degu holds no key\nand speaks no model protocol, so which model or endpoint it uses is its business.\nSee degu's configuration documentation for the exact contract.\n",
            shown(convention)
        ));
    }
    crate::output::write_stdout(out.into_bytes())
}

fn list(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values.join(", ")
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
