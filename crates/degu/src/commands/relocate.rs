use crate::output::stdoutln;
use anyhow::Result;
use degu_core::ecosystem::DetectCtx;
use serde::Serialize;
use std::path::{Path, PathBuf};

const SHELL_QUOTE_DELIMITERS: usize = 2;

#[derive(Serialize)]
struct RelocateExport {
    ecosystem: String,
    var: &'static str,
    value: String,
    current: Vec<String>,
    /// Trailer label for the "existing data" comments; distinct per export
    /// so sibling relocations of one ecosystem (the huggingface hub,
    /// datasets, and xet caches) do not repeat one ambiguous line. Never
    /// serialized: the JSON schema is frozen.
    #[serde(skip)]
    label: &'static str,
}

#[derive(Serialize)]
struct RelocateRefusal {
    ecosystem: String,
    reason: &'static str,
    var: &'static str,
}

struct RelocationPlan {
    exports: Vec<RelocateExport>,
    refusals: Vec<RelocateRefusal>,
}

#[derive(Serialize)]
struct RelocationReport<'a> {
    target: &'a str,
    exports: &'a [RelocateExport],
    not_relocatable: &'a [RelocateRefusal],
}

pub(crate) fn run(json: bool, target: PathBuf) -> Result<()> {
    if !target.is_absolute() {
        anyhow::bail!("relocate target must be an absolute path");
    }
    validate_target_is_not_a_file(&target)?;
    let target_utf8 = target
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("relocate target must be valid UTF-8"))?;
    let ctx = DetectCtx::from_process()?;
    let plan = relocation_plan(&ctx, &target)?;
    if json {
        print_json(target_utf8, &plan)?;
    } else {
        print_script(&plan)?;
    }
    Ok(())
}

/// An existing non-directory TARGET can only fail at runtime inside the
/// generated script's `mkdir -p`, so it is refused up front instead of
/// printing a script that cannot succeed.
fn validate_target_is_not_a_file(target: &Path) -> Result<()> {
    match std::fs::metadata(target) {
        Ok(metadata) if !metadata.is_dir() => anyhow::bail!(
            "relocate target {} exists and is not a directory; choose a directory path or move the existing file, then rerun",
            target.display()
        ),
        _ => Ok(()),
    }
}

fn relocation_plan(ctx: &DetectCtx, target: &Path) -> Result<RelocationPlan> {
    let mut exports = Vec::new();
    let mut refusals = Vec::new();
    for registration in degu_adapters::all() {
        let adapter = registration.ecosystem();
        let ecosystem = adapter.id().to_string();
        let relocations = adapter.relocations();
        refusals.extend(
            adapter
                .relocation_refusals()
                .into_iter()
                .map(|refusal| RelocateRefusal {
                    ecosystem: ecosystem.clone(),
                    var: refusal.var,
                    reason: refusal.reason,
                }),
        );
        if relocations.is_empty() {
            continue;
        }
        let current_roots = existing_roots(adapter, ctx)?;
        let sibling_relocations = relocations.len() > 1;
        for relocation in relocations {
            let current = current_roots
                .iter()
                .filter(|root| relocation.role.is_none() || root.role == relocation.role)
                .map(|root| root.path.clone())
                .collect::<Vec<_>>();
            let value = target
                .join(relocation.subdir)
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    anyhow::anyhow!("generated {ecosystem} relocation path contains invalid UTF-8")
                })?;
            exports.push(RelocateExport {
                ecosystem: ecosystem.clone(),
                var: relocation.var,
                value,
                current,
                label: if sibling_relocations {
                    relocation.subdir
                } else {
                    adapter.id()
                },
            });
        }
    }
    Ok(RelocationPlan { exports, refusals })
}

struct ExistingRoot {
    role: Option<&'static str>,
    path: String,
}

fn existing_roots(
    adapter: &dyn degu_core::ecosystem::Ecosystem,
    ctx: &DetectCtx,
) -> Result<Vec<ExistingRoot>> {
    let outcome = adapter.roots(ctx);
    if outcome.incomplete {
        anyhow::bail!("failed to resolve existing {} roots", adapter.id());
    }
    outcome
        .roots
        .into_iter()
        .map(|root| {
            let role = root.role;
            root.path
                .into_os_string()
                .into_string()
                .map(|path| ExistingRoot { role, path })
                .map_err(|_| {
                    anyhow::anyhow!("existing {} root contains invalid UTF-8", adapter.id())
                })
        })
        .collect()
}

fn print_json(target: &str, plan: &RelocationPlan) -> Result<()> {
    let report = RelocationReport {
        target,
        exports: &plan.exports,
        not_relocatable: &plan.refusals,
    };
    stdoutln!("{}", serde_json::to_string_pretty(&report)?)
}

fn print_script(plan: &RelocationPlan) -> Result<()> {
    stdoutln!(
        "# degu {}: review, run, then append the exports to your shell profile",
        env!("CARGO_PKG_VERSION")
    )?;
    stdoutln!(
        "# degu only printed this script — nothing was moved and no shell profile was edited; \
         evaluating it only creates the proposed cache directories and exports cache-specific variables"
    )?;
    print_commands(&plan.exports)?;
    for refusal in &plan.refusals {
        stdoutln!("# refused: {} — {}", refusal.var, refusal.reason)?;
    }
    print_existing(&plan.exports)
}

fn print_existing(exports: &[RelocateExport]) -> Result<()> {
    stdoutln!("# existing data remains at the locations below; migrate manually if desired:")?;
    for export in exports {
        if export.current.is_empty() {
            stdoutln!("# {}: none found", export.label)?;
        } else {
            for root in &export.current {
                stdoutln!("# {}: {}", export.label, sh_comment(root))?;
            }
        }
    }
    Ok(())
}

fn print_commands(exports: &[RelocateExport]) -> Result<()> {
    if exports.is_empty() {
        return Ok(());
    }
    stdoutln!("if")?;
    let mut directories = exports.iter().peekable();
    while let Some(export) = directories.next() {
        let suffix = if directories.peek().is_some() {
            " &&"
        } else {
            ""
        };
        stdoutln!("  mkdir -p {}{suffix}", sh_double_quote(&export.value))?;
    }
    stdoutln!("then")?;
    for export in exports {
        stdoutln!("  export {}={}", export.var, sh_double_quote(&export.value))?;
        stdoutln!("  [ \"$?\" -eq 0 ] || return 1 2>/dev/null || exit 1")?;
    }
    stdoutln!("else\n  false\nfi")
}

fn sh_comment(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() || character == '\\' {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn sh_double_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + SHELL_QUOTE_DELIMITERS);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '$' | '`' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}
