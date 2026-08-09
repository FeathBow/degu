use crate::action_result::{ActionId, ActionKind, ActionResultOwner, NotStartedReason};
use crate::cli::{ReclaimCommand, ReclaimUvArgs};
use crate::configuration::load_config;
use crate::output::stdoutln;
use crate::presentation::{Severity, escape_terminal_text, print_stderr_note};
use crate::quota_observation::{json as observation_json, not_attempted_action};
use crate::runtime::Ui;
use crate::source_selection::SourceSelection;
use crate::uv_cache_root::UvCacheRootSelection;
use crate::uv_prune_plan::{ACTION_ID, PreparedUvPrunePlan, prepare_uv_prune_plan};
use anyhow::{Result, anyhow};
use degu_adapters::RegisteredAdapter;
use degu_adapters::native::{NativeExecutableSelection, NativeInheritedEnvironment};
use degu_core::ecosystem::DetectCtx;
use serde::Serialize;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;

pub(crate) fn run(command: ReclaimCommand, ui: Ui) -> Result<()> {
    match command {
        ReclaimCommand::Uv(args) => run_uv(args, ui),
    }
}

struct ExplicitSelections {
    executable: NativeExecutableSelection,
    cache_root: UvCacheRootSelection,
}

impl ExplicitSelections {
    fn new(executable: PathBuf, cache_root: PathBuf) -> Result<Self> {
        require_representable(&executable, "uv executable")?;
        require_representable(&cache_root, "uv cache root")?;
        Ok(Self {
            executable: NativeExecutableSelection::explicit(executable)?,
            cache_root: UvCacheRootSelection::explicit(cache_root)?,
        })
    }
}

/// Preview-only: renders the validated plan — the bounded `uv -V` snapshot, the
/// sealed cache root, and the fixed request — and refuses to execute prune.
fn run_uv(args: ReclaimUvArgs, ui: Ui) -> Result<()> {
    validate_mode(&args)?;
    let selections = ExplicitSelections::new(args.executable, args.cache_dir)?;
    if !args.dry_run {
        anyhow::bail!(
            "uv reclaim execution is not available in this build; use --dry-run to validate and preview the exact action"
        );
    }
    if args.yes {
        print_stderr_note(
            Severity::Warning,
            "--yes has no effect in a dry run.",
            ui.colors,
        );
    }

    let prepared = prepare_preview(selections)?;
    prepared.revalidate()?;
    let document = preview_document(&prepared)?;
    if args.output.json {
        stdoutln!("{}", serde_json::to_string_pretty(&document)?)
    } else {
        stdoutln!("{}", render_human(&document))
    }
}

fn validate_mode(args: &ReclaimUvArgs) -> Result<()> {
    if args.output.json && !args.dry_run && !args.yes {
        anyhow::bail!("--json requires --yes or --dry-run");
    }
    Ok(())
}

fn require_representable(path: &Path, label: &str) -> Result<()> {
    representable_text(path, label).map(drop)
}

fn representable_text(path: &Path, label: &str) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        anyhow!("{label} is not valid UTF-8 and cannot be represented in the reclaim preview")
    })
}

fn preview_document(plan: &PreparedUvPrunePlan) -> Result<PreviewDocument> {
    let executable = representable_text(plan.selected_executable(), "selected uv executable")?;
    let selected_cache_root =
        representable_text(plan.selected_cache_root(), "selected uv cache root")?;
    let canonical_cache_root =
        representable_text(plan.canonical_cache_root(), "canonical uv cache root")?;
    let arguments = plan
        .arguments()
        .iter()
        .enumerate()
        .map(|(index, argument)| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("fixed uv prune argument {index} is not valid UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    if !matches!(
        plan.inherited_environment(),
        NativeInheritedEnvironment::Clear
    ) {
        anyhow::bail!("fixed uv prune plan unexpectedly inherits environment variables");
    }
    let fixed_environment = plan
        .fixed_environment()
        .iter()
        .map(|(name, value)| {
            Ok(EnvironmentEntry {
                name: name
                    .to_str()
                    .ok_or_else(|| anyhow!("fixed uv prune environment name is not UTF-8"))?
                    .to_owned(),
                value: value
                    .to_str()
                    .ok_or_else(|| anyhow!("fixed uv prune environment value is not UTF-8"))?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let observation = not_attempted_action(
        ActionResultOwner::NativeAdapter {
            adapter_id: ActionId::new("uv")
                .map_err(|error| anyhow!("invalid static uv action owner: {error:?}"))?,
        },
        ActionKind::Native,
        ACTION_ID,
        [plan.canonical_cache_root().to_path_buf()],
        NotStartedReason::DryRun,
    )
    .map_err(|error| anyhow!("invalid uv dry-run observation contract: {error:?}"))?;
    Ok(PreviewDocument {
        schema_version: SCHEMA_VERSION,
        command: "reclaim.uv",
        adapter: "uv",
        action: ACTION_ID,
        mode: "dry_run",
        probe: ProbePreview {
            attempted: true,
            selected_executable: executable,
            arguments: vec!["-V".to_owned()],
            version: plan.version().to_string(),
            uses_private_temporary_snapshot: true,
        },
        cache_root: CacheRootPreview {
            selected: selected_cache_root,
            canonical: canonical_cache_root,
        },
        invocation: InvocationPreview {
            executable: "private_snapshot_of_selected_executable",
            arguments,
            inherited_environment: "clear",
            fixed_environment,
        },
        deletion_scope: vec![
            "stale top-level cache entries",
            "cached environments",
            "stale source revisions",
            "unreferenced archives",
        ],
        exact_item_preview_available: false,
        reversible_by_degu: false,
        cache_prune: OutcomePreview {
            start: "not_started",
            status: "dry_run",
        },
        quota_observations: observation_json(&observation),
    })
}

fn prepare_preview(selections: ExplicitSelections) -> Result<PreparedUvPrunePlan> {
    let ctx = DetectCtx::from_process()?;
    let config = load_config(&ctx)?;
    SourceSelection::from_only(&["uv".to_owned()], false, &config.disable)?;
    let registration = uv_registration()?;
    let plan = prepare_uv_prune_plan(
        &registration,
        &ctx,
        selections.executable,
        selections.cache_root,
    )?;
    Ok(plan)
}

fn uv_registration() -> Result<RegisteredAdapter> {
    degu_adapters::all()
        .into_iter()
        .find(|registration| registration.id() == "uv")
        .ok_or_else(|| anyhow!("uv adapter is not registered"))
}

#[derive(Debug, Serialize)]
struct PreviewDocument {
    schema_version: u32,
    command: &'static str,
    adapter: &'static str,
    action: &'static str,
    mode: &'static str,
    probe: ProbePreview,
    cache_root: CacheRootPreview,
    invocation: InvocationPreview,
    deletion_scope: Vec<&'static str>,
    exact_item_preview_available: bool,
    reversible_by_degu: bool,
    cache_prune: OutcomePreview,
    quota_observations: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ProbePreview {
    attempted: bool,
    selected_executable: String,
    arguments: Vec<String>,
    version: String,
    uses_private_temporary_snapshot: bool,
}

#[derive(Debug, Serialize)]
struct CacheRootPreview {
    selected: String,
    canonical: String,
}

#[derive(Debug, Serialize)]
struct InvocationPreview {
    executable: &'static str,
    arguments: Vec<String>,
    inherited_environment: &'static str,
    fixed_environment: Vec<EnvironmentEntry>,
}

#[derive(Debug, Serialize)]
struct EnvironmentEntry {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct OutcomePreview {
    start: &'static str,
    status: &'static str,
}

fn render_human(document: &PreviewDocument) -> String {
    let executable = escape_terminal_text(&document.probe.selected_executable);
    let selected_cache_root = escape_terminal_text(&document.cache_root.selected);
    let canonical_cache_root = escape_terminal_text(&document.cache_root.canonical);
    let version = escape_terminal_text(&document.probe.version);
    let arguments = document
        .invocation
        .arguments
        .iter()
        .map(|argument| format!("    {}", escape_terminal_text(argument)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Native reclaim preview (dry run)\n\
Adapter: uv\n\
Action: cache prune\n\
Selected executable: {executable}\n\
Validated version: {version}\n\
Selected cache root: {selected_cache_root}\n\
Sealed canonical cache root: {canonical_cache_root}\n\
Version probe: a private temporary snapshot was created and the selected executable was started with only `-V`; prune was not run. The selected binary is not sandboxed, so this preview constrains its invocation but cannot promise that arbitrary binary bytes have no side effects.\n\
Fixed invocation executable: private snapshot of the selected executable\n\
Fixed invocation arguments:\n{arguments}\n\
Environment: inherited environment cleared; UV_LOCK_TIMEOUT=240\n\
Potential deletion scope: stale top-level cache entries, cached environments, stale source revisions, and unreferenced archives.\n\
No exact item list or reclaimed-byte estimate is available. This native operation bypasses degu trash and cannot be restored by degu undo.\n\
No uv cache prune action was started."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::JsonArgs;

    fn args(json: bool, dry_run: bool, yes: bool) -> ReclaimUvArgs {
        ReclaimUvArgs {
            output: JsonArgs { json },
            executable: PathBuf::from("/opt/uv/bin/uv"),
            cache_dir: PathBuf::from("/scratch/alice/uv"),
            dry_run,
            yes,
        }
    }

    fn document() -> PreviewDocument {
        PreviewDocument {
            schema_version: SCHEMA_VERSION,
            command: "reclaim.uv",
            adapter: "uv",
            action: ACTION_ID,
            mode: "dry_run",
            probe: ProbePreview {
                attempted: true,
                selected_executable: "/opt/uv/bin/uv".to_owned(),
                arguments: vec!["-V".to_owned()],
                version: "0.12.3".to_owned(),
                uses_private_temporary_snapshot: true,
            },
            cache_root: CacheRootPreview {
                selected: "/scratch/alice/uv-link".to_owned(),
                canonical: "/scratch/alice/uv".to_owned(),
            },
            invocation: InvocationPreview {
                executable: "private_snapshot_of_selected_executable",
                arguments: vec![
                    "--no-config".to_owned(),
                    "--color".to_owned(),
                    "never".to_owned(),
                    "--no-progress".to_owned(),
                    "--offline".to_owned(),
                    "--cache-dir".to_owned(),
                    "/scratch/alice/uv".to_owned(),
                    "cache".to_owned(),
                    "prune".to_owned(),
                ],
                inherited_environment: "clear",
                fixed_environment: vec![EnvironmentEntry {
                    name: "UV_LOCK_TIMEOUT".to_owned(),
                    value: "240".to_owned(),
                }],
            },
            deletion_scope: vec![
                "stale top-level cache entries",
                "cached environments",
                "stale source revisions",
                "unreferenced archives",
            ],
            exact_item_preview_available: false,
            reversible_by_degu: false,
            cache_prune: OutcomePreview {
                start: "not_started",
                status: "dry_run",
            },
            quota_observations: serde_json::json!({
                "observation_state": "not_attempted",
                "owner": {"native_adapter": "uv"},
                "kind": "native",
                "id": "cache-prune",
                "quota_observations": [{
                    "anchors": ["/scratch/alice/uv"],
                    "quota_observed_usage_delta": {"state": "not_attempted"}
                }]
            }),
        }
    }

    #[test]
    fn non_utf8_paths_are_refused_before_preview_serialization() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/cache/\xff".to_vec()));
        let error = require_representable(&path, "canonical uv cache root").unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn production_registry_stays_without_native_capabilities() {
        let ctx = DetectCtx::for_test(
            PathBuf::from("/home/alice"),
            [] as [(std::ffi::OsString, std::ffi::OsString); 0],
        );
        let selection =
            NativeExecutableSelection::explicit(PathBuf::from("/opt/uv/bin/uv")).unwrap();
        for registration in degu_adapters::all() {
            assert!(
                registration
                    .declare_native_cleanup(&ctx, &[], &selection)
                    .unwrap()
                    .is_none(),
                "{} unexpectedly registered native execution",
                registration.id()
            );
        }
    }

    #[test]
    fn dry_run_and_future_json_confirmation_rules_are_explicit() {
        assert!(validate_mode(&args(false, true, false)).is_ok());
        assert!(validate_mode(&args(true, true, false)).is_ok());
        assert!(validate_mode(&args(true, false, true)).is_ok());
        let error = validate_mode(&args(true, false, false)).unwrap_err();
        assert_eq!(error.to_string(), "--json requires --yes or --dry-run");
    }

    #[test]
    fn preview_json_freezes_probe_invocation_and_not_started_state() {
        let value = serde_json::to_value(document()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["command"], "reclaim.uv");
        assert_eq!(value["adapter"], "uv");
        assert_eq!(value["action"], "cache-prune");
        assert_eq!(value["mode"], "dry_run");
        assert_eq!(value["probe"]["attempted"], true);
        assert_eq!(value["probe"]["arguments"], serde_json::json!(["-V"]));
        assert_eq!(value["probe"]["version"], "0.12.3");
        assert_eq!(value["probe"]["uses_private_temporary_snapshot"], true);
        assert_eq!(
            value["invocation"]["arguments"],
            serde_json::json!([
                "--no-config",
                "--color",
                "never",
                "--no-progress",
                "--offline",
                "--cache-dir",
                "/scratch/alice/uv",
                "cache",
                "prune"
            ])
        );
        assert_eq!(value["cache_root"]["selected"], "/scratch/alice/uv-link");
        assert_eq!(value["cache_root"]["canonical"], "/scratch/alice/uv");
        assert_eq!(value["invocation"]["inherited_environment"], "clear");
        assert_eq!(value["exact_item_preview_available"], false);
        assert_eq!(value["reversible_by_degu"], false);
        assert_eq!(
            value["quota_observations"]["observation_state"],
            "not_attempted"
        );
        assert_eq!(value["quota_observations"]["owner"]["native_adapter"], "uv");
        assert_eq!(value["quota_observations"]["kind"], "native");
        assert_eq!(value["quota_observations"]["id"], "cache-prune");
        assert_eq!(
            value["quota_observations"]["quota_observations"][0]["quota_observed_usage_delta"]["state"],
            "not_attempted"
        );
        assert_eq!(value["cache_prune"]["start"], "not_started");
        assert_eq!(value["cache_prune"]["status"], "dry_run");
    }

    #[test]
    fn human_preview_discloses_probe_and_never_claims_reclaimed_space() {
        let output = render_human(&document());
        assert!(output.contains("Native reclaim preview (dry run)"));
        assert!(output.contains("selected executable was started with only `-V`"));
        assert!(output.contains("selected binary is not sandboxed"));
        assert!(output.contains("No uv cache prune action was started."));
        assert!(output.contains("bypasses degu trash"));
        assert!(output.contains("cannot be restored by degu undo"));
        assert!(output.contains("UV_LOCK_TIMEOUT=240"));
        assert!(output.contains("No exact item list or reclaimed-byte estimate is available."));
        assert!(!output.contains("Bytes reclaimed:"));
        assert!(!output.contains("Space freed:"));
    }

    #[test]
    fn human_preview_escapes_terminal_controls_in_paths_and_arguments() {
        let mut document = document();
        document.probe.selected_executable = "/opt/uv\u{1b}[31m".to_owned();
        document.invocation.arguments[6] = "/cache\nother".to_owned();
        let output = render_human(&document);
        assert!(output.contains("/opt/uv\\u{1b}[31m"));
        assert!(output.contains("/cache\\nother"));
        assert!(!output.contains('\u{1b}'));
    }
}
