use crate::cli::{ReclaimCommand, ReclaimUvArgs};
use crate::commands::prompt::confirm_native_reclaim;
use crate::configuration::load_config;
use crate::native::{
    ActionId, ActionKind, ActionResultOwner, CapturedOutput, NativeRunOutcome, NativeRunReport,
    NativeRunnerError, NotStartedReason, QuotaActionReport, json as observation_json,
    not_attempted_action,
};
use crate::output::{flush_stdout, stdout_closed_error, stdout_consumer_gone, stdoutln};
use crate::presentation::{Severity, escape_terminal_text, print_stderr_note};
use crate::runtime::Ui;
use crate::selection::SourceSelection;
use crate::uv::{
    ACTION_ID, PreparedUvPrunePlan, UvCacheRootSelection, UvPruneOutputError, UvPruneSummary,
    prepare_uv_prune_plan,
};
use anyhow::{Result, anyhow};
use degu_adapters::RegisteredAdapter;
use degu_adapters::native::{NativeExecutableSelection, NativeInheritedEnvironment};
use degu_core::ecosystem::DetectCtx;
use serde::Serialize;
use std::fmt::Write as _;
use std::io::IsTerminal;
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

struct PreparedReclaim {
    ctx: DetectCtx,
    registration: RegisteredAdapter,
    plan: PreparedUvPrunePlan,
}

fn run_uv(args: ReclaimUvArgs, ui: Ui) -> Result<()> {
    validate_mode(&args)?;
    let selections = ExplicitSelections::new(args.executable, args.cache_dir)?;
    if stdout_consumer_gone() {
        return Err(stdout_closed_error());
    }
    if !args.dry_run && !args.yes && !std::io::stdin().is_terminal() {
        anyhow::bail!("uv cache prune requires --yes when stdin is not a terminal");
    }
    if args.dry_run && args.yes {
        print_stderr_note(
            Severity::Warning,
            "--yes has no effect in a dry run.",
            ui.colors,
        );
    }

    let prepared = prepare_reclaim(selections)?;
    prepared.plan.revalidate()?;
    let details = plan_details(&prepared.plan)?;

    if args.dry_run {
        let document = preview_document(details, &prepared.plan)?;
        return if args.output.json {
            stdoutln!("{}", serde_json::to_string_pretty(&document)?)
        } else {
            stdoutln!("{}", render_plan_human(&document.details, true))
        };
    }

    if !args.output.json {
        stdoutln!("{}", render_plan_human(&details, false))?;
        flush_stdout()?;
        if stdout_consumer_gone() {
            return Err(stdout_closed_error());
        }
        if !args.yes && !confirm_native_reclaim(ui.colors)? {
            anyhow::bail!("uv cache prune cancelled; no native reclaim action was started");
        }
        // Re-establish the human stdout boundary after an arbitrarily long
        // confirmation delay. A failed write prevents the mutation transition.
        stdoutln!("Starting irreversible uv cache prune.")?;
        flush_stdout()?;
        if stdout_consumer_gone() {
            return Err(stdout_closed_error());
        }
    }
    // JSON emits no pre-mutation bytes, but `poll` still observes a pipe/socket
    // whose reader is already gone. Keep this common guard immediately before
    // the consuming transition for both output modes.
    if stdout_consumer_gone() {
        return Err(stdout_closed_error());
    }

    // Confirmation is complete. This consuming transition repeats executable
    // and root checks, requires an exact production-registry declaration, and
    // moves the held root seal into the runner's final pre-spawn binding.
    let execution = prepared
        .plan
        .into_execution(&prepared.registration, &prepared.ctx)?;
    let completed = execution.execute();
    let (native, observation) = completed.into_parts();
    let observation = QuotaActionReport::Attempted(observation);
    let cache_prune = execution_outcome(&native);
    let succeeded = cache_prune.status == "success";
    let failure = cache_prune
        .error
        .clone()
        .unwrap_or_else(|| format!("terminal status {}", cache_prune.status));
    let document = ExecutionDocument {
        schema_version: SCHEMA_VERSION,
        command: "reclaim.uv",
        adapter: "uv",
        action: ACTION_ID,
        mode: "execute",
        details,
        cache_prune,
        quota_observations: observation_json(&observation),
    };

    let output_result = if args.output.json {
        crate::native::print_warnings(&observation, ui.colors);
        stdoutln!("{}", serde_json::to_string_pretty(&document)?)
    } else {
        stdoutln!("{}", render_execution_human(&document))
            .and_then(|()| crate::native::print_human(&observation, ui.colors))
    };
    finish_execution_output(output_result, succeeded, &failure)
}

fn finish_execution_output(
    output_result: Result<()>,
    succeeded: bool,
    failure: &str,
) -> Result<()> {
    if !succeeded {
        // A real native failure, particularly unconfirmed termination, must not
        // be converted to process success merely because its final consumer
        // also disappeared. The bounded result was already attempted.
        drop(output_result);
        anyhow::bail!("uv cache prune did not complete successfully: {failure}");
    }
    output_result
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
        anyhow!("{label} is not valid UTF-8 and cannot be represented in reclaim output")
    })
}

fn prepare_reclaim(selections: ExplicitSelections) -> Result<PreparedReclaim> {
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
    require_representable(plan.canonical_cache_root(), "canonical uv cache root")?;
    Ok(PreparedReclaim {
        ctx,
        registration,
        plan,
    })
}

fn uv_registration() -> Result<RegisteredAdapter> {
    degu_adapters::all()
        .into_iter()
        .find(|registration| registration.id() == "uv")
        .ok_or_else(|| anyhow!("uv adapter is not registered"))
}

fn plan_details(plan: &PreparedUvPrunePlan) -> Result<PlanDetails> {
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
    Ok(PlanDetails {
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
    })
}

fn preview_document(details: PlanDetails, plan: &PreparedUvPrunePlan) -> Result<PreviewDocument> {
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
        details,
        cache_prune: OutcomePreview {
            start: "not_started",
            status: "dry_run",
        },
        quota_observations: observation_json(&observation),
    })
}

#[derive(Clone, Debug, Serialize)]
struct PlanDetails {
    probe: ProbePreview,
    cache_root: CacheRootPreview,
    invocation: InvocationPreview,
    deletion_scope: Vec<&'static str>,
    exact_item_preview_available: bool,
    reversible_by_degu: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ProbePreview {
    attempted: bool,
    selected_executable: String,
    arguments: Vec<String>,
    version: String,
    uses_private_temporary_snapshot: bool,
}

#[derive(Clone, Debug, Serialize)]
struct CacheRootPreview {
    selected: String,
    canonical: String,
}

#[derive(Clone, Debug, Serialize)]
struct InvocationPreview {
    executable: &'static str,
    arguments: Vec<String>,
    inherited_environment: &'static str,
    fixed_environment: Vec<EnvironmentEntry>,
}

#[derive(Clone, Debug, Serialize)]
struct EnvironmentEntry {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct PreviewDocument {
    schema_version: u32,
    command: &'static str,
    adapter: &'static str,
    action: &'static str,
    mode: &'static str,
    #[serde(flatten)]
    details: PlanDetails,
    cache_prune: OutcomePreview,
    quota_observations: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OutcomePreview {
    start: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ExecutionDocument {
    schema_version: u32,
    command: &'static str,
    adapter: &'static str,
    action: &'static str,
    mode: &'static str,
    #[serde(flatten)]
    details: PlanDetails,
    cache_prune: ExecutionOutcome,
    quota_observations: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ExecutionOutcome {
    start: &'static str,
    status: &'static str,
    mutation_state: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    summary: Option<UvPruneSummary>,
    summary_is_authoritative_quota_attribution: bool,
    stdout: Option<CapturedStream>,
    stderr: Option<CapturedStream>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CapturedStream {
    encoding: &'static str,
    content: String,
    bytes_captured: usize,
    truncated: bool,
}

impl CapturedStream {
    fn from_capture(captured: &CapturedOutput) -> Self {
        match std::str::from_utf8(captured.bytes()) {
            Ok(text) => Self {
                encoding: "utf8",
                content: text.to_owned(),
                bytes_captured: captured.bytes().len(),
                truncated: captured.truncated(),
            },
            Err(_) => {
                let mut content = String::with_capacity(captured.bytes().len() * 2);
                for byte in captured.bytes() {
                    write!(&mut content, "{byte:02x}").expect("writing to String cannot fail");
                }
                Self {
                    encoding: "hex",
                    content,
                    bytes_captured: captured.bytes().len(),
                    truncated: captured.truncated(),
                }
            }
        }
    }
}

fn execution_outcome(
    execution: &Result<NativeRunReport<UvPruneSummary, UvPruneOutputError>, NativeRunnerError>,
) -> ExecutionOutcome {
    match execution {
        Err(error) => ExecutionOutcome {
            start: "started",
            status: "runner_error",
            mutation_state: "may_have_completed_or_partially_modified_cache",
            exit_code: None,
            signal: None,
            summary: None,
            summary_is_authoritative_quota_attribution: false,
            stdout: None,
            stderr: None,
            error: Some(error.to_string()),
        },
        Ok(report) => {
            let (status, exit_code, signal, summary, error) = match report.outcome() {
                NativeRunOutcome::Success(summary) => {
                    ("success", None, None, Some(summary.clone()), None)
                }
                NativeRunOutcome::ExitFailure { code } => (
                    "exit_failure",
                    *code,
                    None,
                    None,
                    Some(format!("uv exited unsuccessfully with code {code:?}")),
                ),
                NativeRunOutcome::Signal { signal } => (
                    "signal",
                    None,
                    *signal,
                    None,
                    Some(format!("uv terminated by signal {signal:?}")),
                ),
                NativeRunOutcome::Timeout => (
                    "timeout",
                    None,
                    None,
                    None,
                    Some("uv exceeded the 250-second execution timeout".to_owned()),
                ),
                NativeRunOutcome::OutputTruncated => (
                    "output_truncated",
                    None,
                    None,
                    None,
                    Some("uv output exceeded the fixed 64-KiB capture bound".to_owned()),
                ),
                NativeRunOutcome::OutputParseFailure(error) => (
                    "output_parse_failure",
                    None,
                    None,
                    None,
                    Some(error.to_string()),
                ),
            };
            ExecutionOutcome {
                start: "started",
                status,
                mutation_state: if status == "success" {
                    "completed"
                } else {
                    "may_have_completed_or_partially_modified_cache"
                },
                exit_code,
                signal,
                summary,
                summary_is_authoritative_quota_attribution: false,
                stdout: Some(CapturedStream::from_capture(report.stdout())),
                stderr: Some(CapturedStream::from_capture(report.stderr())),
                error,
            }
        }
    }
}

fn render_plan_human(details: &PlanDetails, dry_run: bool) -> String {
    let executable = escape_terminal_text(&details.probe.selected_executable);
    let selected_cache_root = escape_terminal_text(&details.cache_root.selected);
    let canonical_cache_root = escape_terminal_text(&details.cache_root.canonical);
    let version = escape_terminal_text(&details.probe.version);
    let arguments = details
        .invocation
        .arguments
        .iter()
        .map(|argument| format!("    {}", escape_terminal_text(argument)))
        .collect::<Vec<_>>()
        .join("\n");
    let heading = if dry_run {
        "Native reclaim preview (dry run)"
    } else {
        "Native reclaim plan (irreversible)"
    };
    let ending = if dry_run {
        "No uv cache prune action was started."
    } else {
        "Execution requires --yes or typing `prune` at the confirmation prompt."
    };
    format!(
        "{heading}\n\
Adapter: uv\n\
Action: cache prune\n\
Selected executable: {executable}\n\
Validated version: {version}\n\
Selected cache root: {selected_cache_root}\n\
Sealed canonical cache root: {canonical_cache_root}\n\
Version probe: a private temporary snapshot was created and the selected executable was started with only `-V`; prune was not run during validation. The selected binary is not sandboxed, so validation constrains its invocation but cannot promise that arbitrary binary bytes have no side effects.\n\
Fixed invocation executable: private snapshot of the selected executable\n\
Fixed invocation arguments:\n{arguments}\n\
Environment: inherited environment cleared; UV_LOCK_TIMEOUT=240\n\
Potential deletion scope: stale top-level cache entries, cached environments, stale source revisions, and unreferenced archives.\n\
No exact item list or reclaimed-byte estimate is available. This native operation bypasses degu trash and cannot be restored by degu undo.\n\
{ending}"
    )
}

fn render_execution_human(document: &ExecutionDocument) -> String {
    let outcome = &document.cache_prune;
    let mut lines = vec![
        "Native reclaim result".to_owned(),
        "Adapter: uv".to_owned(),
        "Action: cache prune".to_owned(),
        format!("Status: {}", outcome.status),
    ];
    if let Some(summary) = &outcome.summary {
        let mut reported = match summary.removal_kind {
            "none" => "uv reported no unused entries.".to_owned(),
            kind => format!("uv reported {} removed {}.", summary.removal_count, kind),
        };
        if let Some(size) = &summary.reported_size {
            let qualifier = if summary.reported_size_is_lower_bound {
                "at least "
            } else {
                ""
            };
            write!(&mut reported, " Reported size: {qualifier}{size}.")
                .expect("writing to String cannot fail");
        }
        reported.push_str(" This is uv's bounded summary, not authoritative quota attribution.");
        lines.push(reported);
        if summary.waited_for_lock {
            lines.push("uv waited for another cache user before pruning.".to_owned());
        }
    }
    if let Some(error) = &outcome.error {
        lines.push(format!("Failure: {}", escape_terminal_text(error)));
        if outcome.status == "output_parse_failure" {
            lines.push(
                "uv exited successfully, but its bounded output did not match the audited uv 0.12.3 contract; prune may already have completed."
                    .to_owned(),
            );
        }
        lines.push(
            "uv cache prune may already have modified the cache; this failure does not imply rollback. Inspect the cache before retrying."
                .to_owned(),
        );
    }
    if outcome.status != "success"
        && let Some(stderr) = &outcome.stderr
        && !stderr.content.is_empty()
    {
        lines.push(format!(
            "Captured uv stderr ({}): {}",
            stderr.encoding,
            escape_terminal_text(&stderr.content)
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::JsonArgs;
    use degu_core::ecosystem::Root;

    fn args(json: bool, dry_run: bool, yes: bool) -> ReclaimUvArgs {
        ReclaimUvArgs {
            output: JsonArgs { json },
            executable: PathBuf::from("/opt/uv/bin/uv"),
            cache_dir: PathBuf::from("/scratch/alice/uv"),
            dry_run,
            yes,
        }
    }

    fn details() -> PlanDetails {
        PlanDetails {
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
        }
    }

    fn document() -> PreviewDocument {
        PreviewDocument {
            schema_version: SCHEMA_VERSION,
            command: "reclaim.uv",
            adapter: "uv",
            action: ACTION_ID,
            mode: "dry_run",
            details: details(),
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
    fn non_utf8_paths_are_refused_before_output_serialization() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/cache/\xff".to_vec()));
        let error = require_representable(&path, "canonical uv cache root").unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn production_registry_exposes_only_fixed_uv_prune() {
        let ctx = DetectCtx::for_test(
            PathBuf::from("/home/alice"),
            [] as [(std::ffi::OsString, std::ffi::OsString); 0],
        );
        let selection =
            NativeExecutableSelection::explicit(PathBuf::from("/opt/uv/bin/uv")).unwrap();
        let root = Root::well_known(PathBuf::from("/scratch/alice/uv"));
        let mut declared = degu_adapters::all()
            .into_iter()
            .filter_map(|registration| {
                registration
                    .declare_native_cleanup(&ctx, std::slice::from_ref(&root), &selection)
                    .transpose()
                    .map(|result| (registration.id(), result))
            })
            .collect::<Vec<_>>();
        assert_eq!(declared.len(), 1);
        let (adapter, request) = declared.pop().unwrap();
        let request = request.unwrap();
        assert_eq!(adapter, "uv");
        assert_eq!(request.identity().action_id(), ACTION_ID);
        assert_eq!(
            request.observation_requests(),
            [PathBuf::from("/scratch/alice/uv")]
        );
    }

    #[test]
    fn dry_run_and_json_confirmation_rules_are_explicit() {
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
        assert_eq!(value["cache_prune"]["start"], "not_started");
        assert_eq!(value["cache_prune"]["status"], "dry_run");
    }

    #[test]
    fn native_failure_dominates_final_closed_consumer_but_success_keeps_pipe_contract() {
        let failure = finish_execution_output(
            Err(crate::output::stdout_closed_error()),
            false,
            "termination unconfirmed",
        )
        .unwrap_err();
        assert!(!crate::output::is_stdout_closed(&failure));
        assert!(failure.to_string().contains("termination unconfirmed"));

        let success =
            finish_execution_output(Err(crate::output::stdout_closed_error()), true, "unused")
                .unwrap_err();
        assert!(crate::output::is_stdout_closed(&success));
    }

    #[test]
    fn every_runner_failure_warns_that_cache_may_already_be_modified() {
        let execution: Result<NativeRunReport<UvPruneSummary, UvPruneOutputError>, _> = Err(
            NativeRunnerError::MutationBinding("root changed".to_owned()),
        );
        let outcome = execution_outcome(&execution);
        assert_eq!(outcome.status, "runner_error");
        assert_eq!(
            outcome.mutation_state,
            "may_have_completed_or_partially_modified_cache"
        );
        let document = ExecutionDocument {
            schema_version: SCHEMA_VERSION,
            command: "reclaim.uv",
            adapter: "uv",
            action: ACTION_ID,
            mode: "execute",
            details: details(),
            cache_prune: outcome,
            quota_observations: serde_json::json!({}),
        };
        let human = render_execution_human(&document);
        assert!(human.contains("may already have modified the cache"));
        assert!(human.contains("failure does not imply rollback"));
        assert!(human.contains("Inspect the cache before retrying"));
    }

    #[test]
    fn every_started_terminal_failure_has_conservative_json_and_human_semantics() {
        let cases = [
            (
                NativeRunOutcome::ExitFailure { code: Some(7) },
                "exit_failure",
            ),
            (
                NativeRunOutcome::Signal {
                    signal: Some(libc::SIGTERM),
                },
                "signal",
            ),
            (NativeRunOutcome::Timeout, "timeout"),
            (NativeRunOutcome::OutputTruncated, "output_truncated"),
            (
                NativeRunOutcome::OutputParseFailure(UvPruneOutputError::InvalidShape),
                "output_parse_failure",
            ),
        ];
        for (native_outcome, expected_status) in cases {
            let report = NativeRunReport::for_test(
                native_outcome,
                CapturedOutput::for_test(Vec::new(), false, 64),
                CapturedOutput::for_test(b"bounded diagnostic\n".to_vec(), false, 64),
            );
            let execution = Ok(report);
            let outcome = execution_outcome(&execution);
            assert_eq!(outcome.status, expected_status);
            assert_eq!(
                outcome.mutation_state,
                "may_have_completed_or_partially_modified_cache"
            );
            let document = ExecutionDocument {
                schema_version: SCHEMA_VERSION,
                command: "reclaim.uv",
                adapter: "uv",
                action: ACTION_ID,
                mode: "execute",
                details: details(),
                cache_prune: outcome,
                quota_observations: serde_json::json!({
                    "observation_state": "resolved",
                    "owner": {"native_adapter": "uv"},
                    "kind": "native",
                    "id": "cache-prune",
                    "quota_observations": []
                }),
            };
            let value = serde_json::to_value(&document).unwrap();
            assert_eq!(value["cache_prune"]["start"], "started");
            assert_eq!(value["cache_prune"]["status"], expected_status);
            assert_eq!(
                value["cache_prune"]["mutation_state"],
                "may_have_completed_or_partially_modified_cache"
            );
            assert_eq!(value["quota_observations"]["observation_state"], "resolved");
            let human = render_execution_human(&document);
            assert!(human.contains("may already have modified the cache"));
            assert!(human.contains("failure does not imply rollback"));
            if expected_status == "output_parse_failure" {
                assert!(human.contains("uv exited successfully"));
                assert!(human.contains("prune may already have completed"));
            }
        }
    }

    #[test]
    fn execution_json_freezes_terminal_and_non_attribution_fields() {
        let document = ExecutionDocument {
            schema_version: SCHEMA_VERSION,
            command: "reclaim.uv",
            adapter: "uv",
            action: ACTION_ID,
            mode: "execute",
            details: details(),
            cache_prune: ExecutionOutcome {
                start: "started",
                status: "success",
                mutation_state: "completed",
                exit_code: None,
                signal: None,
                summary: Some(UvPruneSummary {
                    waited_for_lock: true,
                    removal_kind: "files",
                    removal_count: 3,
                    reported_size: Some("1.0MiB".to_owned()),
                    reported_size_is_lower_bound: false,
                }),
                summary_is_authoritative_quota_attribution: false,
                stdout: Some(CapturedStream {
                    encoding: "utf8",
                    content: String::new(),
                    bytes_captured: 0,
                    truncated: false,
                }),
                stderr: Some(CapturedStream {
                    encoding: "utf8",
                    content: "Pruning cache at: /scratch/alice/uv\nRemoved 3 files (1.0MiB)\n"
                        .to_owned(),
                    bytes_captured: 72,
                    truncated: false,
                }),
                error: None,
            },
            quota_observations: serde_json::json!({
                "observation_state": "resolved",
                "owner": {"native_adapter": "uv"},
                "kind": "native",
                "id": "cache-prune",
                "quota_observations": []
            }),
        };
        let value = serde_json::to_value(&document).unwrap();
        assert_eq!(value["mode"], "execute");
        assert_eq!(value["cache_prune"]["start"], "started");
        assert_eq!(value["cache_prune"]["status"], "success");
        assert_eq!(value["cache_prune"]["mutation_state"], "completed");
        assert_eq!(value["cache_prune"]["summary"]["removal_count"], 3);
        assert_eq!(
            value["cache_prune"]["summary_is_authoritative_quota_attribution"],
            false
        );
        assert_eq!(value["quota_observations"]["observation_state"], "resolved");
        let human = render_execution_human(&document);
        assert!(human.contains("not authoritative quota attribution"));
        assert!(human.contains("waited for another cache user"));
    }

    #[test]
    fn human_preview_discloses_probe_and_never_claims_reclaimed_space() {
        let output = render_plan_human(&details(), true);
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
    fn human_plan_escapes_terminal_controls_in_paths_and_arguments() {
        let mut details = details();
        details.probe.selected_executable = "/opt/uv\u{1b}[31m".to_owned();
        details.invocation.arguments[6] = "/cache\nother".to_owned();
        let output = render_plan_human(&details, false);
        assert!(output.contains("/opt/uv\\u{1b}[31m"));
        assert!(output.contains("/cache\\nother"));
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("typing `prune`"));
    }

    #[test]
    fn binary_native_output_is_losslessly_hex_encoded() {
        let captured = CapturedOutput::for_test(vec![0xff, 0x00, b'a'], false, 16);
        let stream = CapturedStream::from_capture(&captured);
        assert_eq!(stream.encoding, "hex");
        assert_eq!(stream.content, "ff0061");
        assert_eq!(stream.bytes_captured, 3);
    }
}
