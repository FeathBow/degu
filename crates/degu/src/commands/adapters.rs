use anyhow::Result;

/// One-line descriptions for the built-in project source IDs; they join the
/// adapter registry in `--only` but are not adapters, so the listing names
/// them in their own section.
const BUILT_IN_SOURCES: [(&str, &str); 2] = [
    (
        degu_adapters::ARTIFACT_SOURCE_ID,
        "build artifacts under the project roots given to scan or clean",
    ),
    (
        degu_adapters::CHECKPOINT_SOURCE_ID,
        "training checkpoints under the project roots given to scan or clean",
    ),
];

pub(crate) fn run() -> Result<()> {
    let adapters = crate::configuration::valid_adapter_ids();
    tracing::info!(adapters = adapters.len(), "adapter registry listed");
    let mut output = format!("{}\n", adapters.join("\n"));
    output.push_str("\nBuilt-in source IDs (accepted by --only):\n");
    for (id, description) in BUILT_IN_SOURCES {
        output.push_str(&format!("  {id:<12} {description}\n"));
    }
    crate::output::write_stdout(output.into_bytes())
}
