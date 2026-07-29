use anyhow::Result;
use degu_adapters::{AdapterScope, RegisteredAdapter};
use std::collections::HashSet;

#[derive(Debug)]
pub(crate) struct SourceSelection {
    ids: Vec<String>,
    findings_selected: bool,
    runtime_selected: bool,
}

impl SourceSelection {
    pub(crate) fn from_only(
        only: &[String],
        runtime_enabled: bool,
        disabled: &[String],
    ) -> Result<Self> {
        let registrations = degu_adapters::all();
        let valid = valid_sources(&registrations);
        let valid_set = valid.iter().map(String::as_str).collect::<HashSet<_>>();
        for id in only {
            if !valid_set.contains(id.as_str()) {
                anyhow::bail!(
                    "unknown source {id:?}; valid source IDs: {}",
                    valid.join(", ")
                );
            }
            // Before the runtime check: the missing platform is the cause, not a missing --runtime.
            if let Some(platform) = platform_requirement(&registrations, id) {
                anyhow::bail!("{id} is only available on {platform}; remove it from --only");
            }
            if !runtime_enabled && is_runtime_adapter(&registrations, id) {
                anyhow::bail!(
                    "{id} is a node-runtime adapter; enable it with --runtime (scan only)"
                );
            }
            if disabled.iter().any(|disabled| disabled == id) {
                anyhow::bail!(
                    "source {id:?} is disabled by configuration; remove it from --only or config.disable"
                );
            }
        }
        Ok(Self {
            ids: only.to_vec(),
            findings_selected: selects_findings(&registrations, only),
            runtime_selected: selects_runtime(&registrations, only, runtime_enabled),
        })
    }

    pub(crate) fn includes(&self, id: &str) -> bool {
        self.ids.is_empty() || self.ids.iter().any(|selected| selected == id)
    }

    pub(crate) fn includes_project_sources(&self) -> bool {
        project_sources_selected(&self.ids)
    }

    pub(crate) fn project_sources(&self) -> degu_adapters::discovery::ProjectSources {
        degu_adapters::discovery::ProjectSources::new(
            self.includes(degu_adapters::ARTIFACT_SOURCE_ID),
            self.includes(degu_adapters::CHECKPOINT_SOURCE_ID),
        )
    }

    pub(crate) fn selects_runtime(&self) -> bool {
        self.runtime_selected
    }

    pub(crate) fn selects_findings(&self) -> bool {
        self.findings_selected
    }
}

pub(crate) fn project_sources_selected(only: &[String]) -> bool {
    only.is_empty()
        || degu_adapters::PROJECT_SOURCE_IDS
            .iter()
            .any(|id| only.iter().any(|selected| selected == id))
}

pub(crate) fn clean_only_ids(only: &[String]) -> Vec<String> {
    let registrations = degu_adapters::all();
    only.iter()
        .filter(|id| !is_runtime_adapter(&registrations, id))
        .cloned()
        .collect()
}

fn selects_findings(registrations: &[RegisteredAdapter], only: &[String]) -> bool {
    project_sources_selected(only)
        || only.iter().any(|id| {
            registrations.iter().any(|registration| {
                registration.id() == id && registration.scope() == AdapterScope::Cache
            })
        })
}

fn selects_runtime(
    registrations: &[RegisteredAdapter],
    only: &[String],
    runtime_enabled: bool,
) -> bool {
    runtime_enabled
        && (only.is_empty() || only.iter().any(|id| is_runtime_adapter(registrations, id)))
}

fn platform_requirement(registrations: &[RegisteredAdapter], id: &str) -> Option<&'static str> {
    registrations
        .iter()
        .find(|registration| registration.id() == id)
        .and_then(|registration| registration.ecosystem().platform_requirement())
}

fn is_runtime_adapter(registrations: &[RegisteredAdapter], id: &str) -> bool {
    registrations.iter().any(|registration| {
        registration.id() == id && registration.scope() == AdapterScope::Runtime
    })
}

fn valid_sources(registrations: &[RegisteredAdapter]) -> Vec<String> {
    let mut ids = registrations
        .iter()
        .map(RegisteredAdapter::id)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ids.extend(degu_adapters::PROJECT_SOURCE_IDS.map(str::to_owned));
    ids.sort();
    ids
}
