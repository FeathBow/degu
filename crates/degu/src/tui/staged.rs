use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::cli::{JsonArgs, TrashPurgeArgs};
use crate::lifecycle::TrashEntry;

use super::decision::Plan;

pub struct Entry {
    pub original: Option<PathBuf>,
    pub entry: PathBuf,
    pub bytes: u64,
    pub age_days: u64,
    pub ambiguous: bool,
    pub lower_bound: bool,
    /// Included in lifecycle expiry assessment; execution still admits each entry.
    pub expiring: bool,
    /// Interrupted claims are reviewed through the full purge workflow.
    pub interrupted: bool,
}

impl Entry {
    pub fn selectable(&self) -> bool {
        !self.interrupted
    }

    fn note(&self) -> Option<&'static str> {
        if self.interrupted {
            Some("interrupted purge; only a full purge reaches it")
        } else if self.ambiguous {
            Some("ambiguous; inspect the operation history first")
        } else {
            None
        }
    }

    pub fn label(&self, home: &Path) -> String {
        let path = self.original.as_deref().unwrap_or(&self.entry);
        let origin = crate::presentation::display_path(path, home);
        let id = self
            .entry
            .file_name()
            .unwrap_or(self.entry.as_os_str())
            .to_string_lossy();
        let mut label = format!("{id} · {origin}");
        if self.original.is_none() {
            label.push_str(" (no recorded origin)");
        }
        if let Some(note) = self.note() {
            label.push_str(" (");
            label.push_str(note);
            label.push(')');
        }
        label
    }
}

pub struct Staged {
    entries: Vec<Entry>,
    chosen: BTreeSet<PathBuf>,
    cursor: usize,
}

impl Staged {
    pub fn new(rows: Vec<TrashEntry>, expiring: BTreeSet<PathBuf>) -> Self {
        let entries = rows
            .into_iter()
            .map(|row| Entry {
                expiring: expiring.contains(row.entry.as_path()),
                interrupted: row.interrupted_purge,
                original: row.original,
                entry: row.entry,
                bytes: row.bytes_allocated,
                age_days: row.age_days,
                ambiguous: row.ambiguous,
                lower_bound: row.lower_bound,
            })
            .collect();
        Self {
            entries,
            chosen: BTreeSet::new(),
            cursor: 0,
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn move_by(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let last = self.entries.len() - 1;
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
    }

    pub fn select_first(&mut self) {
        self.cursor = 0;
    }

    pub fn select_last(&mut self) {
        self.cursor = self.entries.len().saturating_sub(1);
    }

    pub fn is_chosen(&self, entry: &Entry) -> bool {
        self.chosen.contains(&entry.entry)
    }

    pub fn toggle(&mut self) {
        let Some(entry) = self.entries.get(self.cursor) else {
            return;
        };
        if !entry.selectable() {
            return;
        }
        if !self.chosen.remove(&entry.entry) {
            self.chosen.insert(entry.entry.clone());
        }
    }

    pub fn nothing_chosen(&self) -> bool {
        self.chosen.is_empty()
    }

    pub fn purge_args(&self) -> Option<TrashPurgeArgs> {
        if self.nothing_chosen() {
            return None;
        }
        Some(TrashPurgeArgs {
            output: JsonArgs { json: false },
            yes: false,
            path: Vec::new(),
            entry: self.chosen.iter().cloned().collect(),
        })
    }

    pub fn chosen_plan(&self) -> Plan {
        self.total(|entry| self.is_chosen(entry))
    }

    pub fn expiring_plan(&self, cleaning: bool) -> Plan {
        self.total(|entry| cleaning && entry.expiring && !self.is_chosen(entry))
    }

    pub fn total_plan(&self) -> Plan {
        self.total(|_| true)
    }

    /// Entries outside both plans. Unsupported entries within a plan also stay.
    pub fn remaining_plan(&self, cleaning: bool) -> Plan {
        self.total(|entry| !self.is_chosen(entry) && !(cleaning && entry.expiring))
    }

    fn total(&self, keep: impl Fn(&Entry) -> bool) -> Plan {
        let mut plan = Plan::default();
        for entry in self.entries.iter().filter(|entry| keep(entry)) {
            plan.locations += 1;
            plan.bytes = plan.bytes.saturating_add(entry.bytes);
        }
        plan
    }
}
