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
    /// The next confirmed clean removes this one whether or not it is chosen.
    /// Execution still admits each entry.
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
    pub fn new(rows: Vec<TrashEntry>) -> Self {
        let entries = rows
            .into_iter()
            .map(|row| Entry {
                expiring: row.expiring,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::TrashEntry;

    fn row(entry: &str, original: Option<&str>, bytes: u64) -> TrashEntry {
        TrashEntry {
            entry: PathBuf::from(entry),
            original: original.map(PathBuf::from),
            bytes_allocated: bytes,
            bytes_hardlinked: 0,
            age_days: 1,
            ambiguous: false,
            interrupted_purge: false,
            expiring: false,
            lower_bound: false,
        }
    }

    #[test]
    fn nothing_is_marked_for_deletion_until_it_is_chosen() {
        let staged = Staged::new(vec![row("/trash/0001", Some("/a"), 10)]);
        assert!(staged.nothing_chosen());
        assert!(staged.purge_args().is_none());
        assert_eq!(staged.chosen_plan().locations, 0);
    }

    #[test]
    fn choosing_an_entry_names_the_exact_entry_not_its_origin() {
        let mut staged = Staged::new(vec![
            row("/trash/0001", Some("/a"), 10),
            row("/trash/0002", Some("/b"), 20),
        ]);
        staged.move_by(1);
        staged.toggle();

        let args = staged
            .purge_args()
            .expect("a chosen entry produces arguments");
        assert_eq!(args.entry, vec![PathBuf::from("/trash/0002")]);
        assert!(
            args.path.is_empty(),
            "an exact selection must not also narrow by origin"
        );
        assert!(!args.yes, "the purge confirmation still runs");
        assert_eq!(staged.chosen_plan().bytes, 20);
    }

    #[test]
    fn choosing_twice_returns_to_not_chosen() {
        let mut staged = Staged::new(vec![row("/trash/0001", Some("/a"), 10)]);
        staged.toggle();
        staged.toggle();
        assert!(staged.nothing_chosen());
    }

    /// An interrupted claim has no recorded staging operation behind it, so
    /// only a full purge reaches it. Offering it would promise a removal the
    /// selected purge cannot perform.
    #[test]
    fn an_interrupted_claim_cannot_be_chosen() {
        let mut entry = row("/trash/.claims/1", None, 10);
        entry.interrupted_purge = true;
        let mut staged = Staged::new(vec![entry]);
        assert!(!staged.entries()[0].selectable());
        staged.toggle();
        assert!(staged.nothing_chosen());
    }

    /// The CLI warns about ambiguous entries rather than refusing them, and
    /// the review must refuse only where the CLI refuses.
    #[test]
    fn an_ambiguous_entry_stays_choosable_and_says_so() {
        let mut entry = row("/trash/0001", Some("/a"), 10);
        entry.ambiguous = true;
        let mut staged = Staged::new(vec![entry]);
        assert!(staged.entries()[0].selectable());
        staged.toggle();
        assert!(!staged.nothing_chosen());
        assert!(
            staged.entries()[0]
                .label(Path::new("/home/me"))
                .contains("ambiguous")
        );
    }

    /// What a clean expires on its own is counted apart from what was chosen,
    /// and choosing one moves it between the two totals rather than counting
    /// the same bytes twice.
    #[test]
    fn the_expiry_total_is_separate_from_the_chosen_total() {
        let mut old = row("/trash/0001", Some("/old"), 10);
        old.expiring = true;
        let mut older = row("/trash/0002", Some("/older"), 20);
        older.expiring = true;
        let mut staged = Staged::new(vec![old, older, row("/trash/0003", Some("/new"), 40)]);

        assert_eq!(staged.expiring_plan(true).locations, 2);
        assert_eq!(staged.expiring_plan(true).bytes, 30);
        assert_eq!(staged.remaining_plan(true).bytes, 40);

        staged.toggle();
        assert_eq!(staged.chosen_plan().bytes, 10);
        assert_eq!(staged.expiring_plan(true).bytes, 20);
        assert_eq!(staged.total_plan().bytes, 70);
    }

    /// Expiry rides on a confirmed clean. With no clean to run, nothing
    /// expires, so the screen must not claim it will.
    #[test]
    fn nothing_expires_when_no_clean_is_planned() {
        let mut old = row("/trash/0001", Some("/old"), 10);
        old.expiring = true;
        let staged = Staged::new(vec![old]);
        assert_eq!(staged.expiring_plan(false).locations, 0);
        assert_eq!(staged.remaining_plan(false).bytes, 10);
    }

    #[test]
    fn the_cursor_stays_on_a_row_that_exists() {
        let mut staged = Staged::new(vec![
            row("/trash/0001", Some("/a"), 10),
            row("/trash/0002", Some("/b"), 10),
        ]);
        staged.move_by(-5);
        assert_eq!(staged.cursor(), 0);
        staged.move_by(99);
        assert_eq!(staged.cursor(), 1);
        staged.select_first();
        assert_eq!(staged.cursor(), 0);
        staged.select_last();
        assert_eq!(staged.cursor(), 1);
    }

    #[test]
    fn an_empty_trash_answers_without_a_cursor_to_move() {
        let mut staged = Staged::new(Vec::new());
        assert!(staged.is_empty());
        staged.move_by(1);
        staged.toggle();
        assert_eq!(staged.cursor(), 0);
        assert!(staged.nothing_chosen());
    }
}
