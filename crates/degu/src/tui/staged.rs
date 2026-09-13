use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::lifecycle::{TRASH_RETENTION_DAYS, TrashEntry};

use super::decision::Plan;

/// One staged entry, as much of it as a reader needs to decide.
pub struct Entry {
    pub original: Option<PathBuf>,
    pub entry: PathBuf,
    pub bytes: u64,
    pub age_days: u64,
    pub ambiguous: bool,
    pub lower_bound: bool,
    /// A confirmed clean removes this one whether or not the reader chooses
    /// it, because degu runs no background timer and that housekeeping rides
    /// on the next mutating command.
    pub expiring: bool,
    /// A stray claim from a purge that did not finish. It has no recorded
    /// original, so `trash purge --path` cannot name it and only a full purge
    /// reaches it.
    pub interrupted: bool,
}

impl Entry {
    /// `trash purge --path` selects by the original location, so an entry that
    /// never recorded one cannot be chosen here.
    pub fn selectable(&self) -> bool {
        self.original.is_some() && !self.interrupted
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
        let mut label = crate::presentation::display_path(path, home);
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

/// What is in the staging trash, and which of it the reader wants destroyed.
///
/// Staging is what makes `degu clean` reversible, and it is also why a clean
/// does not free quota. This is where the reader converts one into the other,
/// for the entries they name and no others.
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
                expiring: row.age_days >= TRASH_RETENTION_DAYS,
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
        entry
            .original
            .as_ref()
            .is_some_and(|original| self.chosen.contains(original))
    }

    /// Mark the entry under the cursor for permanent removal, or unmark it.
    pub fn toggle(&mut self) {
        let Some(entry) = self.entries.get(self.cursor) else {
            return;
        };
        if !entry.selectable() {
            return;
        }
        let Some(original) = entry.original.clone() else {
            return;
        };
        if !self.chosen.remove(&original) {
            self.chosen.insert(original);
        }
    }

    pub fn nothing_chosen(&self) -> bool {
        self.chosen.is_empty()
    }

    /// The originals to hand to `trash purge --path`.
    pub fn purge_paths(&self) -> Vec<PathBuf> {
        self.chosen.iter().cloned().collect()
    }

    /// What the reader chose to destroy.
    pub fn chosen_plan(&self) -> Plan {
        self.total(|entry| self.is_chosen(entry))
    }

    /// What a confirmed clean destroys on its own, whatever the reader chose.
    /// Shown apart from the choice so the two are never read as one number.
    pub fn expiring_plan(&self) -> Plan {
        self.total(|entry| entry.expiring && !self.is_chosen(entry))
    }

    pub fn total_plan(&self) -> Plan {
        self.total(|_| true)
    }

    fn total(&self, keep: impl Fn(&Entry) -> bool) -> Plan {
        let mut plan = Plan::default();
        for entry in self.entries.iter().filter(|entry| keep(entry)) {
            plan.locations += 1;
            plan.bytes = plan.bytes.saturating_add(entry.bytes);
        }
        plan
    }

    /// How the same permanent removal would be written on a command line.
    pub fn command_line(&self) -> String {
        let mut words = vec!["degu".to_owned(), "trash".to_owned(), "purge".to_owned()];
        for path in &self.chosen {
            words.push("--path".to_owned());
            words.push(path.display().to_string());
        }
        words.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(original: Option<&str>, age_days: u64, bytes: u64) -> TrashEntry {
        TrashEntry {
            entry: PathBuf::from("/state/degu/trash/0001"),
            original: original.map(PathBuf::from),
            bytes_allocated: bytes,
            bytes_hardlinked: 0,
            age_days,
            ambiguous: false,
            interrupted_purge: false,
            lower_bound: false,
        }
    }

    fn staged(rows: Vec<TrashEntry>) -> Staged {
        Staged::new(rows)
    }

    #[test]
    fn nothing_is_marked_for_deletion_until_it_is_chosen() {
        let staged = staged(vec![row(Some("/a"), 0, 10)]);
        assert!(staged.nothing_chosen());
        assert!(staged.purge_paths().is_empty());
        assert_eq!(staged.chosen_plan(), Plan::default());
    }

    #[test]
    fn choosing_an_entry_names_the_place_it_came_from() {
        let mut staged = staged(vec![row(Some("/a"), 0, 10), row(Some("/b"), 0, 20)]);
        staged.move_by(1);
        staged.toggle();
        assert_eq!(staged.purge_paths(), vec![PathBuf::from("/b")]);
        assert_eq!(
            staged.chosen_plan(),
            Plan {
                locations: 1,
                bytes: 20
            }
        );
        assert_eq!(staged.command_line(), "degu trash purge --path /b");
    }

    #[test]
    fn choosing_twice_returns_to_not_chosen() {
        let mut staged = staged(vec![row(Some("/a"), 0, 10)]);
        staged.toggle();
        staged.toggle();
        assert!(staged.nothing_chosen());
    }

    #[test]
    fn an_entry_with_no_recorded_origin_cannot_be_chosen() {
        // `trash purge --path` selects on the original location, so an entry
        // without one would be silently absent from the plan it appeared in.
        let mut staged = staged(vec![row(None, 0, 10)]);
        assert!(!staged.entries()[0].selectable());
        staged.toggle();
        assert!(staged.nothing_chosen());
    }

    #[test]
    fn an_interrupted_claim_cannot_be_chosen() {
        let mut entry = row(Some("/a"), 0, 10);
        entry.interrupted_purge = true;
        let mut staged = staged(vec![entry]);
        assert!(!staged.entries()[0].selectable());
        staged.toggle();
        assert!(staged.nothing_chosen());
    }

    #[test]
    fn an_ambiguous_entry_stays_choosable_and_says_so() {
        // The CLI warns about these rather than refusing them, and the
        // interface must refuse only where the CLI refuses.
        let mut entry = row(Some("/a"), 0, 10);
        entry.ambiguous = true;
        let mut staged = staged(vec![entry]);
        assert!(staged.entries()[0].selectable());
        staged.toggle();
        assert_eq!(staged.purge_paths(), vec![PathBuf::from("/a")]);
        assert!(
            staged.entries()[0]
                .label(Path::new("/home/me"))
                .contains("ambiguous")
        );
    }

    #[test]
    fn what_expires_on_its_own_is_counted_apart_from_what_was_chosen() {
        let mut staged = staged(vec![
            row(Some("/old"), TRASH_RETENTION_DAYS, 10),
            row(Some("/older"), TRASH_RETENTION_DAYS + 5, 20),
            row(Some("/fresh"), 1, 40),
        ]);
        assert_eq!(
            staged.expiring_plan(),
            Plan {
                locations: 2,
                bytes: 30
            }
        );

        // Choosing an expiring entry moves it out of that total and into the
        // chosen one, so the two never count the same bytes twice.
        staged.toggle();
        assert_eq!(
            staged.chosen_plan(),
            Plan {
                locations: 1,
                bytes: 10
            }
        );
        assert_eq!(
            staged.expiring_plan(),
            Plan {
                locations: 1,
                bytes: 20
            }
        );
        assert_eq!(
            staged.total_plan(),
            Plan {
                locations: 3,
                bytes: 70
            }
        );
    }

    #[test]
    fn the_cursor_stays_on_a_row_that_exists() {
        let mut staged = staged(vec![row(Some("/a"), 0, 10), row(Some("/b"), 0, 10)]);
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
        let mut staged = staged(Vec::new());
        assert!(staged.is_empty());
        staged.move_by(1);
        staged.toggle();
        assert_eq!(staged.cursor(), 0);
        assert!(staged.nothing_chosen());
    }
}
