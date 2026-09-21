use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::browser::{Browser, SortBy};
use crate::tui::decision::Decisions;
use crate::tui::report::{ScanReport, Section};
use crate::tui::staged::Staged;

use super::allocation::{self, Segment};
use super::derived::Derived;
use super::details::Document;
use super::format;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Groups,
    Findings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Quit,
    Preview,
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browser,
    Staged,
    Details,
    Help,
}

impl View {
    /// Whether `c` runs the decided plans from here.
    ///
    /// The footer offers the key by asking this, and `handle` accepts it by
    /// asking this, so the screen cannot name a key the keyboard will ignore.
    pub const fn runs_cleanup(self) -> bool {
        matches!(self, Self::Browser | Self::Staged)
    }
}

pub struct App {
    /// Whether this account can run a cleanup at all.
    ///
    /// Asked once before the review opens, because the answer does not change
    /// while it is open and finding out at the end wastes every decision the
    /// reader made. Browsing still works without it; only running does not.
    /// Why it cannot is left to `degu doctor`, which distinguishes setup that
    /// was never done from setup that went missing — a difference this screen
    /// has no room to explain and no business deciding.
    blocked: bool,
    browser: Browser,
    decisions: Decisions,
    staged: Staged,
    home: std::path::PathBuf,
    view: View,
    focus: Focus,
    page_size: usize,
    group_page_size: usize,
    staged_page_size: usize,
    document: Derived<Document, Option<(Section, usize)>>,
    metric_width: Derived<usize, (Section, SortBy, usize)>,
    allocation: Derived<Vec<Segment>, Section>,
    help_return: View,
}

impl App {
    pub fn new(
        report: ScanReport,
        staged: Staged,
        home: std::path::PathBuf,
        blocked: bool,
    ) -> Self {
        let decisions = Decisions::new(report.section(Section::Cache));
        let browser = Browser::new(report);
        let document = Derived::new(browser.selection(), || document(&browser, &home));
        let metric_width = Derived::new(metric_key(&browser), || metric_width(&browser));
        let allocation = Derived::new(browser.section(), || allocation::segments(&browser));
        Self {
            blocked,
            browser,
            decisions,
            staged,
            home,
            view: View::Browser,
            focus: Focus::Findings,
            page_size: 1,
            group_page_size: 1,
            staged_page_size: 1,
            document,
            metric_width,
            allocation,
            help_return: View::Browser,
        }
    }

    fn refresh(&mut self) {
        let browser = &self.browser;
        self.document
            .refresh(browser.selection(), || document(browser, &self.home));
        self.metric_width
            .refresh(metric_key(browser), || metric_width(browser));
        self.allocation
            .refresh(browser.section(), || allocation::segments(browser));
    }

    pub fn decisions(&self) -> &Decisions {
        &self.decisions
    }

    pub fn staged(&self) -> &Staged {
        &self.staged
    }

    pub fn home(&self) -> &std::path::Path {
        &self.home
    }

    pub fn browser(&self) -> &Browser {
        &self.browser
    }

    pub fn view(&self) -> View {
        self.view
    }

    pub fn focus(&self) -> Focus {
        self.focus
    }

    pub fn document(&mut self) -> &mut Document {
        self.document.get_mut()
    }

    pub fn metric_width(&self) -> usize {
        *self.metric_width.get()
    }

    pub fn allocation(&self) -> &[Segment] {
        self.allocation.get()
    }

    pub fn resize(&mut self, findings: usize, groups: usize) {
        self.page_size = findings;
        self.group_page_size = groups;
    }

    pub fn resize_staged(&mut self, entries: usize) {
        self.staged_page_size = entries;
    }

    pub fn handle(&mut self, key: KeyEvent) -> Option<Outcome> {
        let control_quit = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd'));
        if key.code == KeyCode::Char('q') || control_quit {
            return Some(Outcome::Quit);
        }
        match key.code {
            KeyCode::Esc => match self.view {
                View::Help => self.view = self.help_return,
                View::Details | View::Staged => self.view = View::Browser,
                View::Browser => {
                    if !self.browser.clear_filter() {
                        return Some(Outcome::Quit);
                    }
                }
            },
            KeyCode::Char('?') => {
                if self.view == View::Help {
                    self.view = self.help_return;
                } else {
                    self.help_return = self.view;
                    self.view = View::Help;
                }
            }
            KeyCode::Char('c') if self.can_run() && self.view.runs_cleanup() => {
                return Some(Outcome::Clean);
            }
            code => match self.view {
                View::Browser => {
                    if let Some(outcome) = self.browse(code) {
                        return Some(outcome);
                    }
                }
                View::Staged => {
                    if let Some(outcome) = self.review_staged(code) {
                        return Some(outcome);
                    }
                }
                View::Details => self.scroll(code),
                View::Help => {}
            },
        }
        self.refresh();
        None
    }

    fn browse(&mut self, code: KeyCode) -> Option<Outcome> {
        let page_size = match self.focus {
            Focus::Groups => self.group_page_size,
            Focus::Findings => self.page_size,
        };
        if let Some(delta) = movement(code, page_size) {
            match self.focus {
                Focus::Groups => self.browser.filter_by(delta),
                Focus::Findings => self.browser.move_by(delta),
            }
            return None;
        }
        match code {
            KeyCode::Home | KeyCode::End => {
                let last = code == KeyCode::End;
                if self.focus == Focus::Groups {
                    let position = if last { self.browser.groups().len() } else { 0 };
                    self.browser
                        .filter_by(position as isize - self.browser.group_position() as isize);
                    return None;
                }
                if last {
                    self.browser.select_last();
                } else {
                    self.browser.select_first();
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.browser.filter_by(-1);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.browser.filter_by(1);
            }
            KeyCode::Char('s') => {
                self.browser.next_sort();
            }
            KeyCode::Char('g') => {
                self.browser.next_grouping();
            }
            KeyCode::Tab => {
                self.browser.switch_section();
            }
            KeyCode::Enter | KeyCode::Char('3') => {
                if self.browser.selected_finding().is_some() {
                    self.view = View::Details;
                }
            }
            KeyCode::Char('t') => self.view = View::Staged,
            KeyCode::Char('p') => return Some(Outcome::Preview),
            KeyCode::Char(' ') => {
                if let Some(finding) = self.browser.selected_finding() {
                    self.decisions.toggle(finding, self.browser.section());
                }
            }
            KeyCode::Char('1') => self.focus = Focus::Groups,
            KeyCode::Char('2') => self.focus = Focus::Findings,
            _ => {}
        }
        None
    }

    fn review_staged(&mut self, code: KeyCode) -> Option<Outcome> {
        if let Some(delta) = movement(code, self.staged_page_size) {
            self.staged.move_by(delta);
            return None;
        }
        match code {
            KeyCode::Home => self.staged.select_first(),
            KeyCode::End => self.staged.select_last(),
            KeyCode::Char(' ') => self.staged.toggle(),
            KeyCode::Char('t') => self.view = View::Browser,
            _ => {}
        }
        None
    }

    pub fn has_work(&self) -> bool {
        !self.decisions.is_empty() || !self.staged.nothing_chosen()
    }

    /// Whether running is unavailable here.
    pub fn blocked(&self) -> bool {
        self.blocked
    }

    /// Whether `c` would reach a command that can do anything.
    pub fn can_run(&self) -> bool {
        !self.blocked && self.has_work()
    }

    fn scroll(&mut self, code: KeyCode) {
        if let Some(delta) = movement(code, self.document.get_mut().page_size()) {
            self.document.get_mut().move_by(delta);
            return;
        }
        match code {
            KeyCode::Home => self.document.get_mut().first(),
            KeyCode::End => self.document.get_mut().last(),
            KeyCode::Enter => self.view = View::Browser,
            _ => {}
        }
    }
}

fn document(browser: &Browser, home: &std::path::Path) -> Document {
    browser
        .selected_finding()
        .map(|finding| Document::new(finding, browser.section(), home))
        .unwrap_or_default()
}

fn metric_key(browser: &Browser) -> (Section, SortBy, usize) {
    (
        browser.section(),
        browser.sort_by(),
        browser.group_position(),
    )
}

fn metric_width(browser: &Browser) -> usize {
    browser
        .findings()
        .map(|finding| format::metric(finding, browser.sort_by()).len())
        .max()
        .unwrap_or(0)
        .max(format::metric_heading(browser.sort_by()).len())
}

fn movement(code: KeyCode, page_size: usize) -> Option<isize> {
    match code {
        KeyCode::Down | KeyCode::Char('j') => Some(1),
        KeyCode::Up | KeyCode::Char('k') => Some(-1),
        KeyCode::PageDown => Some(page_size as isize),
        KeyCode::PageUp => Some(-(page_size as isize)),
        _ => None,
    }
}
