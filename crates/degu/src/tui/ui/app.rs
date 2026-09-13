use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::browser::{Browser, SortBy};
use crate::tui::decision::{Choice, Decisions};
use crate::tui::report::{ScanReport, Section};

use super::allocation::{self, Segment};
use super::derived::Derived;
use super::details::Document;
use super::format;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Groups,
    Findings,
}

/// Why the interface stopped. Anything that acts happens after the screen is
/// restored, so its output lands in the scrollback exactly as the command's own
/// output would.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Quit,
    Preview,
    Clean,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browser,
    Details,
    Help,
}

pub struct App {
    browser: Browser,
    decisions: Decisions,
    limits: crate::cli::ScanLimitArgs,
    view: View,
    focus: Focus,
    page_size: usize,
    group_page_size: usize,
    document: Derived<Document, Option<(Section, usize)>>,
    metric_width: Derived<usize, (Section, SortBy, usize)>,
    allocation: Derived<Vec<Segment>, Section>,
    help_return: View,
}

impl App {
    pub fn new(report: ScanReport, limits: crate::cli::ScanLimitArgs) -> Self {
        let decisions = Decisions::new(report.section(Section::Cache));
        let browser = Browser::new(report);
        let document = Derived::new(document_key(&browser), || document(&browser));
        let metric_width = Derived::new(metric_key(&browser), || metric_width(&browser));
        let allocation = Derived::new(browser.section(), || allocation::segments(&browser));
        Self {
            browser,
            decisions,
            limits,
            view: View::Browser,
            focus: Focus::Findings,
            page_size: 1,
            group_page_size: 1,
            document,
            metric_width,
            allocation,
            help_return: View::Browser,
        }
    }

    fn refresh(&mut self) {
        let browser = &self.browser;
        self.document
            .refresh(document_key(browser), || document(browser));
        self.metric_width
            .refresh(metric_key(browser), || metric_width(browser));
        self.allocation
            .refresh(browser.section(), || allocation::segments(browser));
    }

    pub fn decisions(&self) -> &Decisions {
        &self.decisions
    }

    /// The choice the reader faces for one finding, or has already made.
    pub fn choice(&self, finding: &degu_core::finding::Finding) -> Choice {
        Choice::of(
            finding,
            self.browser.section(),
            self.decisions.is_chosen(finding),
        )
    }

    /// The clean the current decisions describe, ready for preview or
    /// execution by the ordinary command implementation.
    pub fn clean_args(&self, dry_run: bool) -> crate::cli::CleanArgs {
        self.decisions.clean_args(self.limits, dry_run)
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

    pub fn handle(&mut self, key: KeyEvent) -> Option<Outcome> {
        let control_quit = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd'));
        if key.code == KeyCode::Char('q') || control_quit {
            return Some(Outcome::Quit);
        }
        match key.code {
            KeyCode::Esc => match self.view {
                View::Help => self.view = self.help_return,
                View::Details => self.view = View::Browser,
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
            code => match self.view {
                View::Browser => {
                    if let Some(outcome) = self.browse(code) {
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
            KeyCode::Char('p') => return Some(Outcome::Preview),
            KeyCode::Char('c') if !self.decisions.is_empty() => return Some(Outcome::Clean),
            KeyCode::Char(' ') => {
                if let Some(finding) = self.browser.selected_finding().cloned() {
                    self.decisions.toggle(&finding, self.browser.section());
                }
            }
            KeyCode::Char('1') => self.focus = Focus::Groups,
            KeyCode::Char('2') => self.focus = Focus::Findings,
            _ => {}
        }
        None
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

fn document(browser: &Browser) -> Document {
    browser
        .selected_finding()
        .map(|finding| Document::new(finding, browser.section()))
        .unwrap_or_default()
}

fn document_key(browser: &Browser) -> Option<(Section, usize)> {
    browser.selection()
}

// Sized from every finding currently listed.
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
