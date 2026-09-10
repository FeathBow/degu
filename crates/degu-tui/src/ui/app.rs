use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::browser::Browser;
use crate::escape;
use crate::report::ScanReport;

use super::allocation::{self, Segment};
use super::details::Document;
use super::format;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Groups,
    Findings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browser,
    Details,
    Help,
}

pub struct App {
    browser: Browser,
    source: String,
    view: View,
    focus: Focus,
    document: Document,
    page_size: usize,
    group_page_size: usize,
    metric_width: usize,
    allocation: Vec<Segment>,
    help_return: View,
}

impl App {
    pub fn new(report: ScanReport, source: String) -> Self {
        let browser = Browser::new(report);
        let allocation = allocation::segments(&browser);
        let document = document(&browser);
        let metric_width = metric_width(&browser);
        Self {
            browser,
            source: escape::text(&source),
            view: View::Browser,
            focus: Focus::Findings,
            document,
            page_size: 1,
            group_page_size: 1,
            metric_width,
            allocation,
            help_return: View::Browser,
        }
    }

    pub fn browser(&self) -> &Browser {
        &self.browser
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn view(&self) -> View {
        self.view
    }

    pub fn focus(&self) -> Focus {
        self.focus
    }

    pub fn document(&mut self) -> &mut Document {
        &mut self.document
    }

    pub fn metric_width(&self) -> usize {
        self.metric_width
    }

    pub fn allocation(&self) -> &[Segment] {
        &self.allocation
    }

    pub fn resize(&mut self, findings: usize, groups: usize) {
        self.page_size = findings;
        self.group_page_size = groups;
    }

    pub fn handle(&mut self, key: KeyEvent) -> bool {
        let control_quit = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd'));
        if key.code == KeyCode::Char('q') || control_quit {
            return true;
        }
        let selection = self.browser.selection();
        let section = self.browser.section();
        let reordered = match key.code {
            KeyCode::Esc => match self.view {
                View::Help => {
                    self.view = self.help_return;
                    false
                }
                View::Details => {
                    self.view = View::Browser;
                    false
                }
                View::Browser => {
                    if !self.browser.clear_filter() {
                        return true;
                    }
                    true
                }
            },
            KeyCode::Char('?') => {
                if self.view == View::Help {
                    self.view = self.help_return;
                } else {
                    self.help_return = self.view;
                    self.view = View::Help;
                }
                false
            }
            code => match self.view {
                View::Browser => self.browse(code),
                View::Details => {
                    self.scroll(code);
                    false
                }
                View::Help => false,
            },
        };
        if reordered {
            self.metric_width = metric_width(&self.browser);
        }
        if section != self.browser.section() {
            self.allocation = allocation::segments(&self.browser);
        }
        if selection != self.browser.selection() {
            self.document = document(&self.browser);
        }
        false
    }

    fn browse(&mut self, code: KeyCode) -> bool {
        let page_size = match self.focus {
            Focus::Groups => self.group_page_size,
            Focus::Findings => self.page_size,
        };
        if let Some(delta) = movement(code, page_size) {
            return match self.focus {
                Focus::Groups => {
                    self.browser.filter_by(delta);
                    true
                }
                Focus::Findings => {
                    self.browser.move_by(delta);
                    false
                }
            };
        }
        match code {
            KeyCode::Home | KeyCode::End => {
                let last = code == KeyCode::End;
                if self.focus == Focus::Groups {
                    let position = if last {
                        self.browser.groups().len()
                    } else {
                        0
                    };
                    self.browser
                        .filter_by(position as isize - self.browser.group_position() as isize);
                    return true;
                }
                if last {
                    self.browser.select_last();
                } else {
                    self.browser.select_first();
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.browser.filter_by(-1);
                return true;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.browser.filter_by(1);
                return true;
            }
            KeyCode::Char('s') => {
                self.browser.next_sort();
                return true;
            }
            KeyCode::Char('g') => {
                self.browser.next_grouping();
                return true;
            }
            KeyCode::Tab => {
                self.browser.switch_section();
                return true;
            }
            KeyCode::Enter | KeyCode::Char('3') => {
                if self.browser.selected_finding().is_some() {
                    self.view = View::Details;
                }
            }
            KeyCode::Char('1') => self.focus = Focus::Groups,
            KeyCode::Char('2') => self.focus = Focus::Findings,
            _ => {}
        }
        false
    }

    fn scroll(&mut self, code: KeyCode) {
        if let Some(delta) = movement(code, self.document.page_size()) {
            self.document.move_by(delta);
            return;
        }
        match code {
            KeyCode::Home => self.document.first(),
            KeyCode::End => self.document.last(),
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
