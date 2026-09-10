use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::report::{Class, Coverage, Finding, ScanReport, Section, Total};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Size,
    Inodes,
    Age,
    Path,
}

impl SortBy {
    pub fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Inodes => "inodes",
            Self::Age => "age",
            Self::Path => "path",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Size => Self::Inodes,
            Self::Inodes => Self::Age,
            Self::Age => Self::Path,
            Self::Path => Self::Size,
        }
    }

    fn compare(self, left: &Finding, right: &Finding) -> Ordering {
        match self {
            Self::Size => right.bytes_allocated.cmp(&left.bytes_allocated),
            Self::Inodes => right.inodes.cmp(&left.inodes),
            // Unknown ages follow every measured age.
            Self::Age => match (left.age_days, right.age_days) {
                (Some(left), Some(right)) => right.cmp(&left),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            Self::Path => left.path.cmp(&right.path),
        }
        .then_with(|| left.path.cmp(&right.path))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    Ecosystem,
    Class,
    Kind,
}

impl GroupBy {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ecosystem => "ecosystem",
            Self::Class => "disposition",
            Self::Kind => "kind",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Ecosystem => Self::Class,
            Self::Class => Self::Kind,
            Self::Kind => Self::Ecosystem,
        }
    }

    fn key(self, finding: &Finding, section: Section) -> (&str, Option<Class>) {
        match self {
            Self::Ecosystem => (&finding.ecosystem, None),
            Self::Class => {
                let class = Class::of(finding, section);
                (class.label(), Some(class))
            }
            Self::Kind => (&finding.kind, None),
        }
    }
}

#[derive(Clone)]
pub struct Group {
    // The filter matches findings against this key, so it stays raw and private.
    name: String,
    pub count: usize,
    pub class: Option<Class>,
    pub allocated: Total,
}

impl Group {
    pub fn label(&self) -> String {
        crate::escape::text(&self.name)
    }
}

fn group(findings: &[Finding], section: Section, by: GroupBy) -> Vec<Group> {
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut groups: Vec<Group> = Vec::new();
    for finding in findings {
        let (name, class) = by.key(finding, section);
        match index.get(name) {
            Some(&position) => {
                let group = &mut groups[position];
                group.count += 1;
                let total = Total::of([group.allocated.value, finding.bytes_allocated].into_iter());
                group.allocated = Total {
                    saturated: group.allocated.saturated || total.saturated,
                    ..total
                };
            }
            None => {
                index.insert(name, groups.len());
                groups.push(Group {
                    name: name.to_owned(),
                    count: 1,
                    class,
                    allocated: Total {
                        value: finding.bytes_allocated,
                        saturated: false,
                    },
                });
            }
        }
    }
    groups.sort_by(|left, right| {
        right
            .allocated
            .value
            .cmp(&left.allocated.value)
            .then_with(|| left.name.cmp(&right.name))
    });
    groups
}

pub struct Browser {
    report: ScanReport,
    section: Section,
    group_by: GroupBy,
    sort_by: SortBy,
    selected: usize,
    order: Vec<usize>,
    group_index: Option<usize>,
    groups: Vec<Group>,
    allocated: Total,
    inodes: Total,
}

impl Browser {
    pub fn new(report: ScanReport) -> Self {
        let section = Section::Cache;
        let allocated = report.total_allocated(section);
        let inodes = report.total_inodes(section);
        let mut browser = Self {
            report,
            section,
            group_by: GroupBy::Class,
            sort_by: SortBy::Size,
            selected: 0,
            order: Vec::new(),
            group_index: None,
            groups: Vec::new(),
            allocated,
            inodes,
        };
        browser.regroup();
        browser
    }

    pub fn section(&self) -> Section {
        self.section
    }

    pub fn coverage(&self) -> Coverage {
        self.coverage_of(self.section)
    }

    pub fn coverage_of(&self, section: Section) -> Coverage {
        self.report.completeness.section(section)
    }

    pub fn section_len(&self) -> usize {
        self.report.section(self.section).len()
    }

    pub fn allocated(&self) -> Total {
        self.allocated
    }

    pub fn inodes(&self) -> Total {
        self.inodes
    }

    pub fn sort_by(&self) -> SortBy {
        self.sort_by
    }

    pub fn group_by(&self) -> GroupBy {
        self.group_by
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    // Borrowed when the current grouping already answers this.
    pub fn ecosystem_groups(&self) -> Cow<'_, [Group]> {
        if self.group_by == GroupBy::Ecosystem {
            return Cow::Borrowed(&self.groups);
        }
        Cow::Owned(group(
            self.report.section(self.section),
            self.section,
            GroupBy::Ecosystem,
        ))
    }

    pub fn active_group(&self) -> Option<&Group> {
        self.group_index.map(|index| &self.groups[index])
    }

    // Position zero is the unfiltered "All findings" row.
    pub fn group_position(&self) -> usize {
        self.group_index.map_or(0, |index| index + 1)
    }

    pub fn finding_count(&self) -> usize {
        self.order.len()
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selection(&self) -> Option<(Section, usize)> {
        self.order
            .get(self.selected)
            .map(|&index| (self.section, index))
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.selection()
            .map(|(section, index)| &self.report.section(section)[index])
    }

    pub fn findings(&self) -> impl ExactSizeIterator<Item = &Finding> {
        let findings = self.report.section(self.section);
        self.order.iter().map(move |&index| &findings[index])
    }

    pub fn next_sort(&mut self) {
        self.sort_by = self.sort_by.next();
        self.reorder();
    }

    pub fn next_grouping(&mut self) {
        self.group_by = self.group_by.next();
        self.regroup();
    }

    fn regroup(&mut self) {
        self.group_index = None;
        self.groups = group(
            self.report.section(self.section),
            self.section,
            self.group_by,
        );
        if self.group_by == GroupBy::Class {
            self.groups.sort_by_key(|group| group.class);
        }
        self.reorder();
    }

    pub fn filter_by(&mut self, delta: isize) {
        let length = self.groups.len() + 1;
        let position =
            (self.group_position() as isize + delta).rem_euclid(length as isize) as usize;
        self.group_index = position.checked_sub(1);
        self.reorder();
        self.selected = 0;
    }

    pub fn clear_filter(&mut self) -> bool {
        if self.group_index.take().is_none() {
            return false;
        }
        self.reorder();
        true
    }

    fn reorder(&mut self) {
        let held = self.selection().map(|(_, index)| index);
        let items = self.report.section(self.section);
        let mut order: Vec<usize> = (0..items.len())
            .filter(|&index| {
                self.active_group().is_none_or(|group| {
                    self.group_by.key(&items[index], self.section).0 == group.name
                })
            })
            .collect();
        order.sort_by(|&left, &right| self.sort_by.compare(&items[left], &items[right]));
        self.selected = held
            .and_then(|index| order.iter().position(|&candidate| candidate == index))
            .unwrap_or(0);
        self.order = order;
    }

    pub fn switch_section(&mut self) {
        self.section = self.section.other();
        self.allocated = self.report.total_allocated(self.section);
        self.inodes = self.report.total_inodes(self.section);
        self.regroup();
        self.selected = 0;
    }

    pub fn move_by(&mut self, delta: isize) {
        let last = self.order.len().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }

    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    pub fn select_last(&mut self) {
        self.selected = self.order.len().saturating_sub(1);
    }
}
