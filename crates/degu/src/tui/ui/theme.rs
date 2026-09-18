use ratatui::prelude::*;
use ratatui::widgets::{Block, BorderType, Borders, Padding};

use crate::tui::report::Class;

pub const BACKGROUND: Color = Color::Rgb(24, 28, 41);
pub const SURFACE: Color = Color::Rgb(32, 38, 55);
pub const TEXT: Color = Color::Rgb(222, 226, 238);
pub const SECONDARY: Color = Color::Rgb(165, 174, 197);
pub const ACCENT: Color = Color::Rgb(157, 207, 232);
pub const EDGE: Color = Color::Rgb(92, 105, 137);
pub const SELECTION: Color = Color::Rgb(51, 64, 87);
pub const READY: Color = Color::Rgb(156, 219, 201);
pub const REVIEW: Color = Color::Rgb(194, 179, 237);
pub const UNMANAGED: Color = Color::Rgb(165, 180, 205);
pub const ROSE: Color = Color::Rgb(217, 182, 210);
pub const CAUTION: Color = Color::Rgb(227, 198, 142);

pub fn canvas() -> Style {
    Style::new().fg(TEXT).bg(BACKGROUND)
}

pub fn class_style(class: Class) -> Style {
    let color = match class {
        Class::Ready => READY,
        Class::NeedsReview => REVIEW,
        Class::NotManaged => UNMANAGED,
    };
    Style::new().fg(color)
}

pub fn panel(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .style(Style::new().fg(TEXT).bg(SURFACE))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(EDGE))
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            format!(" {} ", title.into()),
            Style::new().fg(TEXT).bold(),
        ))
}

pub fn focused_panel(title: impl Into<String>, focused: bool) -> Block<'static> {
    let color = if focused { ACCENT } else { EDGE };
    panel(title).border_style(Style::new().fg(color))
}
