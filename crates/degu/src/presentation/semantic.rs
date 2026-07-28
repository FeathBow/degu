use crossterm::style::{Stylize, style};

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Review,
    Destructive,
}

pub(crate) fn paint(value: impl std::fmt::Display, tone: Tone, enabled: bool) -> String {
    let text = value.to_string();
    if !enabled {
        return text;
    }
    match tone {
        // Standard yellow (palette 3), not bright yellow (palette 11):
        // bright yellow is near-invisible on light terminal themes.
        Tone::Review => style(text).dark_yellow().bold().to_string(),
        Tone::Destructive => style(text).red().bold().to_string(),
    }
}
