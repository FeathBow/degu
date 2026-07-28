use crossterm::style::{Stylize, style};

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Destructive,
}

pub(crate) fn paint(value: impl std::fmt::Display, tone: Tone, enabled: bool) -> String {
    let text = value.to_string();
    if !enabled {
        return text;
    }
    match tone {
        Tone::Destructive => style(text).red().bold().to_string(),
    }
}
