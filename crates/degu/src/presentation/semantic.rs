use crossterm::style::{Stylize, style};
use degu_core::finding::DispositionMode;

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Heading,
    Ready,
    Review,
    Accent,
    AccentHeading,
    Destructive,
    Secondary,
}

pub(crate) fn paint(value: impl std::fmt::Display, tone: Tone, enabled: bool) -> String {
    let text = value.to_string();
    if !enabled {
        return text;
    }
    match tone {
        Tone::Heading => style(text).bold().to_string(),
        Tone::Ready => style(text).green().bold().to_string(),
        // Standard yellow (palette 3), not bright yellow (palette 11):
        // bright yellow is near-invisible on light terminal themes.
        Tone::Review => style(text).dark_yellow().bold().to_string(),
        Tone::Accent => style(text).cyan().to_string(),
        Tone::AccentHeading => style(text).cyan().bold().to_string(),
        Tone::Destructive => style(text).red().bold().to_string(),
        Tone::Secondary => style(text).dim().to_string(),
    }
}

pub(crate) fn disposition_tone(mode: DispositionMode) -> Tone {
    match mode {
        DispositionMode::Eligible => Tone::Ready,
        DispositionMode::OptIn => Tone::Review,
        DispositionMode::ReportOnly => Tone::Heading,
    }
}
