use clap::builder::styling::{AnsiColor, Color, Style, Styles};
use clap::{ColorChoice, ValueEnum};
use std::ffi::{OsStr, OsString};

const DUMB_TERMINAL: &str = "dumb";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ColorPolicy {
    mode: ColorWhen,
    environment: ColorEnvironment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ColorEnvironment {
    no_color: bool,
    force_color: bool,
    clicolor: Option<bool>,
    terminal_supports_color: bool,
    ci: bool,
}

impl ColorPolicy {
    pub(crate) fn current(mode: ColorWhen) -> Self {
        Self {
            mode,
            environment: ColorEnvironment::current(),
        }
    }

    pub(crate) fn enabled(self, stream_is_terminal: bool) -> bool {
        match self.mode {
            ColorWhen::Always => true,
            ColorWhen::Never => false,
            ColorWhen::Auto => self.environment.auto_enabled(stream_is_terminal),
        }
    }
}

impl ColorEnvironment {
    fn current() -> Self {
        Self {
            no_color: non_empty_env("NO_COLOR"),
            force_color: non_empty_env("CLICOLOR_FORCE"),
            clicolor: std::env::var_os("CLICOLOR").map(|value| value != "0"),
            terminal_supports_color: terminal_supports_color(std::env::var_os("TERM").as_deref()),
            ci: std::env::var_os("CI").is_some(),
        }
    }

    fn auto_enabled(self, stream_is_terminal: bool) -> bool {
        if self.no_color {
            return false;
        }
        if self.force_color {
            return true;
        }
        if self.clicolor == Some(false) {
            return false;
        }
        stream_is_terminal
            && (self.terminal_supports_color || self.clicolor == Some(true) || self.ci)
    }
}

pub(crate) fn clap_color_choice(args: &[OsString]) -> ColorChoice {
    match requested_color_mode(args) {
        ColorWhen::Always => ColorChoice::Always,
        ColorWhen::Never => ColorChoice::Never,
        ColorWhen::Auto => ColorChoice::Auto,
    }
}

pub(crate) fn help_styles() -> Styles {
    let green = ansi(AnsiColor::Green).bold();
    let cyan = ansi(AnsiColor::Cyan);
    Styles::styled()
        .header(green)
        .usage(green)
        .literal(cyan.bold())
        .placeholder(cyan)
        .error(ansi(AnsiColor::Red).bold())
        .valid(ansi(AnsiColor::Green))
        .invalid(ansi(AnsiColor::Yellow))
}

fn ansi(color: AnsiColor) -> Style {
    Style::new().fg_color(Some(Color::Ansi(color)))
}

fn explicit_color_mode(args: &[OsString]) -> Option<ColorWhen> {
    let mut mode = None;
    let mut index = 1;
    while index < args.len() {
        let Some(argument) = args[index].to_str() else {
            index += 1;
            continue;
        };
        if argument == "--" {
            break;
        }
        if argument == "--color" {
            mode = args.get(index + 1).and_then(|value| parse_mode(value));
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--color=") {
            mode = parse_mode(OsStr::new(value));
        }
        index += 1;
    }
    mode
}

fn requested_color_mode(args: &[OsString]) -> ColorWhen {
    explicit_color_mode(args).unwrap_or(ColorWhen::Auto)
}

fn parse_mode(value: &OsStr) -> Option<ColorWhen> {
    match value.to_str()? {
        "auto" => Some(ColorWhen::Auto),
        "always" => Some(ColorWhen::Always),
        "never" => Some(ColorWhen::Never),
        _ => None,
    }
}

fn non_empty_env(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn terminal_supports_color(term: Option<&OsStr>) -> bool {
    #[cfg(windows)]
    return term != Some(OsStr::new(DUMB_TERMINAL));

    #[cfg(not(windows))]
    return term.is_some_and(|value| value != OsStr::new(DUMB_TERMINAL));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_mode_uses_documented_precedence() {
        let no_color = ColorEnvironment {
            no_color: true,
            force_color: true,
            clicolor: Some(true),
            terminal_supports_color: true,
            ci: true,
        };
        let forced = ColorEnvironment {
            no_color: false,
            force_color: true,
            clicolor: Some(false),
            terminal_supports_color: false,
            ci: false,
        };
        let disabled = ColorEnvironment {
            no_color: false,
            force_color: false,
            clicolor: Some(false),
            terminal_supports_color: true,
            ci: true,
        };
        let requested = ColorEnvironment {
            no_color: false,
            force_color: false,
            clicolor: Some(true),
            terminal_supports_color: false,
            ci: false,
        };

        assert!(!no_color.auto_enabled(true));
        assert!(forced.auto_enabled(false));
        assert!(!disabled.auto_enabled(true));
        assert!(requested.auto_enabled(true));
        assert!(!requested.auto_enabled(false));
    }

    #[test]
    fn automatic_mode_requires_terminal_capability_by_default() {
        let capable = ColorEnvironment {
            no_color: false,
            force_color: false,
            clicolor: None,
            terminal_supports_color: true,
            ci: false,
        };
        let incapable = ColorEnvironment {
            terminal_supports_color: false,
            ..capable
        };
        let ci = ColorEnvironment {
            ci: true,
            ..incapable
        };

        assert!(capable.auto_enabled(true));
        assert!(!capable.auto_enabled(false));
        assert!(!incapable.auto_enabled(true));
        assert!(ci.auto_enabled(true));
        assert!(!ci.auto_enabled(false));
    }
}
