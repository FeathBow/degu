use crate::cli::ColorPolicy;
use crate::presentation::semantic::{self, Tone};
use anyhow::Result;
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::Path;
use unicode_width::UnicodeWidthStr;

const ROOT_OVERRIDE: &str = "1";
const WARN_VERBOSITY: u8 = 0;
const INFO_VERBOSITY: u8 = 1;
const DEBUG_VERBOSITY: u8 = 2;
const STAT_INDENT: &str = "  ";
const STAT_INDENT_WIDTH: u16 = STAT_INDENT.len() as u16;

/// Immutable presentation facts captured once at startup and threaded as one
/// value through every human-output renderer.
#[derive(Clone, Copy)]
pub(crate) struct Ui {
    pub(crate) colors: OutputColors,
    pub(crate) stdout_is_terminal: bool,
    pub(crate) glyphs: Glyphs,
    pub(crate) width: u16,
}

impl Ui {
    /// Wraps explanatory prose to the captured terminal width. Piped output
    /// stays single-line so greppable sentences survive intact; suggested
    /// command lines and paths must never pass through here. Wrapping happens
    /// on plain text: callers style the wrapped result, never the input.
    pub(crate) fn prose(self, text: &str) -> String {
        if self.stdout_is_terminal {
            crate::presentation::wrap_words(text, self.width)
        } else {
            text.to_owned()
        }
    }

    /// Opens a new output block on a terminal: one blank line, then the
    /// rendered text. Piped output keeps the block flush against the
    /// previous line so the piped byte contract stays frozen.
    pub(crate) fn section(self, text: &str) -> String {
        if self.stdout_is_terminal {
            format!("\n{text}")
        } else {
            text.to_owned()
        }
    }

    /// [`Ui::indented_prose`] painted line by line, so a tone never spans a
    /// line break.
    pub(crate) fn toned_prose(self, indent: u16, text: &str, tone: Tone) -> String {
        let margin = " ".repeat(usize::from(indent));
        if !self.stdout_is_terminal {
            return format!(
                "{margin}{}",
                semantic::paint(text, tone, self.colors.stdout)
            );
        }
        crate::presentation::wrap_words(text, self.width.saturating_sub(indent))
            .lines()
            .map(|line| {
                format!(
                    "{margin}{}",
                    semantic::paint(line, tone, self.colors.stdout)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Heading plus trailing stats: one line where it fits; narrow terminals move
    /// stats to an indented line, then one per line. Indent counts against every
    /// line; piped output stays one line.
    pub(crate) fn headline(self, headline: Headline) -> String {
        let margin = " ".repeat(usize::from(headline.indent));
        if headline.stats.is_empty() {
            return self.label_lines(&headline, &margin).join("\n");
        }
        let separator = format!(" {} ", self.glyphs.separator);
        let lead = match headline.lead {
            HeadlineLead::Separator => separator.clone(),
            HeadlineLead::Colon => ": ".to_owned(),
        };
        let joined = headline
            .stats
            .iter()
            .map(|(stat, _)| stat.as_str())
            .collect::<Vec<_>>()
            .join(&separator);
        let width = usize::from(self.width);
        let one_line =
            margin.len() + headline.label.width() + lead.width() + joined.width() <= width;
        if !self.stdout_is_terminal || one_line {
            let label = self.label_text(&headline, &headline.label);
            let stats = headline
                .stats
                .iter()
                .map(|(stat, tone)| self.stat_text(stat, tone.unwrap_or(headline.stat_tone)))
                .collect::<Vec<_>>()
                .join(&self.stat_text(&separator, headline.stat_tone));
            return format!("{margin}{label}{lead}{stats}");
        }
        let mut lines = self.label_lines(&headline, &margin);
        let stat_margin = format!("{margin}{STAT_INDENT}");
        let stat_width = self
            .width
            .saturating_sub(headline.indent.saturating_add(STAT_INDENT_WIDTH));
        let stat_lines = if joined.width() <= usize::from(stat_width) {
            vec![joined]
        } else {
            headline
                .stats
                .iter()
                .flat_map(|(stat, _)| {
                    crate::presentation::wrap_words(stat, stat_width)
                        .lines()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        lines.extend(
            stat_lines
                .iter()
                .map(|stat| format!("{stat_margin}{}", self.stat_text(stat, headline.stat_tone))),
        );
        lines.join("\n")
    }

    fn label_lines(self, headline: &Headline, margin: &str) -> Vec<String> {
        if !self.stdout_is_terminal {
            return vec![format!(
                "{margin}{}",
                self.label_text(headline, &headline.label)
            )];
        }
        crate::presentation::wrap_words(&headline.label, self.width.saturating_sub(headline.indent))
            .lines()
            .map(|line| format!("{margin}{}", self.label_text(headline, line)))
            .collect()
    }

    fn label_text(self, headline: &Headline, line: &str) -> String {
        match headline.label_tone {
            Some(tone) => semantic::paint(line, tone, self.colors.stdout),
            None => line.to_owned(),
        }
    }

    /// Cell-wrapping width for tables: the captured width on a terminal,
    /// none when piped. Piped table cells must never wrap or truncate, so
    /// full paths survive into pipelines regardless of any assumed width.
    pub(crate) fn table_width(self) -> Option<u16> {
        self.stdout_is_terminal.then_some(self.width)
    }

    /// Truncation budget for a full-width path cell in the compact table
    /// layouts; effectively unbounded when piped, where paths stay whole.
    pub(crate) fn compact_path_budget(self) -> usize {
        match self.table_width() {
            Some(width) => usize::from(width).saturating_sub(crate::presentation::CELL_PADDING),
            None => usize::MAX,
        }
    }

    /// Lays out a suggested command under its heading. On a terminal the
    /// command always occupies a full line of its own, indented two spaces,
    /// and is never wrapped even when it exceeds the width; piped output
    /// keeps the single-line "<heading> <command>" form.
    pub(crate) fn command_block(self, heading: &str, command: &str) -> String {
        if self.stdout_is_terminal {
            format!("{heading}\n  {command}")
        } else {
            format!("{heading} {command}")
        }
    }

    fn stat_text(self, stat: &str, tone: Tone) -> String {
        semantic::paint(stat, tone, self.colors.stdout)
    }
}

/// A heading plus the short stat phrases that follow it, in plain text so
/// [`Ui::headline`] can measure display width and wrap before styling;
/// tones name the intent and [`Ui`] paints each produced line.
pub(crate) struct Headline {
    label: String,
    label_tone: Option<Tone>,
    lead: HeadlineLead,
    /// Stat text plus an optional tone override; `None` falls back to the
    /// shared `stat_tone`. Overrides apply only in the one-line form: the
    /// narrow split forms keep painting whole stat lines with the shared
    /// tone.
    stats: Vec<(String, Option<Tone>)>,
    stat_tone: Tone,
    indent: u16,
}

/// Text that joins a headline label to its first stat in the one-line form;
/// the split forms drop it.
#[derive(Clone, Copy)]
pub(crate) enum HeadlineLead {
    Separator,
    Colon,
}

impl Headline {
    pub(crate) fn new(label: impl Into<String>, lead: HeadlineLead) -> Self {
        Self {
            label: label.into(),
            label_tone: None,
            lead,
            stats: Vec::new(),
            stat_tone: Tone::Secondary,
            indent: 0,
        }
    }

    pub(crate) fn label_tone(mut self, tone: Tone) -> Self {
        self.label_tone = Some(tone);
        self
    }

    pub(crate) fn stat(mut self, stat: impl Into<String>) -> Self {
        self.stats.push((stat.into(), None));
        self
    }

    /// A stat that keeps its own tone, so a headline can hold its decision
    /// datum at full intensity while the supporting stats stay dimmed.
    pub(crate) fn stat_toned(mut self, stat: impl Into<String>, tone: Tone) -> Self {
        self.stats.push((stat.into(), Some(tone)));
        self
    }

    /// Left margin the whole headline sits under; it reduces the available
    /// width for every produced line.
    pub(crate) fn indent(mut self, indent: u16) -> Self {
        self.indent = indent;
        self
    }
}

/// Full-control test terminal description; the glyph-matrix tests name every
/// axis, while most tests reach the two common states through
/// [`Ui::test_terminal`] and [`Ui::test_pipe`].
#[cfg(test)]
pub(crate) struct TestTerminal {
    pub(crate) stdout_is_terminal: bool,
    pub(crate) locale_is_utf8: bool,
    pub(crate) terminal_is_dumb: bool,
    pub(crate) width: u16,
}

#[cfg(test)]
impl Ui {
    /// Interactive UTF-8 terminal of the given width.
    pub(crate) fn test_terminal(width: u16) -> Self {
        Self::from_test_terminal(TestTerminal {
            stdout_is_terminal: true,
            locale_is_utf8: true,
            terminal_is_dumb: false,
            width,
        })
    }

    /// Redirected stdout of the given width.
    pub(crate) fn test_pipe(width: u16) -> Self {
        Self::from_test_terminal(TestTerminal {
            stdout_is_terminal: false,
            locale_is_utf8: true,
            terminal_is_dumb: false,
            width,
        })
    }

    /// Builds through the production glyph selection, so tests can only
    /// reach terminal states that exist in the wild; colors stay off, as
    /// under --color=never.
    pub(crate) fn from_test_terminal(terminal: TestTerminal) -> Self {
        Self {
            colors: OutputColors {
                stdout: false,
                stderr: false,
            },
            stdout_is_terminal: terminal.stdout_is_terminal,
            glyphs: Glyphs::select(
                terminal.stdout_is_terminal,
                terminal.locale_is_utf8,
                terminal.terminal_is_dumb,
            ),
            width: terminal.width,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OutputColors {
    pub(crate) stdout: bool,
    pub(crate) stderr: bool,
}

/// Glyph repertoire for stdout, the only stream that renders bars and
/// separators. Unicode requires a terminal with a UTF-8 locale and a TERM
/// that is not "dumb"; everything else falls back to pure ASCII.
#[derive(Clone, Copy)]
pub(crate) struct Glyphs {
    pub(crate) bar_filled: char,
    pub(crate) bar_empty: char,
    pub(crate) separator: char,
    pub(crate) ellipsis: &'static str,
    pub(crate) lower_bound: &'static str,
}

impl Glyphs {
    pub(crate) const UNICODE: Self = Self {
        bar_filled: '\u{2588}',
        bar_empty: '\u{2591}',
        separator: '\u{b7}',
        ellipsis: "\u{2026}",
        lower_bound: "\u{2265}",
    };
    pub(crate) const ASCII: Self = Self {
        bar_filled: '#',
        bar_empty: '-',
        separator: '-',
        ellipsis: "...",
        lower_bound: ">=",
    };

    pub(crate) fn select(
        stream_is_terminal: bool,
        locale_is_utf8: bool,
        terminal_is_dumb: bool,
    ) -> Self {
        if stream_is_terminal && locale_is_utf8 && !terminal_is_dumb {
            Self::UNICODE
        } else {
            Self::ASCII
        }
    }
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .is_some_and(|value| locale_value_is_utf8(&value))
}

fn locale_value_is_utf8(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("utf-8") || value.contains("utf8")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPolicy {
    Proceed,
    Warn,
    Refuse,
}

pub(crate) fn initialize(verbose: u8, policy: ColorPolicy) -> Result<Ui> {
    let stdout_is_terminal = std::io::stdout().is_terminal();
    let colors = OutputColors {
        stdout: policy.enabled(stdout_is_terminal),
        stderr: policy.enabled(std::io::stderr().is_terminal()),
    };
    crossterm::style::force_color_output(colors.stdout);
    init_tracing(verbose, colors.stderr)?;
    Ok(Ui {
        colors,
        stdout_is_terminal,
        glyphs: Glyphs::select(
            stdout_is_terminal,
            locale_is_utf8(),
            crate::presentation::terminal_is_dumb(),
        ),
        width: crate::presentation::output_width(),
    })
}

pub(crate) fn enforce_root_policy(colors: OutputColors) -> Result<()> {
    let in_container =
        Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
    let allow_env =
        std::env::var_os("DEGU_ALLOW_ROOT").as_deref() == Some(OsStr::new(ROOT_OVERRIDE));
    match root_policy(
        rustix::process::geteuid().is_root(),
        in_container,
        allow_env,
    ) {
        RootPolicy::Proceed => Ok(()),
        RootPolicy::Warn => {
            crate::presentation::print_stderr_note(
                crate::presentation::Severity::Warning,
                "degu is running as root; root changes degu semantics ($HOME, guard defaults, and trash anchor ownership); proceeding because a container marker or DEGU_ALLOW_ROOT=1 allowed it",
                colors,
            );
            Ok(())
        }
        RootPolicy::Refuse => anyhow::bail!(
            "refusing to run as root: root changes degu semantics ($HOME, guard defaults, and trash anchor ownership); run as a normal user or set DEGU_ALLOW_ROOT=1 to override"
        ),
    }
}

fn root_policy(euid_is_root: bool, in_container: bool, allow_env: bool) -> RootPolicy {
    if !euid_is_root {
        RootPolicy::Proceed
    } else if allow_env || in_container {
        RootPolicy::Warn
    } else {
        RootPolicy::Refuse
    }
}

fn init_tracing(verbose: u8, ansi: bool) -> Result<()> {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;

    let default_level = match verbose {
        WARN_VERBOSITY => LevelFilter::WARN,
        INFO_VERBOSITY => LevelFilter::INFO,
        DEBUG_VERBOSITY => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) => value
            .parse::<Targets>()
            .map_err(|error| anyhow::anyhow!("invalid RUST_LOG directive {value:?}: {error}"))?,
        Err(std::env::VarError::NotPresent) => Targets::new().with_default(default_level),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("RUST_LOG contains invalid UTF-8")
        }
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(ansi),
        )
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    const TEST_WIDTH: u16 = 80;
    const NOTE: &str = "Quota can change only after permanent deletion: inspect degu trash list; degu trash purge deletes all listed entries.";

    fn sample_headline() -> Headline {
        Headline::new("Ready to clean", HeadlineLead::Separator)
            .stat("36 locations")
            .stat("111.6 MiB")
    }

    #[test]
    fn prose_wraps_to_every_terminal_width() {
        for width in [24u16, 32, 80] {
            let wrapped = Ui::test_terminal(width).prose(NOTE);
            assert!(
                wrapped
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= usize::from(width)),
                "width {width}: {wrapped}"
            );
            assert_eq!(
                wrapped.split_whitespace().collect::<Vec<_>>(),
                NOTE.split_whitespace().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn prose_stays_single_line_when_piped() {
        assert_eq!(Ui::test_pipe(24).prose(NOTE), NOTE);
    }

    #[test]
    fn headline_layout_follows_the_terminal_width() {
        for (width, expected) in [
            (80u16, "Ready to clean · 36 locations · 111.6 MiB"),
            (32, "Ready to clean\n  36 locations · 111.6 MiB"),
            (24, "Ready to clean\n  36 locations\n  111.6 MiB"),
        ] {
            assert_eq!(
                Ui::test_terminal(width).headline(sample_headline()),
                expected,
                "width {width}"
            );
        }
    }

    #[test]
    fn headline_wraps_a_single_overlong_stat() {
        let sources = || {
            Headline::new("No matching locations", HeadlineLead::Separator)
                .stat("Sources: pip-cache, npm-cache, hf-hub")
        };
        for (width, expected) in [
            (
                80u16,
                "No matching locations · Sources: pip-cache, npm-cache, hf-hub",
            ),
            (
                32,
                "No matching locations\n  Sources: pip-cache, npm-cache,\n  hf-hub",
            ),
            (
                24,
                "No matching locations\n  Sources: pip-cache,\n  npm-cache, hf-hub",
            ),
        ] {
            assert_eq!(Ui::test_terminal(width).headline(sources()), expected);
        }
        assert_eq!(
            Ui::test_pipe(24).headline(sources()),
            "No matching locations - Sources: pip-cache, npm-cache, hf-hub"
        );
    }

    #[test]
    fn headline_wraps_a_long_label() {
        let review = || {
            Headline::new(
                "Needs review (included by --include-review)",
                HeadlineLead::Separator,
            )
            .stat("1 location")
        };
        for (width, expected) in [
            (
                80u16,
                "Needs review (included by --include-review) · 1 location",
            ),
            (
                32,
                "Needs review (included by\n--include-review)\n  1 location",
            ),
            (
                24,
                "Needs review (included\nby --include-review)\n  1 location",
            ),
        ] {
            assert_eq!(Ui::test_terminal(width).headline(review()), expected);
        }
        assert_eq!(
            Ui::test_pipe(24).headline(review()),
            "Needs review (included by --include-review) - 1 location"
        );
    }

    #[test]
    fn headline_indent_counts_against_every_line() {
        let indented = || sample_headline().indent(2);
        for (width, expected) in [
            (80u16, "  Ready to clean · 36 locations · 111.6 MiB"),
            (32, "  Ready to clean\n    36 locations · 111.6 MiB"),
            (24, "  Ready to clean\n    36 locations\n    111.6 MiB"),
        ] {
            assert_eq!(
                Ui::test_terminal(width).headline(indented()),
                expected,
                "width {width}"
            );
        }
        assert_eq!(
            Ui::test_pipe(24).headline(indented()),
            "  Ready to clean - 36 locations - 111.6 MiB"
        );
    }

    #[test]
    fn section_opens_with_a_blank_line_only_on_terminals() {
        for (ui, expected) in [
            (Ui::test_terminal(TEST_WIDTH), "\nTrash holds 4.0 KiB."),
            (Ui::test_pipe(TEST_WIDTH), "Trash holds 4.0 KiB."),
        ] {
            assert_eq!(ui.section("Trash holds 4.0 KiB."), expected);
        }
    }

    #[test]
    fn headline_paints_each_stat_with_its_own_tone_on_one_line() {
        crossterm::style::force_color_output(true);
        let mut ui = Ui::test_terminal(TEST_WIDTH);
        ui.colors.stdout = true;
        let rendered = ui.headline(
            Headline::new("Ready to clean", HeadlineLead::Separator)
                .stat("36 locations")
                .stat_toned("111.6 MiB", Tone::Ready),
        );
        assert!(
            rendered.contains("\u{1b}[2m36 locations\u{1b}[0m"),
            "{rendered:?}"
        );
        assert!(rendered.contains("38;5;10"), "{rendered:?}");
        assert!(!rendered.contains("\u{1b}[2m111.6"), "{rendered:?}");
    }

    #[test]
    fn headline_split_forms_keep_the_shared_stat_tone() {
        crossterm::style::force_color_output(true);
        let mut ui = Ui::test_terminal(24);
        ui.colors.stdout = true;
        let rendered = ui.headline(
            Headline::new("Ready to clean", HeadlineLead::Separator)
                .stat("36 locations")
                .stat_toned("111.6 MiB", Tone::Ready),
        );
        assert!(
            rendered.contains("\u{1b}[2m111.6 MiB\u{1b}[0m"),
            "{rendered:?}"
        );
        assert!(!rendered.contains("\u{1b}[38;5;10m"), "{rendered:?}");
    }

    #[test]
    fn headline_stays_single_line_when_piped() {
        assert_eq!(
            Ui::test_pipe(24).headline(sample_headline()),
            "Ready to clean - 36 locations - 111.6 MiB"
        );
    }

    #[test]
    fn headline_leads_shape_only_the_one_line_form() {
        let colon = || {
            Headline::new("Hidden by filters", HeadlineLead::Colon)
                .stat("1 location")
                .stat("1.8 MiB")
        };
        assert_eq!(
            Ui::test_terminal(80).headline(colon()),
            "Hidden by filters: 1 location · 1.8 MiB"
        );
        assert_eq!(
            Ui::test_terminal(32).headline(colon()),
            "Hidden by filters\n  1 location · 1.8 MiB"
        );
    }

    #[test]
    fn command_block_gives_commands_a_full_line_only_on_terminals() {
        let heading = "Review details:";
        let command = "degu clean --details --dry-run";
        assert_eq!(
            Ui::test_terminal(24).command_block(heading, command),
            "Review details:\n  degu clean --details --dry-run"
        );
        assert_eq!(
            Ui::test_pipe(24).command_block(heading, command),
            "Review details: degu clean --details --dry-run"
        );
    }

    #[test]
    fn glyphs_are_unicode_only_on_a_terminal_with_a_utf8_locale() {
        let selected = Ui::from_test_terminal(TestTerminal {
            stdout_is_terminal: true,
            locale_is_utf8: true,
            terminal_is_dumb: false,
            width: TEST_WIDTH,
        })
        .glyphs;
        assert_eq!(selected.bar_filled, '█');
        assert_eq!(selected.bar_empty, '░');
        assert_eq!(selected.separator, '·');
        assert_eq!(selected.ellipsis, "…");
        assert_eq!(selected.lower_bound, "≥");
        for (stdout_is_terminal, locale_is_utf8) in [(false, true), (true, false), (false, false)] {
            let selected = Ui::from_test_terminal(TestTerminal {
                stdout_is_terminal,
                locale_is_utf8,
                terminal_is_dumb: false,
                width: TEST_WIDTH,
            })
            .glyphs;
            assert_eq!(selected.bar_filled, '#');
            assert_eq!(selected.bar_empty, '-');
            assert_eq!(selected.separator, '-');
            assert_eq!(selected.ellipsis, "...");
            assert_eq!(selected.lower_bound, ">=");
        }
    }

    #[test]
    fn dumb_terminals_never_receive_unicode_glyphs() {
        let selected = Ui::from_test_terminal(TestTerminal {
            stdout_is_terminal: true,
            locale_is_utf8: true,
            terminal_is_dumb: true,
            width: TEST_WIDTH,
        })
        .glyphs;
        assert_eq!(selected.bar_filled, '#');
        assert_eq!(selected.bar_empty, '-');
        assert_eq!(selected.separator, '-');
        assert_eq!(selected.ellipsis, "...");
    }

    #[test]
    fn utf8_locale_values_match_case_insensitively() {
        for value in ["en_US.UTF-8", "C.utf8", "zh_CN.utf-8"] {
            assert!(locale_value_is_utf8(value), "{value:?}");
        }
        for value in ["C", "POSIX", "en_US.ISO8859-1"] {
            assert!(!locale_value_is_utf8(value), "{value:?}");
        }
    }

    #[test]
    fn non_root_proceeds() {
        assert_eq!(root_policy(false, false, false), RootPolicy::Proceed);
    }

    #[test]
    fn root_warns_when_explicitly_allowed() {
        assert_eq!(root_policy(true, false, true), RootPolicy::Warn);
    }

    #[test]
    fn root_warns_in_container() {
        assert_eq!(root_policy(true, true, false), RootPolicy::Warn);
    }

    #[test]
    fn unconfined_root_is_refused() {
        assert_eq!(root_policy(true, false, false), RootPolicy::Refuse);
    }
}
