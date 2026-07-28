use super::{Guidance, GuidanceKind, OutputMode, Request, Resolution, resolve};
use crate::output::stdoutln;
use crate::presentation::semantic::{self, Tone};
use anyhow::Result;

pub(crate) fn print(request: Request<'_>) -> Result<()> {
    resolve(request).print()
}

impl Guidance {
    pub(crate) fn print(self) -> Result<()> {
        let OutputMode::Human(ui) = self.output;
        let color_enabled = ui.colors.stdout;
        match self.resolution {
            Resolution::Ready { line, kind } => stdoutln!(
                "\n{}",
                ui.command_block(
                    &semantic::paint(ui.prose(kind.heading()), Tone::AccentHeading, color_enabled),
                    &semantic::paint(line.as_str(), Tone::Accent, color_enabled),
                )
            ),
            Resolution::UnsafeScope => stdoutln!(
                "\n{}",
                semantic::paint(
                    ui.prose(&format!("Next {}", super::UNSAFE_SCOPE_REASON)),
                    Tone::Review,
                    color_enabled
                )
            ),
            Resolution::Absent => Ok(()),
        }
    }
}

impl GuidanceKind {
    fn heading(self) -> &'static str {
        match self {
            Self::Standard | Self::ProjectScan => "Next:",
            Self::CompleteScan => "Rerun to complete the scan:",
        }
    }
}
