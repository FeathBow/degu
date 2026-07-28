#[cfg(test)]
use crate::presentation::DEFAULT_OUTPUT_WIDTH;
use crate::presentation::{human_bytes, resolve_output_width, terminal_is_dumb};
use anyhow::{Context, Result, anyhow};
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthStr;

const REFRESH_INTERVAL: Duration = Duration::from_millis(100);
const DISPLAY_DELAY: Duration = Duration::from_millis(500);

pub(crate) struct ScanRootProgress {
    current: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl ScanRootProgress {
    pub(crate) fn new() -> Self {
        Self {
            current: Arc::new(AtomicU64::new(0)),
            total: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn set_total(&self, total: usize) {
        self.total
            .store(u64::try_from(total).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn begin_root(&self, current: usize) {
        self.current.store(
            u64::try_from(current).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

pub(crate) enum ScanIndicator {
    Disabled,
    Running {
        stop: Arc<AtomicBool>,
        handle: thread::JoinHandle<std::io::Result<bool>>,
    },
}

impl ScanIndicator {
    pub(crate) fn start(
        progress: Arc<degu_walk::Progress>,
        roots: &ScanRootProgress,
        color_enabled: bool,
    ) -> Self {
        if !indicator_enabled(
            std::io::stderr().is_terminal(),
            color_enabled,
            terminal_is_dumb(),
        ) {
            return Self::Disabled;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let root_current = Arc::clone(&roots.current);
        let root_total = Arc::clone(&roots.total);
        let width = resolve_output_width(stderr_terminal_width());
        let progress_loop = ProgressLoop {
            progress,
            root_current,
            root_total,
            stop: thread_stop,
            width,
        };
        let handle = thread::spawn(move || progress_loop.run());
        Self::Running { stop, handle }
    }

    pub(crate) fn stop_and_clear(self) -> Result<()> {
        let Self::Running { stop, handle } = self else {
            return Ok(());
        };
        stop.store(true, Ordering::Relaxed);
        handle.thread().unpark();
        let rendered = handle
            .join()
            .map_err(|_| anyhow!("scan progress thread panicked"))?
            .context("scan progress renderer failed")?;
        if rendered {
            clear_line().context("failed to clear scan progress")?;
        }
        Ok(())
    }
}

fn indicator_enabled(
    stderr_is_terminal: bool,
    color_enabled: bool,
    terminal_is_dumb: bool,
) -> bool {
    stderr_is_terminal && color_enabled && !terminal_is_dumb
}

struct ProgressLoop {
    progress: Arc<degu_walk::Progress>,
    root_current: Arc<AtomicU64>,
    root_total: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    width: u16,
}

impl ProgressLoop {
    fn run(self) -> std::io::Result<bool> {
        let started = Instant::now();
        let mut rendered = false;
        while !self.stop.load(Ordering::Relaxed) {
            thread::park_timeout(REFRESH_INTERVAL);
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            if started.elapsed() > DISPLAY_DELAY {
                let snapshot =
                    ProgressSnapshot::load(&self.progress, &self.root_current, &self.root_total);
                render_line(&format_scan_progress(snapshot, self.width))?;
                rendered = true;
            }
        }
        Ok(rendered)
    }
}

fn render_line(line: &str) -> std::io::Result<()> {
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "\r{line}\x1b[K")?;
    stderr.flush()
}

fn clear_line() -> std::io::Result<()> {
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "\r\x1b[K")?;
    stderr.flush()
}

struct ProgressSnapshot {
    entries: u64,
    bytes_allocated: u64,
    root_current: u64,
    root_total: u64,
}

impl ProgressSnapshot {
    fn load(progress: &degu_walk::Progress, current: &AtomicU64, total: &AtomicU64) -> Self {
        let progress = progress.snapshot();
        Self {
            entries: progress.inodes,
            bytes_allocated: progress.bytes_allocated,
            root_current: current.load(Ordering::Relaxed),
            root_total: total.load(Ordering::Relaxed),
        }
    }
}

fn stderr_terminal_width() -> Option<u16> {
    terminal_size::terminal_size_of(std::io::stderr()).map(|(terminal_size::Width(width), _)| width)
}

fn format_scan_progress(snapshot: ProgressSnapshot, width: u16) -> String {
    let bytes = human_bytes(snapshot.bytes_allocated);
    let full = format!(
        "scanning... {} entries, {} (root {}/{})",
        snapshot.entries, bytes, snapshot.root_current, snapshot.root_total
    );
    let compact = format!(
        "scanning... {} (root {}/{})",
        bytes, snapshot.root_current, snapshot.root_total
    );
    let minimal = format!("scanning... {bytes}");
    [full, compact, minimal]
        .into_iter()
        .find(|line| UnicodeWidthStr::width(line.as_str()) <= usize::from(width))
        .unwrap_or_else(|| "scanning...".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_line_formats_counts_and_bytes() {
        let snapshot = ProgressSnapshot {
            entries: 123_456,
            bytes_allocated: 4 * 1024 * 1024 * 1024 + 205 * 1024 * 1024,
            root_current: 7,
            root_total: 16,
        };
        assert_eq!(
            format_scan_progress(snapshot, DEFAULT_OUTPUT_WIDTH),
            "scanning... 123456 entries, 4.2 GiB (root 7/16)"
        );
    }

    #[test]
    fn progress_line_drops_fields_before_wrapping() {
        let snapshot = ProgressSnapshot {
            entries: 123_456,
            bytes_allocated: 4 * 1024 * 1024 * 1024 + 205 * 1024 * 1024,
            root_current: 7,
            root_total: 16,
        };

        assert_eq!(
            format_scan_progress(snapshot, 40),
            "scanning... 4.2 GiB (root 7/16)"
        );
    }

    #[test]
    fn progress_indicator_requires_terminal_color_and_capability() {
        assert!(indicator_enabled(true, true, false));
        assert!(!indicator_enabled(false, true, false));
        assert!(!indicator_enabled(true, false, false));
        assert!(!indicator_enabled(true, true, true));
    }

    #[test]
    fn disabled_indicator_has_no_worker() {
        let indicator = ScanIndicator::start(
            Arc::new(degu_walk::Progress::default()),
            &ScanRootProgress::new(),
            false,
        );

        assert!(matches!(indicator, ScanIndicator::Disabled));
    }

    #[test]
    fn worker_panic_is_reported() {
        let indicator = ScanIndicator::Running {
            stop: Arc::new(AtomicBool::new(false)),
            handle: thread::spawn(|| -> std::io::Result<bool> {
                panic!("progress test panic");
            }),
        };

        let error = indicator.stop_and_clear().unwrap_err();
        assert_eq!(error.to_string(), "scan progress thread panicked");
    }

    #[test]
    fn worker_io_error_preserves_renderer_context_and_source() {
        let indicator = ScanIndicator::Running {
            stop: Arc::new(AtomicBool::new(false)),
            handle: thread::spawn(|| Err(std::io::Error::other("renderer test failure"))),
        };

        let error = indicator.stop_and_clear().unwrap_err();
        assert_eq!(error.to_string(), "scan progress renderer failed");
        let source = error.chain().nth(1).unwrap();
        assert!(source.is::<std::io::Error>());
        assert_eq!(source.to_string(), "renderer test failure");
    }
}
