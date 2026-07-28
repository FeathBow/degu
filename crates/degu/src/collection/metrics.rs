use std::time::Duration;

#[cfg(target_os = "linux")]
const KIBIBYTE: u64 = 1024;

pub(crate) fn elapsed_ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn max_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe {
        // SAFETY: the pointer is valid for writes and getrusage initializes it on success.
        libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr())
    };
    if result != 0 {
        return None;
    }
    let max_rss = unsafe {
        // SAFETY: a zero result guarantees that getrusage initialized the structure.
        usage.assume_init()
    }
    .ru_maxrss;
    u64::try_from(max_rss).ok().map(normalize_max_rss)
}

#[cfg(target_os = "linux")]
fn normalize_max_rss(max_rss: u64) -> u64 {
    max_rss.saturating_mul(KIBIBYTE)
}

#[cfg(target_os = "macos")]
fn normalize_max_rss(max_rss: u64) -> u64 {
    max_rss
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn max_rss_bytes() -> Option<u64> {
    None
}
