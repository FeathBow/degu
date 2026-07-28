use std::os::unix::fs::MetadataExt;
use std::time::Duration;

pub(super) const SECONDS_PER_DAY: u64 = 86_400;

fn timestamp_age(ts: jiff::Timestamp, now: jiff::Timestamp) -> Option<Duration> {
    let age = now.duration_since(ts);
    (!age.is_negative()).then(|| age.unsigned_abs())
}

pub(crate) fn fallback_age(meta: &std::fs::Metadata, now: jiff::Timestamp) -> Duration {
    let ts = jiff::Timestamp::from_second(meta.ctime().max(0)).unwrap_or(jiff::Timestamp::MIN);
    timestamp_age(ts, now).unwrap_or(Duration::ZERO)
}
