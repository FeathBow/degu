use std::time::Duration;

const SECONDS_PER_MINUTE: u64 = 60;
const MINUTES_PER_HOUR: u64 = 60;

pub(crate) fn parse_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("duration must not be empty".to_string());
    }
    let (digits, multiplier) = split_duration(raw)?;
    parse_scaled(digits, multiplier, "duration").map(Duration::from_secs)
}

fn split_duration(raw: &str) -> Result<(&str, u64), String> {
    let Some(last) = raw.as_bytes().last().copied() else {
        unreachable!("empty input rejected by parse_duration");
    };
    if !last.is_ascii_alphabetic() {
        return Ok((raw, 1));
    }
    let multiplier = match (last as char).to_ascii_lowercase() {
        's' => 1,
        'm' => SECONDS_PER_MINUTE,
        'h' => SECONDS_PER_MINUTE * MINUTES_PER_HOUR,
        _ => {
            return Err(
                "duration suffix must be one of s, m, or h; decimals are not supported".to_string(),
            );
        }
    };
    Ok((&raw[..raw.len() - 1], multiplier))
}

fn parse_scaled(digits: &str, multiplier: u64, kind: &str) -> Result<u64, String> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        let units = if kind == "size" {
            "whole bytes or an integer with K, M, G, or T suffix"
        } else {
            "whole seconds or an integer with s, m, or h suffix"
        };
        return Err(format!("{kind} must be {units}"));
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or_else(|| format!("{kind} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_accepts_seconds_and_smh_suffixes() {
        let cases = [
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("42", Duration::from_secs(42)),
            ("1s", Duration::from_secs(1)),
            ("2S", Duration::from_secs(2)),
            ("3m", Duration::from_secs(3 * SECONDS_PER_MINUTE)),
            ("4M", Duration::from_secs(4 * SECONDS_PER_MINUTE)),
            (
                "5h",
                Duration::from_secs(5 * SECONDS_PER_MINUTE * MINUTES_PER_HOUR),
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse_duration(raw), Ok(expected));
        }
    }

    #[test]
    fn duration_rejects_invalid_and_fractional_values() {
        for raw in ["", "s", "1.5s", "1d", "12ms", "-1", "abc"] {
            assert!(parse_duration(raw).is_err(), "{raw:?} should be invalid");
        }
    }
}
