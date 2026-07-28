const BYTE_BASE: f64 = 1024.0;
const HALF_TENTH: f64 = 0.05;

fn parse_parts(text: &str) -> (f64, &str) {
    let text = text.strip_prefix(">= ").unwrap_or(text);
    let (value, unit) = text.split_once(' ').unwrap();
    (value.parse().unwrap(), unit)
}

fn unit_scale(unit: &str) -> f64 {
    match unit {
        "B" => 1.0,
        "KiB" => BYTE_BASE,
        "MiB" => BYTE_BASE.powi(2),
        "GiB" => BYTE_BASE.powi(3),
        "TiB" => BYTE_BASE.powi(4),
        "PiB" => BYTE_BASE.powi(5),
        other => panic!("unknown byte unit {other:?}"),
    }
}

pub fn parse_human_bytes(text: &str) -> f64 {
    let (value, unit) = parse_parts(text);
    value * unit_scale(unit)
}

pub fn assert_human_bytes(actual: &str, expected: u64) {
    assert!(
        !actual.starts_with(">= "),
        "unexpected lower bound: {actual}"
    );
    let (_, unit) = actual.split_once(' ').unwrap();
    let scale = unit_scale(unit);
    let expected = expected as f64;
    let represented = parse_human_bytes(actual);
    if unit == "B" {
        assert!(expected < BYTE_BASE, "non-canonical byte unit: {actual}");
        assert_eq!(represented, expected, "byte count differs: {actual}");
        return;
    }
    assert!(expected >= scale, "unit is too large: {actual}");
    if unit != "PiB" {
        assert!(expected < scale * BYTE_BASE, "unit is too small: {actual}");
    }
    let tolerance = scale * HALF_TENTH;
    assert!(
        (represented - expected).abs() <= tolerance,
        "displayed byte count {actual} differs from {expected} by more than {tolerance} bytes"
    );
}
