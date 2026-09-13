use ratatui::prelude::*;

use super::theme::{ACCENT, READY, REVIEW};

const DIGITS: [[&str; 3]; 11] = [
    ["█▀█", "█ █", "▀▀▀"],
    ["▄█ ", " █ ", "▀▀▀"],
    ["▀▀█", "█▀▀", "▀▀▀"],
    ["▀▀█", "▀▀█", "▀▀▀"],
    ["█ █", "▀▀█", "  ▀"],
    ["█▀▀", "▀▀█", "▀▀▀"],
    ["█▀▀", "█▀█", "▀▀▀"],
    ["▀▀█", " █ ", " ▀ "],
    ["█▀█", "█▀█", "▀▀▀"],
    ["█▀█", "▀▀█", "▀▀▀"],
    [" ", " ", "▀"],
];
const WORDMARK: [&str; 4] = [
    "    █                     ",
    "▄▀▀▀█  ▄▀▀▀▄  ▄▀▀▀█  █   █",
    "█   █  █▀▀▀▀  ▀▄▄▄█  █   █",
    " ▀▀▀▀   ▀▀▀    ▄▄▄▀   ▀▀▀▀",
];

pub fn number(value: &str) -> Vec<Line<'static>> {
    (0..DIGITS[0].len())
        .map(|row| {
            let glyphs = value.chars().map(|digit| {
                let index = if digit == '.' {
                    DIGITS.len() - 1
                } else {
                    digit.to_digit(10).expect("formatted size contains digits") as usize
                };
                DIGITS[index][row]
            });
            Line::from(glyphs.collect::<Vec<_>>().join(" ")).fg(REVIEW)
        })
        .collect()
}

pub fn wordmark() -> Vec<Line<'static>> {
    WORDMARK
        .iter()
        .enumerate()
        .map(|(row, text)| {
            Line::from(*text)
                .fg(if row < WORDMARK.len() / 2 {
                    READY
                } else {
                    ACCENT
                })
                .centered()
        })
        .collect()
}
