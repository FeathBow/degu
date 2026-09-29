//! Replay a PTY byte stream into the screen a reader would be looking at.
//!
//! A terminal stream is not a transcript: ratatui redraws only what changed, so a
//! sentence the reader sees whole arrives split across cursor-positioning escapes
//! and interleaved with the parts that did not change. Searching the raw bytes
//! answers a question about the stream; these tests ask what is on the screen.

/// The visible lines, top to bottom, with trailing blanks trimmed off each.
pub fn render(stream: &[u8], rows: usize, columns: usize) -> Vec<String> {
    let mut grid = vec![vec![' '; columns]; rows];
    let (mut row, mut column) = (0usize, 0usize);
    let mut index = 0;
    while index < stream.len() {
        let byte = stream[index];
        match byte {
            b'\n' => {
                row = (row + 1).min(rows.saturating_sub(1));
                index += 1;
            }
            b'\r' => {
                column = 0;
                index += 1;
            }
            0x1b => {
                let consumed = escape(stream, index, &mut grid, &mut row, &mut column, columns);
                index += consumed;
            }
            _ => {
                let (character, width) = character(stream, index);
                if row < rows && column < columns {
                    grid[row][column] = character;
                }
                column += 1;
                index += width;
            }
        }
    }
    grid.into_iter()
        .map(|line| line.into_iter().collect::<String>().trim_end().to_owned())
        .collect()
}

/// The whole screen as one string, which is what an assertion about a wrapped
/// sentence has to search: the renderer breaks it across rows.
pub fn flattened(stream: &[u8], rows: usize, columns: usize) -> String {
    render(stream, rows, columns).join(" ")
}

fn character(stream: &[u8], index: usize) -> (char, usize) {
    let rest = &stream[index..];
    match std::str::from_utf8(&rest[..rest.len().min(4)]) {
        Ok(text) => text.chars().next().map_or((' ', 1), |c| (c, c.len_utf8())),
        Err(error) if error.valid_up_to() > 0 => {
            let text = std::str::from_utf8(&rest[..error.valid_up_to()]).unwrap();
            text.chars().next().map_or((' ', 1), |c| (c, c.len_utf8()))
        }
        Err(_) => (' ', 1),
    }
}

/// Consumes one escape sequence and applies the ones that move the cursor or
/// erase, which are the only ones that change where text lands.
fn escape(
    stream: &[u8],
    start: usize,
    grid: &mut [Vec<char>],
    row: &mut usize,
    column: &mut usize,
    columns: usize,
) -> usize {
    if stream.get(start + 1) != Some(&b'[') {
        // Not CSI: a two-byte sequence, or an OSC string ending at BEL or ST.
        return 2;
    }
    let mut end = start + 2;
    while end < stream.len() && !stream[end].is_ascii_alphabetic() {
        end += 1;
    }
    if end >= stream.len() {
        return stream.len() - start;
    }
    let body = std::str::from_utf8(&stream[start + 2..end]).unwrap_or("");
    let final_byte = stream[end];
    let numbers = body
        .trim_start_matches('?')
        .split(';')
        .map(|part| part.parse::<usize>().ok())
        .collect::<Vec<_>>();
    let first = numbers.first().copied().flatten();
    match final_byte {
        b'H' | b'f' => {
            *row = first.unwrap_or(1).saturating_sub(1);
            *column = numbers
                .get(1)
                .copied()
                .flatten()
                .unwrap_or(1)
                .saturating_sub(1);
        }
        b'A' => *row = row.saturating_sub(first.unwrap_or(1)),
        b'B' => *row = (*row + first.unwrap_or(1)).min(grid.len().saturating_sub(1)),
        b'C' => *column += first.unwrap_or(1),
        b'D' => *column = column.saturating_sub(first.unwrap_or(1)),
        b'J' => erase_display(grid, *row, *column, first.unwrap_or(0), columns),
        b'K' => erase_line(grid, *row, *column, first.unwrap_or(0), columns),
        // Entering the alternate screen starts a blank one. Leaving it restores the
        // primary screen, but what the reader last saw is the alternate one, so the
        // grid is kept rather than wiped on the way out.
        b'h' if body.starts_with('?') && first == Some(1049) => {
            for line in grid.iter_mut() {
                line.fill(' ');
            }
            *row = 0;
            *column = 0;
        }
        _ => {}
    }
    end + 1 - start
}

fn erase_line(grid: &mut [Vec<char>], row: usize, column: usize, mode: usize, columns: usize) {
    let Some(line) = grid.get_mut(row) else {
        return;
    };
    let range = match mode {
        1 => 0..=column.min(columns.saturating_sub(1)),
        2 => 0..=columns.saturating_sub(1),
        _ => column.min(columns)..=columns.saturating_sub(1),
    };
    for index in range {
        if let Some(cell) = line.get_mut(index) {
            *cell = ' ';
        }
    }
}

fn erase_display(grid: &mut [Vec<char>], row: usize, column: usize, mode: usize, columns: usize) {
    match mode {
        1 => {
            for line in grid.iter_mut().take(row) {
                line.fill(' ');
            }
            erase_line(grid, row, column, 1, columns);
        }
        2 => {
            for line in grid.iter_mut() {
                line.fill(' ');
            }
        }
        _ => {
            erase_line(grid, row, column, 0, columns);
            for line in grid.iter_mut().skip(row + 1) {
                line.fill(' ');
            }
        }
    }
}
