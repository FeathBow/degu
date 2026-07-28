/// Pins the two-line next-command form: the heading stands alone on its line
/// and the suggested command follows on the next line indented two spaces.
pub fn assert_next_command(stdout: &str, heading: &str, command: &str) {
    let lines: Vec<&str> = stdout.lines().collect();
    let heading_at = lines
        .iter()
        .position(|line| line.trim_end() == heading)
        .unwrap_or_else(|| panic!("missing heading {heading:?} in stdout: {stdout}"));
    let command_line = lines
        .get(heading_at + 1)
        .unwrap_or_else(|| panic!("heading {heading:?} ends stdout: {stdout}"));
    assert_eq!(
        command_line.trim_end(),
        format!("  {command}"),
        "stdout: {stdout}"
    );
}
