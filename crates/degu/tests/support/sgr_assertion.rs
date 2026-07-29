pub fn assert_sgr_color(output: &str, label: &str, color_code: &str) {
    let position = output
        .find(label)
        .unwrap_or_else(|| panic!("missing {label:?}: {output}"));
    let prefix = output[..position].rsplit("\x1b[0m").next().unwrap();
    assert!(
        prefix.contains(color_code),
        "{label:?} lacks {color_code:?}: {output:?}"
    );
}
