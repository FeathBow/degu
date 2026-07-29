use super::fenced_blocks;

const CONFIGURATION: &str = include_str!("../../../../docs/configuration.md");

#[test]
fn configuration_example_parses() {
    let example = fenced_blocks(CONFIGURATION, "toml")
        .into_iter()
        .find(|block| block.contains("roots ="))
        .expect("missing complete configuration example");
    degu_core::config::Config::from_toml(example).unwrap();
}
