pub fn oplog_records(state: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let log = std::fs::read_to_string(state.path().join("degu/ops.jsonl")).unwrap();
    log.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
