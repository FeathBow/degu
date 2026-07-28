pub(crate) fn valid_adapter_ids() -> Vec<String> {
    let mut ids = degu_adapters::all()
        .into_iter()
        .map(|registration| registration.id().to_string())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}
