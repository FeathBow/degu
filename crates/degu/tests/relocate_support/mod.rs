pub(crate) use crate::common::isolated_degu as degu;

pub(crate) fn generated_script(
    home: &std::path::Path,
    target: &std::path::Path,
) -> std::path::PathBuf {
    let output = degu()
        .env("HOME", home)
        .arg("relocate")
        .arg(target)
        .output()
        .unwrap();
    assert!(output.status.success());
    let script = home.join("relocate.sh");
    std::fs::write(&script, output.stdout).unwrap();
    script
}
