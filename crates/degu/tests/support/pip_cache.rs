use std::path::{Path, PathBuf};

pub fn seed(home: impl AsRef<Path>) -> PathBuf {
    // Seed the pip cache where the scanner probes on the current platform.
    #[cfg(target_os = "macos")]
    let cache = home.as_ref().join("Library/Caches/pip");
    #[cfg(not(target_os = "macos"))]
    let cache = home.as_ref().join(".cache/pip");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("wheel.whl"), [0_u8; 2048]).unwrap();
    crate::common::make_tree_non_shared_writable(home.as_ref()).unwrap();
    cache
}
