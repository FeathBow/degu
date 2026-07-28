use std::path::Path;

use super::is_safe_terminal_character;

pub(crate) fn quote_path(path: &Path) -> Option<String> {
    quote_word(path.to_str()?)
}

/// Renders a path for a suggested command line. Paths under `home` become an
/// unquoted `~/rest` only when `rest` needs no quoting — a quoted `~` never
/// expands — and everything else falls back to the quoted absolute path.
pub(crate) fn command_path(path: &Path, home: &Path) -> Option<String> {
    if home != Path::new("/")
        && let Ok(rest) = path.strip_prefix(home)
        && let Some(rest) = rest.to_str()
        && !rest.is_empty()
        && is_unquoted_safe(rest)
    {
        return Some(format!("~/{rest}"));
    }
    quote_path(path)
}

pub(crate) fn quote_word(word: &str) -> Option<String> {
    if !is_terminal_safe(word) {
        return None;
    }
    if is_unquoted_safe(word) {
        return Some(word.to_string());
    }
    Some(format!("'{}'", word.replace('\'', "'\\''")))
}

fn is_terminal_safe(word: &str) -> bool {
    word.chars().all(is_safe_terminal_character)
}

fn is_unquoted_safe(word: &str) -> bool {
    word.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_./:@%+=,-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_when_the_shell_requires_it() {
        assert_eq!(quote_word("cache/pip").as_deref(), Some("cache/pip"));
        assert_eq!(quote_word("cache path").as_deref(), Some("'cache path'"));
        assert_eq!(quote_word("it's").as_deref(), Some("'it'\\''s'"));
    }

    #[test]
    fn command_paths_under_home_abbreviate_to_an_unquoted_tilde() {
        let home = Path::new("/home/user");
        assert_eq!(
            command_path(Path::new("/home/user/.cache/pip"), home).as_deref(),
            Some("~/.cache/pip")
        );
        // A quoted '~' does not expand, so unsafe rests use the absolute path.
        assert_eq!(
            command_path(Path::new("/home/user/cache path"), home).as_deref(),
            Some("'/home/user/cache path'")
        );
        assert_eq!(
            command_path(Path::new("/scratch/cache"), home).as_deref(),
            Some("/scratch/cache")
        );
        assert_eq!(
            command_path(Path::new("/home/user"), home).as_deref(),
            Some("/home/user")
        );
        assert_eq!(
            command_path(Path::new("/var/cache"), Path::new("/")).as_deref(),
            Some("/var/cache")
        );
        assert_eq!(command_path(Path::new("/home/user/bad\npath"), home), None);
    }

    #[test]
    fn rejects_nonvisible_characters_and_non_utf8_paths() {
        for word in [
            "cache\npath",
            "cache\u{202e}path",
            "cache\u{200b}path",
            "cache\u{2060}path",
            "cache\u{feff}path",
            "cache\u{2028}path",
            "cache\u{2029}path",
            "cachee\u{301}path",
        ] {
            assert_eq!(quote_word(word), None, "accepted {word:?}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = Path::new(std::ffi::OsStr::from_bytes(b"cache-\xff"));
            assert_eq!(quote_path(path), None);
        }
    }
}
