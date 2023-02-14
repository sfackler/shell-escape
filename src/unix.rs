//! Unix-specific escaping.
//!
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

fn non_whitelisted(ch: char) -> bool {
    !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '=' | '/' | ',' | '.' | '+')
}

/// Escape characters that may have special meaning in a shell, including spaces.
pub fn escape(s: Cow<str>) -> Cow<str> {
    if !s.is_empty() && !s.contains(non_whitelisted) {
        return s;
    }

    let mut es = String::with_capacity(s.len() + 2);
    es.push('\'');
    for ch in s.chars() {
        match ch {
            '\'' | '!' => {
                es.push_str("'\\");
                es.push(ch);
                es.push('\'');
            }
            _ => es.push(ch),
        }
    }
    es.push('\'');
    es.into()
}

fn allowed(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'=' | b'/' | b',' | b'.' | b'+')
}

/// Escape characters that may have special meaning in a shell, including spaces.
/// Work with `OsStr` instead of `str`.
pub fn escape_os_str(s: &OsStr) -> Cow<'_, OsStr> {
    let as_bytes = s.as_bytes();
    let all_whitelisted = as_bytes.iter().copied().all(allowed);

    if !as_bytes.is_empty() && all_whitelisted {
        return Cow::Borrowed(s);
    }

    let mut escaped = Vec::with_capacity(as_bytes.len() + 2);
    escaped.push(b'\'');

    for &b in as_bytes {
        match b {
            b'\'' | b'!' => {
                escaped.reserve(4);
                escaped.push(b'\'');
                escaped.push(b'\\');
                escaped.push(b);
                escaped.push(b'\'');
            }
            _ => escaped.push(b),
        }
    }
    escaped.push(b'\'');
    OsString::from_vec(escaped).into()
}

#[cfg(test)]
mod tests {
    extern crate test_case;

    use super::{escape, escape_os_str};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test_case::test_case(
        " ",
        r#"' '"#
        ; "Space is escaped by wrapping it in single quotes."
    )]
    #[test_case::test_case(
        "",
        r#"''"#
        ; "Empty string is escaped by wrapping it in single quotes."
    )]
    #[test_case::test_case(
        r#"'!\$`\\\n "#, 
        r#"''\'''\!'\$`\\\n '"#
        ; "Text with a mix of characters that require escaping are individually escaped as well as wrapping the whole thing in single quotes."
    )]
    #[test_case::test_case(
        r#"--features="default""#,
        r#"'--features="default"'"#
        ; "Text with a double quote is escaped by wrapping it all in single quotes."
    )]
    #[test_case::test_case(
        "linker=gcc -L/foo -Wl,bar",
        r#"'linker=gcc -L/foo -Wl,bar'"#
        ; "Text with a slash is escaped by wrapping it all in single quotes."
    )]
    #[test_case::test_case(
        "--aaa=bbb-ccc",
        "--aaa=bbb-ccc"
        ; "a flag built up entirely of allowed characters is not escaped."
    )]
    #[test_case::test_case(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+"
        ; "all allowed characters that do not require escaping are not escaped"
    )]
    fn test_escape(input: &str, expected: &str) {
        assert_eq!(escape(input.into()), expected);
    }

    #[test_case::test_case(
        " ",
        r#"' '"#
        ; "Space is escaped by wrapping it in single quotes."
    )]
    #[test_case::test_case(
        "",
        r#"''"#
        ; "Empty string is escaped by wrapping it in single quotes."
    )]
    #[test_case::test_case(
        r#"'!\$`\\\n "#, 
        r#"''\'''\!'\$`\\\n '"#
        ; "Text with a mix of characters that require escaping are individually escaped as well as wrapping the whole thing in single quotes."
    )]
    #[test_case::test_case(
        r#"--features="default""#,
        r#"'--features="default"'"#
        ; "Text with a double quote is escaped by wrapping it all in single quotes."
    )]
    #[test_case::test_case(
        "linker=gcc -L/foo -Wl,bar",
        r#"'linker=gcc -L/foo -Wl,bar'"#
        ; "Text with a slash is escaped by wrapping it all in single quotes."
    )]
    #[test_case::test_case(
        "--aaa=bbb-ccc",
        "--aaa=bbb-ccc"
        ; "a flag built up entirely of allowed characters is not escaped."
    )]
    #[test_case::test_case(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+"
        ; "all allowed characters that do not require escaping are not escaped"
    )]
    fn test_escape_os_str(input: &str, expected: &str) {
        let input_os_str = OsStr::from_bytes(input.as_bytes());
        let observed_os_str = escape_os_str(input_os_str);
        let expected_os_str = OsStr::from_bytes(expected.as_bytes());
        assert_eq!(observed_os_str, expected_os_str);
    }

    #[test_case::test_case(
        &[0x66, 0x6f, 0x80, 0x6f],
        &[b'\'', 0x66, 0x6f, 0x80, 0x6f, b'\'']
        ; "Bytes that are not valid UTF-8 are escaped by wrapping them in single quotes."
    )]
    fn test_escape_os_str_from_bytes(input: &[u8], expected: &[u8]) {
        let input_os_str = OsStr::from_bytes(input);
        let observed_os_str = escape_os_str(input_os_str);
        let expected_os_str = OsStr::from_bytes(expected);
        assert_eq!(observed_os_str, expected_os_str);
    }
}
