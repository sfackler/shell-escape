//!
//!  Windows-specific escaping.
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::iter::repeat;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

/// Escape for the windows cmd.exe shell.
///
/// See [here][msdn] for more information.
///
/// [msdn]: http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx
pub fn escape(s: Cow<str>) -> Cow<str> {
    let needs_escape = s.chars().any(|c| matches!(c, '"' | '\t' | '\n' | ' '));
    if s.is_empty() || !needs_escape {
        return s;
    }

    let mut es = String::with_capacity(s.len() + 2);
    es.push('"');
    
    let mut chars = s.chars().peekable();
    loop {
        let mut nslashes = 0;
        while chars.next_if_eq(&'\\').is_some() {
            nslashes += 1;
        }

        match chars.next() {
            Some('"') => {
                es.reserve(nslashes * 2 + 2);
                es.extend(repeat('\\').take(nslashes * 2 + 1));
                es.push('"');
            }
            Some(c) => {
                es.reserve(nslashes + 1);
                es.extend(repeat('\\').take(nslashes));
                es.push(c);
            }
            None => {
                es.reserve(nslashes * 2);
                es.extend(repeat('\\').take(nslashes * 2));
                break;
            }
        }
    }
    es.push('"');
    es.into()
}

/// Determine if a wide byte needs to be escaped.
/// Only tabs, newlines, spaces, and double quotes need to be escaped.
/// Example:
/// ```
/// use shell_escape::windows::needs_escape;
///
/// assert!(needs_escape(b'"' as u16));
/// assert!(needs_escape(b'\t' as u16));
/// assert!(needs_escape(b'\n' as u16));
/// assert!(needs_escape(b' ' as u16));
/// assert!(!needs_escape(b'\\' as u16));
/// ```
pub fn needs_escape(wide_byte: u16) -> bool {
    match char::from_u32(wide_byte as u32) {
        Some(c) => matches!(c, '"' | '\t' | '\n' | ' '), // only tabs, newlines, spaces, and double quotes need to be escaped
        None => true
    }
}

/// Escape OsStr for the windows cmd.exe shell.
///
/// See [here][msdn] for more information.
///
/// Example:
/// ```
/// use shell_escape::windows::escape_os_str;
/// use std::ffi::OsStr;
///
/// let s = OsStr::new("foo bar");
/// let escaped = escape_os_str(s);
/// assert_eq!(escaped, OsStr::new(r#""foo bar""#));
/// ```
/// [msdn]: http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx
pub fn escape_os_str(s: &OsStr) -> Cow<'_, OsStr> {
    let encoded = s.encode_wide();
    let needs_escaping = encoded.clone().any(needs_escape);

    if s.is_empty() || !needs_escaping {
        return Cow::Borrowed(s);
    }

    let mut escaped = Vec::with_capacity(s.len() + 2);
    escaped.push(b'"' as u16);

    let mut chars = encoded.into_iter().peekable();
    loop {
        let mut nslashes = 0;
        while chars.next_if_eq(&(b'\\' as u16)).is_some() {
            nslashes += 1;
        }
        match chars.next() {
            Some(c) if c == b'"' as u16 => {
                escaped.reserve(nslashes * 2 + 2);
                escaped.extend(repeat(b'\\' as u16).take(nslashes * 2 + 1));
                escaped.push(b'"' as u16);
            }
            Some(c) => {
                escaped.reserve(nslashes + 1);
                escaped.extend(repeat(b'\\' as u16).take(nslashes));
                escaped.push(c);
            }
            None => {
                escaped.reserve(nslashes * 2);
                escaped.extend(repeat(b'\\' as u16).take(nslashes * 2));
                break;
            }
        }
    }

    escaped.push(b'"' as u16);
    OsString::from_wide(&escaped).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate test_case;

    #[test_case::test_case(
        r#""""#,
        r#""\"\"""#
        ; "an empty string is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#""--features=\"default\"""#,
        r#""\"--features=\\\"default\\\"\"""#
        ; "a flag with quotes is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#"linker=gcc -L/foo -Wl,bar"#,
        r#""linker=gcc -L/foo -Wl,bar""#
        ; "a flag with spaces is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#"\path\to\my documents\"#,
        r#""\path\to\my documents\\""#
        ; "a path with spaces is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        "--aaa=bbb-ccc",
        "--aaa=bbb-ccc"
        ; "a flag built up entirely of allowed characters is not escaped."
    )]
    fn test_escape(input: &str, expected: &str) {
        assert_eq!(escape(input.into()), expected);
    }

    #[test_case::test_case(
        r#""""#,
        r#""\"\"""#
        ; "an empty string is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#""--features=\"default\"""#,
        r#""\"--features=\\\"default\\\"\"""#
        ; "a flag with quotes is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#"linker=gcc -L/foo -Wl,bar"#,
        r#""linker=gcc -L/foo -Wl,bar""#
        ; "a flag with spaces is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        r#"\path\to\my documents\"#,
        r#""\path\to\my documents\\""#
        ; "a path with spaces is escaped by surrounding with double quotes."
    )]
    #[test_case::test_case(
        "--aaa=bbb-ccc",
        "--aaa=bbb-ccc"
        ; "a flag built up entirely of allowed characters is not escaped."
    )]
    fn test_escape_os_str(input: &str, expected: &str) {
        let binding = OsString::from(input);
        let input_os_str = binding.as_os_str();
        let binding = OsString::from(expected);
        let expected_os_str = binding.as_os_str();
        let observed_os_str = escape_os_str(input_os_str);
        assert_eq!(observed_os_str, expected_os_str);
    }

    #[test_case::test_case(
        &[0x1055, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065],
        &[0x1055, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065]
        ; "u16 (as u32) that are valid chars are not escaped unless they are a double quote, space, backslash, newline, or a tab."
    )]
    #[test_case::test_case(
        &[0xD801, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065],
        &[b'"' as u16, 0xD801, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065, b'"' as u16]
        ; "a 16-bit number that is not a valid char when seen as a u32 is escaped by surrounding with double quotes."
    )]
    fn test_escape_os_str_from_bytes(input: &[u16], expected: &[u16]) {
        let binding = OsString::from_wide(input);
        let input_os_str = binding.as_os_str();
        let binding = OsString::from_wide(expected);
        let expected_os_str = binding.as_os_str();
        let observed_os_str = escape_os_str(input_os_str);
        assert_eq!(observed_os_str, expected_os_str);
    }
}