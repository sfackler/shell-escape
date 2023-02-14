// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//! Escape characters that may have special meaning in a shell.
#![doc(html_root_url = "https://docs.rs/shell-escape/0.1")]


#[cfg(unix)]
pub use unix::escape_os_str as escape_os_str;
#[cfg(unix)]
pub use unix::escape as escape;

#[cfg(windows)]
pub use windows::escape as escape;
#[cfg(windows)]
pub use windows::escape_os_str as escape_os_str;


#[cfg(windows)]
/// Windows-specific escaping.
pub mod windows {
    use std::borrow::Cow;
    use std::ffi::{
        OsStr, 
        OsString
    };
    use std::iter::repeat;

    use std::os::windows::ffi::{
        OsStrExt, 
        OsStringExt
    };

    /// Escape for the windows cmd.exe shell.
    ///
    /// See [here][msdn] for more information.
    ///
    /// [msdn]: http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx
    pub fn escape(s: Cow<str>) -> Cow<str> {
        let mut needs_escape = s.is_empty();
        for ch in s.chars() {
            match ch {
                '"' | '\t' | '\n' | ' ' => needs_escape = true,
                _ => {}
            }
        }
        if !needs_escape {
            return s;
        }
        let mut es = String::with_capacity(s.len());
        es.push('"');
        let mut chars = s.chars().peekable();
        loop {
            let mut nslashes = 0;
            while let Some(&'\\') = chars.peek() {
                chars.next();
                nslashes += 1;
            }

            match chars.next() {
                Some('"') => {
                    es.extend(repeat('\\').take(nslashes * 2 + 1));
                    es.push('"');
                }
                Some(c) => {
                    es.extend(repeat('\\').take(nslashes));
                    es.push(c);
                }
                None => {
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

        let (high, low) = ((wide_byte >> 8) as u8, (wide_byte & 0xFF) as u8);

        if high > 0 {
            // High byte is set, so its not an ASCII character and definitely needs escaping.
            return true;
        }
        matches!(
            low, 
            b'"' | b'\t' | b'\n' | b' '
        )
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
        let encoded: Vec<u16> = s.encode_wide().collect();
        let needs_escaping = encoded.iter().copied().any(needs_escape);

        if s.is_empty() || !needs_escaping {
            return Cow::Borrowed(s);
        }

        let mut escaped = Vec::with_capacity(encoded.len() + 2);
        escaped.push(b'"' as u16);

        let mut chars = encoded.into_iter().peekable();
        loop {
            let mut nslashes = 0;
            while let Some(&c) = chars.peek() {
                if c == (b'\\' as u16) {
                    chars.next();
                    nslashes += 1;
                } else {
                    break;
                }
            }
            match chars.next() {
                Some(c) if c == b'"' as u16 => {
                    escaped.reserve(nslashes * 2 + 1);
                    escaped.extend(repeat(b'\\' as u16).take(nslashes * 2 + 1));
                    escaped.push(b'"' as u16);
                },
                Some(c) => {
                    escaped.reserve(nslashes);
                    escaped.extend(repeat(b'\\' as u16).take(nslashes));
                    escaped.push(c);
                },
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

        /// FIXME: Need to fix this test case. 
        /// I'm not sure what we're expecting to happen here.
        #[test_case::test_case(
            &[0x1055, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065],
            &[0x1055, 0x006E, 0x0069, 0x0063, 0x006F, 0x0064, 0x0065]
            ; "A u16 with high byte set requires escaping."
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
}

/// Unix-specific escaping.
#[cfg(unix)]
pub mod unix {
    use std::{
        borrow::Cow,
        ffi::{OsStr, OsString},
        os::unix::ffi::{
            OsStrExt,
            OsStringExt
        }
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
}
