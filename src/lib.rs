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

use std::borrow::Cow;
use std::env;
use std::ffi::OsStr;

/// Escape characters that may have special meaning in a shell.
pub fn escape(s: Cow<str>) -> Cow<str> {
    if cfg!(unix) || env::var("MSYSTEM").is_ok() {
        unix::escape(s)
    } else {
        windows::escape(s)
    }
}

/// Escape characters that may have special meaning in a shell
/// for an `OsStr`.
pub fn escape_os_str(s: &OsStr) -> Cow<'_, OsStr> {
    if cfg!(unix) || env::var("MSYSTEM").is_ok() {
        unix::escape_os_str(s)
    } else {
        unimplemented!("windows::escape_os_str")
    }
}

/// Windows-specific escaping.
pub mod windows {
    use std::borrow::Cow;
    use std::iter::repeat;

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
    }
}

/// Unix-specific escaping.
pub mod unix {
    use std::{
        borrow::Cow,
        ffi::{OsStr, OsString},
        os::unix::ffi::OsStrExt,
        os::unix::ffi::OsStringExt,
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
