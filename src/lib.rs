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
#![doc(html_root_url="https://docs.rs/shell-escape/0.1.3")]

use std::borrow::Cow;
use std::env;

/// Escape characters that may have special meaning in a shell.
pub fn escape(s: Cow<str>) -> Cow<str> {
    if cfg!(unix) || env::var("MSYSTEM").is_ok() {
        unix::escape(s)
    } else {
        windows::escape(s)
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
        let mut needs_escape = false;
        for ch in s.chars() {
            match ch {
                '"' | '\t' | '\n' | ' ' => needs_escape = true,
                _ => {}
            }
        }
        if !needs_escape {
            return s
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

    #[test]
    fn test_escape() {
        assert_eq!(escape("--aaa=bbb-ccc".into()), "--aaa=bbb-ccc");
        assert_eq!(escape("linker=gcc -L/foo -Wl,bar".into()),
        r#""linker=gcc -L/foo -Wl,bar""#);
        assert_eq!(escape(r#"--features="default""#.into()),
        r#""--features=\"default\"""#);
        assert_eq!(escape(r#"\path\to\my documents\"#.into()),
        r#""\path\to\my documents\\""#);
    }
}

/// Unix-specific escaping.
pub mod unix {
    mod private {
        /// Putting the actual trait declaration and implementation into a
        /// private module stops crates other than shell-escape from
        /// implementing it.
        pub trait UnixEscape: ToOwned {
            fn as_bytes(&self) -> &[u8];
            fn owned_from_bytes(vec: Vec<u8>) -> <Self as ToOwned>::Owned;
        }

        impl UnixEscape for str {
            fn as_bytes(&self) -> &[u8] {
                self.as_bytes()
            }

            fn owned_from_bytes(vec: Vec<u8>) -> String {
                String::from_utf8(vec).unwrap()
            }
        }

        impl UnixEscape for [u8] {
            fn as_bytes(&self) -> &[u8] {
                self
            }

            fn owned_from_bytes(vec: Vec<u8>) -> Vec<u8> {
                vec
            }
        }
    }

    use std::borrow::Cow;
    use self::private::UnixEscape;

    fn non_whitelisted(ch: &u8) -> bool {
        #[allow(unused_imports)]
        use std::ascii::AsciiExt;

        match *ch {
            b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b'-' | b'_' | b'=' | b'/' | b',' | b'.' | b'+' => false,
            _ => ch.is_ascii()
        }
    }

    /// Escape characters that may have special meaning in a shell, including spaces.
    ///
    /// The private trait UnixEscape is implemented for both `str` and `[u8]` since
    /// Unix paths are not necessarily valid UTF-8.
    pub fn escape<'a, T: 'a + ?Sized + UnixEscape>(s: Cow<'a, T>) -> Cow<T> {
        if !s.as_bytes().iter().any(non_whitelisted) {
            return s;
        }

        let bytes = s.as_bytes();
        let mut es = Vec::with_capacity(bytes.len() + 2);
        es.push(b'\'');
        for b in bytes {
            match *b {
                b'\'' | b'!' => {
                    es.extend_from_slice(&b"'\\"[..]);
                    es.push(*b);
                    es.push(b'\'');
                }
                _ => es.push(*b),
            }
        }
        es.push(b'\'');
        Cow::Owned(T::owned_from_bytes(es))
    }

    #[test]
    fn test_escape() {
        assert_eq!(
            escape("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+".into()),
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+"
        );
        assert_eq!(escape("--aaa=bbb-ccc".into()), "--aaa=bbb-ccc");
        assert_eq!(escape("linker=gcc -L/foo -Wl,bar".into()), r#"'linker=gcc -L/foo -Wl,bar'"#);
        assert_eq!(escape(r#"--features="default""#.into()), r#"'--features="default"'"#);
        assert_eq!(escape(r#"'!\$`\\\n "#.into()), r#"''\'''\!'\$`\\\n '"#);
        assert_eq!(escape("Goodbye!".into()), "'Goodbye'\\!''");
    }

    #[test]
    fn test_escape_bytes() {
        assert_eq!(
            escape((&b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+"[..]).into()),
            &b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+"[..]
        );
        assert_eq!(escape((&b"--aaa=bbb-ccc"[..]).into()), &b"--aaa=bbb-ccc"[..]);
        assert_eq!(escape((&b"linker=gcc -L/foo -Wl,bar"[..]).into()), &br#"'linker=gcc -L/foo -Wl,bar'"#[..]);
        assert_eq!(escape((&br#"--features="default""#[..]).into()), &br#"'--features="default"'"#[..]);
        assert_eq!(escape((&br#"'!\$`\\\n "#[..]).into()), &br#"''\'''\!'\$`\\\n '"#[..]);
        assert_eq!(escape((&b"Tsch\xfc\xdf"[..]).into()), &b"Tsch\xfc\xdf"[..]);
        assert_eq!(escape((&b"Tsch\xfc\xdf!"[..]).into()), &b"'Tsch\xfc\xdf'\\!''"[..]);
    }
}

