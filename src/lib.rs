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
mod unix;

#[cfg(unix)]
pub use unix::{
    escape,
    escape_os_str
};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    escape, 
    escape_os_str
};
