//!
//! A crate providing a proposed implementation of Windows file security extensions.
//!
//! Both fs::File and fs::DirEntry are extended with functions to get and set security information
//! on the file. If moved into std, these would be implemented on the windows fs implementation.
//! For an out-of-band crate, they are instead implemented on the exported structs.
//!

#![allow(nonstandard_style)]
#![warn(missing_docs)]

extern crate winapi;

#[cfg(windows)]
mod ext;

#[cfg(windows)]
pub use ext::{
    FileExt,
    DirEntryExt,
    Security
};
