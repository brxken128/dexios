// Rustc lints
#![deny(
    rust_2018_idioms,
    non_ascii_idents,
    unsafe_code,
    unstable_features,
    unused_imports,
    unused_qualifications
)]
// Clippy lints
#![deny(clippy::pedantic, clippy::all)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    // yet
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
)]

pub mod decrypt;
pub mod encrypt;
pub mod erase;
pub mod erase_dir;
pub mod hash;
pub mod hasher;
pub mod header;
pub mod key;
pub mod overwrite;
pub mod pack;
pub mod storage;
pub mod unpack;

pub mod utils;
