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
pub mod key;
pub mod overwrite;
pub mod pack;
pub mod storage;
pub mod unpack;

pub mod utils;
