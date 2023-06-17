//! ## What is it?
//!
//! Dexios-Domain is a library used for managing the core logic behind Dexios, and any applications that require easy integration with the Dexios format.
//!
//! ## Security
//!
//! Dexios-Domain is built on top of Dexios-Core - which uses modern, secure and audited<sup>1</sup> AEADs for encryption and decryption.
//!
//! You may find the audits for both AES-256-GCM and XChaCha20-Poly1305 on [the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).
//!
//! <sup>1</sup> Deoxys-II-256 does not have an official audit, so use it at your own risk
//!
//! ## Who uses Dexios-Domain?
//!
//! This library is implemented by [Dexios](https://github.com/brxken128/dexios), a secure command-line file
//! encryption utility.
//!
//! This crate was made to separate the logic away from the end-user application.
//!
//! It also allows for more things to be built on top of the core functionality, such as a GUI application.
//!
//! ## Donating
//!
//! If you like my work, and want to help support Dexios, Dexios-Core or Dexios-Domain, feel free to donate! This is not necessary by any means, so please don't feel obliged to do so.
//!
//! ```text
//! XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
//! BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
//! ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
//! ```
//!
//! You can read more about Dexios, Dexios-Core, Dexios-Domain and the technical details [in the project's main documentation](https://brxken128.github.io/dexios/)!
//!

// lints
#![forbid(unsafe_code)]
#![warn(
    rust_2018_idioms,
    non_ascii_idents,
    unstable_features,
    unused_imports,
    unused_qualifications,
    clippy::pedantic,
    clippy::all
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
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
